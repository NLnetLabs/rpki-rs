//! Signed Message CMS wrappers used in the RPKI publication (RFC 8181) and
//! provisioning (RFC 6492) protocols.

use bcder::decode;
use bcder::{Mode, Oid, OctetString, Tag, xerr};
use bytes::Bytes;
use crate::repository::crl::RevokedCertificates;
use crate::repository::crypto::{
    DigestAlgorithm, KeyIdentifier, Signature, SignatureAlgorithm, Signer, SigningError
};
use crate::repository::oid;
use crate::repository::sigobj::{
    MessageDigest, SignedAttrs
};
use crate::repository::x509::{
    Name, Serial, SignedData, Time, ValidationError,
    update_once
};
use super::idcert::IdCert;

/// A signed message, as used in RPKI remote protocols.
/// 
/// This is a *lot* like [`SignedObject`], i.e. Signed Object Template
/// for the RPKI (RFC 6488), but with subtle differences which make using
/// a common code base for both types somewhat painful. Hence, this separate
/// but similar structure.
/// 
/// Most important differences to watch out for:
/// = This uses [`IdCert`] rather then (resource) [`Cert`] as the EE
/// = This includes a CRL
/// 
/// The latter seems rather pointless in case one uses single use EE
/// certificates, but it's required by the protocol.. So, when sending
/// we just include an empty CRL to go with our short-lived single-use
/// EE certificates that will never be revoked.
#[derive(Clone, Debug)]
pub struct  SignedMessage {
    //--- From SignedData
    //
    digest_algorithm: DigestAlgorithm,
    content_type: Oid<Bytes>,
    content: OctetString,
    
    // Theoretically there could be multiple certificates, i.e. a chain
    // of certificates needed for validation to the known trusted TA
    // certificate for the other party, but in practice no one does this.
    //
    // So in our case we insist on a single embedded EE certificate which
    // is expected to be signed directly under the known TA certificate.
    ee_cert: IdCert,

    // Similarly there could be one CRL for each embedded certificate, but
    // since we just support a single EE certificate here we also expect a
    // single Crl.
    crl: SignedMessageCrl,

    //--- From SignerInfo
    //
    sid: KeyIdentifier,
    signed_attrs: SignedAttrs,
    signature: Signature,

    //--- SignedAttributes
    //
    message_digest: MessageDigest,
    _signing_time: Option<Time>,
    _binary_signing_time: Option<u64>,
}

/// # Data Access
/// 
impl SignedMessage {
    /// Returns a reference to the object’s content type.
    pub fn content_type(&self) -> &Oid<Bytes> {
        &self.content_type
    }

    /// Returns a reference to the object’s content.
    pub fn content(&self) -> &OctetString {
        &self.content
    }
}


/// # Decoding
///
impl SignedMessage {
    /// Decodes a signed message from the given source.
    pub fn decode<S: decode::Source>(
        source: S,
        strict: bool
    ) -> Result<Self, S::Err> {
        if strict { Mode::Der }
        else { Mode::Ber }
            .decode(source, Self::take_from)
    }

    /// Takes a signed message from an encoded constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            oid::SIGNED_DATA.skip_if(cons)?; // contentType
            cons.take_constructed_if(Tag::CTX_0, Self::take_signed_data)
        })
    }

    fn take_signed_data<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.skip_u8_if(3)?; // version -- must be 3

            let digest_algorithm = DigestAlgorithm::take_set_from(cons)?;

            let (content_type, content) = {
                cons.take_sequence(|cons| {
                    // encapContentInfo
                    Ok((
                        Oid::take_from(cons)?,
                        cons.take_constructed_if(
                            Tag::CTX_0,
                            OctetString::take_from
                        )?,
                    ))
                })?
            };
            if content_type != oid::PROTOCOL_CONTENT_TYPE {
                return xerr!(Err(decode::Malformed.into()));
            }

            let id_cert = Self::take_id_cert(cons)?;
            let crl = Self::take_crl(cons)?;

            let (sid, attrs, signature) = {
                // signerInfos
                cons.take_set(|cons| {
                    cons.take_sequence(|cons| {
                        cons.skip_u8_if(3)?;
                        let sid = cons.take_value_if(Tag::CTX_0, |content| {
                            KeyIdentifier::from_content(content)
                        })?;
                        let alg = DigestAlgorithm::take_from(cons)?;
                        if alg != digest_algorithm {
                            return Err(decode::Malformed.into());
                        }
                        let attrs = SignedAttrs::take_from_signed_message(
                            cons
                        )?;
                        if attrs.2 != content_type {
                            return Err(decode::Malformed.into());
                        }
                        let signature = Signature::new(
                            SignatureAlgorithm::cms_take_from(cons)?,
                            OctetString::take_from(cons)?.into_bytes(),
                        );
                        // no unsignedAttributes
                        Ok((sid, attrs, signature))
                    })
                })?
            };

            Ok(Self {
                digest_algorithm,
                content_type,
                content,
                ee_cert: id_cert,
                crl,

                sid,
                signed_attrs: attrs.0,
                signature,

                message_digest: attrs.1,
                _signing_time: attrs.3,
                _binary_signing_time: attrs.4
            })
        })
    }

    // Take the IdCert - although there could be multiple certificates, we
    // insist that there is only a single embedded EE certificate.
    fn take_id_cert<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<IdCert, S::Err> {
        cons.take_constructed_if(Tag::CTX_0, |cons| {
            cons.take_constructed(|tag, cons| match tag {
                Tag::SEQUENCE => IdCert::from_constructed(cons),
                _ => xerr!(Err(decode::Unimplemented.into())),
            })
        })
    }

    // Take the CRL, if present.
    //
    // In theory there could be multiple CRLs, one for each CA certificate
    // included in signing this object. However, nobody seems to do this, and
    // it's rather poorly defined how (and why) this would be done. So..
    // just expecting 1 CRL here.
    fn take_crl<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<SignedMessageCrl, S::Err> {
        cons.take_constructed_if(Tag::CTX_1, |cons| {
            SignedMessageCrl::take_from(cons)
        })
    }


}

/// # Validation
/// 
impl SignedMessage {
/// Validates the signed message.
    ///
    /// The requirements for an object to be valid are given in section 3
    /// of [RFC 6488].
    pub fn validate(&self, issuer: &IdCert) -> Result<(), ValidationError> {
        self.validate_at(issuer, Time::now())
    }

    /// Validates a signed message for a given point in time.
    pub fn validate_at(
        &self, issuer: &IdCert, when: Time
    ) -> Result<(), ValidationError> {
        self.verify_compliance()?;
        self.verify_signature()?;
        self.ee_cert.validate_ee_at(issuer, when)?;
        self.crl.validate(issuer, when)?;
        self.crl.validate_not_revoked(&self.ee_cert)?;
        Ok(())
    }

    /// Validates that the signed object complies with the specification.
    ///
    /// This is item 1 of [RFC 6488]`s section 3.
    fn verify_compliance(
        &self,
    ) -> Result<(), ValidationError> {
        // Sub-items a, b, d, e, f, g, h, i, j, k, l have been validated while
        // parsing. This leaves these:
        //
        // c. cert is an EE cert with the SubjectKeyIdentifier matching
        //    the sid field of the SignerInfo.
        if self.sid != self.ee_cert.subject_key_identifier() {
            return Err(ValidationError)
        }
        Ok(())
    }

    /// Verifies the signature of the object against contained certificate.
    ///
    /// This is item 2 of [RFC 6488]’s section 3.
    fn verify_signature(&self) -> Result<(), ValidationError> {
        let digest = {
            let mut context = self.digest_algorithm.start();
            self.content.iter().for_each(|x| context.update(x));
            context.finish()
        };
        if digest.as_ref() != self.message_digest.as_ref() {
            return Err(ValidationError);
        }
        let msg = self.signed_attrs.encode_verify();
        self.ee_cert
            .subject_public_key_info()
            .verify(&msg, &self.signature)
            .map_err(Into::into)
    }
}

/// # Creation and Encoding
/// 
impl SignedMessage {
    /// Create a new signed message under the given TA IdCert.
    pub fn create<S: Signer>(
        _content: Bytes,
        _issuing: &IdCert,
        _signer: &S,
    ) -> Result<Self, SigningError<S::Error>> {
        // // Steps:
        // // - create content to sign
        // // - sign content with one off key
        // // - create and sign EE cert with one off key as subject
        // // - create and sign new CRL
        // // - include EE cert
        // //

        // let digest_algorithm = DigestAlgorithm::default();
        // let content_type = PROTOCOL_CONTENT_TYPE;
        // let content = OctetString::new(content);

        // Ok(SignedMessage {
        //     digest_algorithm,
        //     content_type,
        //     content,
        //     ee_cert: todo!(),
        //     crl: todo!(),
        //     sid: todo!(),
        //     signed_attrs: todo!(),
        //     signature: todo!(),
        //     message_digest: todo!(),
        //     _signing_time: todo!(),
        //     _binary_signing_time: todo!(),
        // })
        todo!()
    }
}

//------------ SignedMessageCrl ----------------------------------------------

/// An RPKI certificate revocation list used in RFC6492 and RFC8181 protocol
/// signed messages. Unfortunately.. it is not very clearly defined what
/// extensions are to be included - so we cannot re-use the CRL definition
/// from RFC 6487. That would be too easy..
/// 
/// For example the RFC 6487 CRLs will include an authority key identifier,
/// which may be omitted here.
#[derive(Clone, Debug)]
struct SignedMessageCrl {
    /// The outer structure of the CRL.
    signed_data: SignedData,

    /// The payload of the CRL.
    tbs: SignedMessageTbsCrl,
}

/// # Validation
/// 
impl SignedMessageCrl {
    /// Validates the certificate revocation list.
    ///
    /// The list’s signature is validated against the provided public key.
    pub fn validate(
        &self,
        issuer: &IdCert,
        when: Time
    ) -> Result<(), ValidationError> {
        if self.tbs.signature != self.signed_data.signature().algorithm() {
            return Err(ValidationError)
        }
        self.signed_data.verify_signature(issuer.subject_public_key_info())?;
        self.tbs.validate(issuer, when)
    }

    /// Returns whether the given serial number is on this revocation list.
    fn validate_not_revoked(
        &self, id_cert: &IdCert
    ) -> Result<(), ValidationError> {
        if self.tbs.revoked_certs.contains(id_cert.serial_number()) {
            Err(ValidationError)
        } else {
            Ok(())
        }
    }
}

/// # Decode
/// 
impl SignedMessageCrl {
    /// Takes an encoded CRL from the beginning of a constructed value.
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the content of a certificate revocation list.
    fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::from_constructed(cons)?;
        let tbs = signed_data.data().clone()
            .decode(SignedMessageTbsCrl::take_from)?;
        Ok(Self { signed_data, tbs })
    }
}

/// The payload of a SignedMessageCrl
#[derive(Clone, Debug)]
struct SignedMessageTbsCrl {
    /// The algorithm used for signing the certificate.
    /// 
    /// This MUST be RSA.
    signature: SignatureAlgorithm,
    
    /// The name of the issuer.
    ///
    /// This should match the subject of the issuing certificate.
    _issuer: Name,

    /// The time this version of the CRL was created. Must be before now.
    this_update: Time,

    /// The time the next version of the CRL is likely to be created. Must
    /// be after now - we do not accept stale CRLs.
    next_update: Time,

    /// The list of revoked certificates.
    revoked_certs: RevokedCertificates,

    /// Authority Key Identifier, may be included.. if it is included
    /// then we should validate that it matches the issuing certificate.
    authority_key_id: Option<KeyIdentifier>,

    /// CRL Number, may be included but it's irrelevant in this context
    _crl_number: Option<Serial>,
}

/// # Validation
/// 
impl SignedMessageTbsCrl {
    /// Validates the certificate revocation list content
    /// 
    /// Note that the signature is verified earlier on the outer wrapping
    /// of this content.
    fn validate(
        &self,
        issuer: &IdCert,
        when: Time,
    ) -> Result<(), ValidationError> {
        if self.this_update > when || self.next_update < when {
            Err(ValidationError)
        } else {
            match self.authority_key_id {
                None => Ok(()),
                Some(aki) => if issuer.subject_key_id() == aki {
                    Ok(())
                } else {
                    Err(ValidationError)
                }
            }
        }
    }
}

/// # Decoding
/// 
impl SignedMessageTbsCrl {
    /// Takes a value from the beginning of a encoded constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            // version. Technically it is optional but we need v2, so it must
            // actually be there. v2 is encoded as an integer of value 1.
            cons.skip_u8_if(1)?;
            let signature = SignatureAlgorithm::x509_take_from(cons)?;
            let issuer = Name::take_from(cons)?;
            let this_update = Time::take_from(cons)?;
            let next_update = Time::take_from(cons)?;
            let revoked_certs = RevokedCertificates::take_from(cons)?;
            let mut authority_key_id = None;
            let mut crl_number = None;
            cons.take_constructed_if(Tag::CTX_0, |cons| {
                cons.take_sequence(|cons| {
                    while let Some(()) = cons.take_opt_sequence(|cons| {
                        let id = Oid::take_from(cons)?;
                        let _critical = cons.take_opt_bool()?.unwrap_or(false);
                        let value = OctetString::take_from(cons)?;
                        Mode::Der.decode(value.to_source(), |content| {
                            if id == oid::CE_AUTHORITY_KEY_IDENTIFIER {
                                Self::take_authority_key_identifier(
                                    content, &mut authority_key_id
                                )
                            }
                            else if id == oid::CE_CRL_NUMBER {
                                Self::take_crl_number(
                                    content, &mut crl_number
                                )
                            }
                            else {
                                // RFC 6487 says that no other extensions are
                                // allowed. So we fail even if there is only
                                // non-critical extension.
                                xerr!(Err(decode::Malformed))
                            }
                        }).map_err(Into::into)
                    })? { }
                    Ok(())
                })
            })?;
            
            Ok(Self {
                signature,
                _issuer: issuer,
                this_update,
                next_update,
                revoked_certs,
                authority_key_id,
                _crl_number: crl_number
            })
        })
    }

    /// Parses the Authority Key Identifier extension.
    fn take_authority_key_identifier<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        authority_key_id: &mut Option<KeyIdentifier>,
    ) -> Result<(), S::Err> {
        update_once(authority_key_id, || {
            cons.take_sequence(|cons| {
                cons.take_value_if(Tag::CTX_0, KeyIdentifier::from_content)
            })
        })
    }

    /// Parses the CRL Number extension.
    fn take_crl_number<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        crl_number: &mut Option<Serial>,
    ) -> Result<(), S::Err> {
        update_once(crl_number, || {
            Serial::take_from(cons)
        })
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    
    use super::*;

    #[test]
    fn parse_and_validate_signed_message() {
        let der = include_bytes!("../../test-data/remote/sigmsg/pdu_200.der");
        let msg = SignedMessage::decode(Bytes::from_static(der), false).unwrap();

        let b = include_bytes!("../../test-data/remote/sigmsg/cms_ta.cer");
        let id_cert = IdCert::decode(Bytes::from_static(b)).unwrap();

        msg.validate_at(&id_cert, Time::utc(2012, 1, 1, 0, 0, 0)).unwrap();
    }

}

#[cfg(all(test, feature="softkeys"))]
mod signer_test {
    use crate::{
        remote::idcert::IdCert,
        repository::crypto::softsigner::OpenSslSigner
    };

    
    #[test]
    fn encode_and_sign_signed_message() {
        let signer = OpenSslSigner::new();
        let _ta_cert = IdCert::new_ta(1, &signer).unwrap();


    }

}
