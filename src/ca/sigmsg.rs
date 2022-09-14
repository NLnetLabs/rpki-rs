//! Signed Message CMS wrappers used in the RPKI publication (RFC 8181) and
//! provisioning (RFC 6492) protocols.

use bcder::{decode, encode, Captured};
use bcder::{Mode, Oid, OctetString, Tag};
use bcder::decode::{DecodeError, IntoSource, Source};
use bcder::encode::PrimitiveContent;
use bytes::Bytes;
use crate::oid;
use crate::crypto::{
    DigestAlgorithm, KeyIdentifier, RpkiSignature, RpkiSignatureAlgorithm,
    SignatureAlgorithm, Signer, SigningError, PublicKey
};
use crate::repository::error::{
    InspectionError, ValidationError, VerificationError
};
use crate::repository::sigobj::{MessageDigest, SignedAttrs};
use crate::repository::x509::{
    Name, Serial, SignedData, Time, Validity, encode_extension,
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
/// = This uses [`IdCert`] instead of [`Cert`] as the EE (no INRs needed)
/// = This MUST include a CRL
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
    signature: RpkiSignature,

    //--- SignedAttributes
    //
    message_digest: MessageDigest,
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
    pub fn decode<S: IntoSource>(
        source: S, strict: bool,
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        if strict {
            Mode::Der
        }
        else {
            Mode::Ber
        }.decode(source.into_source(), Self::take_from)
    }

    /// Takes a signed message from an encoded constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            oid::SIGNED_DATA.skip_if(cons)?; // contentType
            cons.take_constructed_if(Tag::CTX_0, Self::take_signed_data)
        })
    }

    fn take_signed_data<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
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
                return Err(cons.content_err("unexpected content type"));
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
                            return Err(cons.content_err(
                                    "signer algorithm mismatch"
                            ));
                        }
                        let attrs = SignedAttrs::take_from_signed_message(
                            cons
                        )?;
                        if attrs.2 != content_type {
                            return Err(cons.content_err(
                                "content type in signed attributes differs"
                            ));
                        }
                        let signature = RpkiSignature::new(
                            RpkiSignatureAlgorithm::cms_take_from(cons)?,
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
            })
        })
    }

    // Take the IdCert - although there could be multiple certificates, we
    // insist that there is only a single embedded EE certificate.
    fn take_id_cert<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<IdCert, DecodeError<S::Error>> {
        cons.take_constructed_if(Tag::CTX_0, |cons| {
            cons.take_constructed(|tag, cons| match tag {
                Tag::SEQUENCE => IdCert::from_constructed(cons),
                _ => {
                    Err(cons.content_err(
                        "multiple embedded EE certificates not supported"
                    ))
                }
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
    ) -> Result<SignedMessageCrl, DecodeError<S::Error>> {
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
    pub fn validate(
        &self, issuer_key: &PublicKey
    ) -> Result<(), ValidationError> {
        self.validate_at(issuer_key, Time::now())
    }

    /// Validates a signed message for a given point in time.
    pub fn validate_at(
        &self, issuer_key: &PublicKey, when: Time
    ) -> Result<(), ValidationError> {
        self.inspect()?;
        self.verify()?;
        self.ee_cert.validate_ee_at(issuer_key, when)?;
        self.crl.validate(issuer_key, when)?;
        self.crl.verify_not_revoked(&self.ee_cert)?;
        Ok(())
    }

    /// Validates that the signed object complies with the specification.
    ///
    /// This is item 1 of [RFC 6488]`s section 3.
    fn inspect(
        &self,
    ) -> Result<(), InspectionError> {
        // Sub-items a, b, d, e, f, g, h, i, j, k, l have been validated while
        // parsing. This leaves these:
        //
        // c. cert is an EE cert with the SubjectKeyIdentifier matching
        //    the sid field of the SignerInfo.
        if self.sid != self.ee_cert.subject_key_identifier() {
            return Err(InspectionError::new(
                "Subject Key Identifier mismatch in signed object"
            ))
        }
        Ok(())
    }

    /// Verifies the signature of the object against contained certificate.
    ///
    /// This is item 2 of [RFC 6488]’s section 3.
    fn verify(&self) -> Result<(), VerificationError> {
        let digest = {
            let mut context = self.digest_algorithm.start();
            self.content.iter().for_each(|x| context.update(x));
            context.finish()
        };
        if digest.as_ref() != self.message_digest.as_ref() {
            return Err(VerificationError::new(
                "message digest mismatch in signed object"
            ))
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
        data: Bytes,
        validity: Validity,
        issuing_key_id: &S::KeyId,
        signer: &S,
    ) -> Result<Self, SigningError<S::Error>> {
        // Steps:
        // - create content to sign
        // - sign content with one off key
        // - create and sign EE cert with one off key as subject
        // - create and sign new CRL
        // - include EE cert

        let digest_algorithm = DigestAlgorithm::default();
        let content_type = Oid(oid::PROTOCOL_CONTENT_TYPE.0.into());
        
        // Produce signed attributes
        let message_digest = digest_algorithm.digest(&data).into();
        let signing_time = Some(Time::now());
        let binary_signing_time = None;
        
        let signed_attrs = SignedAttrs::new(
            &content_type,
            &message_digest,
            signing_time,
            binary_signing_time
        );
        
        let (signature, ee_key) = signer.sign_one_off(
            RpkiSignatureAlgorithm::default(), &signed_attrs.encode_verify()
        )?;
        let sid = ee_key.key_identifier();
        
        let crl = SignedMessageCrl::create(
            &validity,
            issuing_key_id,
            signer
        )?;

        let ee_cert = IdCert::new_ee(
            &ee_key,
            validity,
            issuing_key_id,
            signer
        )?;
        
        let content = OctetString::new(data);

        Ok(SignedMessage {
            digest_algorithm,
            content_type,
            content,
            ee_cert,
            crl,
            sid,
            signed_attrs,
            signature,
            message_digest,
        })
    }

    /// Returns a value encoder for a reference to a signed message.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            oid::SIGNED_DATA.encode(), // outer contentType
            encode::sequence_as(Tag::CTX_0, 
                encode::sequence((
                    3u8.encode(), // version
                    self.digest_algorithm.encode_set(),
                    encode::sequence(( // encapContentInfo
                        self.content_type.encode_ref(),
                        encode::sequence_as(Tag::CTX_0,
                            self.content.encode_ref()
                        ),
                    )),
                    encode::sequence_as(Tag::CTX_0, // certificates
                        self.ee_cert.encode_ref(),
                    ),
                    encode::sequence_as(Tag::CTX_1, // CRL
                        self.crl.encode_ref(),
                    ),
                    encode::set( // signerInfo
                        encode::sequence(( // SignerInfo
                            3u8.encode(), // version
                            self.sid.encode_ref_as(Tag::CTX_0),
                            self.digest_algorithm.encode(), // digestAlgorithm
                            self.signed_attrs.encode_ref(), // signedAttrs
                            self.signature.algorithm().cms_encode(),
                                                        // signatureAlgorithm
                            OctetString::encode_slice( // signature
                                self.signature.value().as_ref()
                            ),
                            // unsignedAttrs omitted
                        ))
                    )
                ))
            )
        ))
    }

    /// Returns a captured encoding of the certificate.
    pub fn to_captured(&self) -> Captured {
        Captured::from_values(Mode::Der, self.encode_ref())
    }

}

//------------ SignedMessageCrl ----------------------------------------------

/// A CRL used in RFC6492 and RFC8181 CMS.
/// 
/// Unfortunately.. it is not very clearly defined what extensions are to be
/// included - so we cannot re-use the CRL definition from RFC 6487. For
/// example the RFC 6487 CRLs will include an authority key identifier,
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
        issuer_key: &PublicKey,
        when: Time
    ) -> Result<(), ValidationError> {
        if self.tbs.signature != *self.signed_data.signature().algorithm() {
            return Err(VerificationError::new(
                "CRL signature algorithm mismatch"
            ).into())
        }
        self.signed_data.verify_signature(
            issuer_key
        ).map_err(VerificationError::from)?;
        self.tbs.validate(issuer_key, when)
    }

    /// Returns whether the given serial number is on this revocation list.
    fn verify_not_revoked(
        &self, id_cert: &IdCert
    ) -> Result<(), VerificationError> {
        if self.tbs.revoked_certs.contains(id_cert.serial_number()) {
            Err(VerificationError::new(
                "signed object EE certificate revoked"
            ))
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
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the content of a certificate revocation list.
    fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        let signed_data = SignedData::from_constructed(cons)?;
        let tbs = signed_data.data().clone().decode(
            SignedMessageTbsCrl::take_from
        ).map_err(DecodeError::convert)?;
        Ok(Self { signed_data, tbs })
    }
}

/// # Encode
/// 
impl SignedMessageCrl {
    /// Creates a new, empty, CRL to be included in a new SignedMessage.
    /// Note that this CRL is empty because in our context we will only
    /// ever use short-lived one-off EE certificate which never need
    /// to be revoked.
    /// 
    /// The CRL will use a this_update and next_update time which is aligned
    /// with the EE certificate validity time for the signed message CMS
    /// wrapper.
    fn create<S: Signer>(
        validity: &Validity,
        issuing_key_id: &S::KeyId,
        signer: &S,
    ) -> Result<Self, SigningError<S::Error>> {
        let issuing_pub_key = signer.get_key_info(issuing_key_id)?;
        
        let signature = RpkiSignatureAlgorithm::default();
        let issuer = Name::from_pub_key(&issuing_pub_key);
        
        let this_update = validity.not_before();
        let next_update = validity.not_after();
        
        let revoked_certs = SignedMessageRevokedCertificates::empty();
        
        let authority_key_id = Some(issuing_pub_key.key_identifier());
        
        // We are required to include a CRL number.
        //
        // Because the number MUST always increase, let's just use  time in
        // milliseconds. We don't sign *that* quickly after all..
        let crl_number = Some(Serial::from(
            Time::now().timestamp_millis() as u64
        ));

        let tbs = SignedMessageTbsCrl {
            signature,
            issuer,
            this_update,
            next_update,
            revoked_certs,
            authority_key_id,
            crl_number,
        };

        let data = Captured::from_values(Mode::Der, tbs.encode_ref());
        let signature = signer.sign(issuing_key_id, tbs.signature, &data)?;
        let signed_data = SignedData::new(data, signature);

        Ok(SignedMessageCrl {
            signed_data,
            tbs,
        })
    }

    /// Returns a value encoder for a reference to a signed message CRL.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        self.signed_data.encode_ref()
    }
}


/// The payload of a SignedMessageCrl
#[derive(Clone, Debug)]
struct SignedMessageTbsCrl {
    /// The algorithm used for signing the certificate.
    /// 
    /// This MUST be RSA.
    signature: RpkiSignatureAlgorithm,
    
    /// The name of the issuer.
    ///
    /// This should match the subject of the issuing certificate.
    issuer: Name,

    /// The time this version of the CRL was created. Must be before now.
    this_update: Time,

    /// The time the next version of the CRL is likely to be created. Must
    /// be after now - we do not accept stale CRLs.
    next_update: Time,

    /// The list of revoked certificates.
    revoked_certs: SignedMessageRevokedCertificates,

    /// Authority Key Identifier, may be included.. if it is included
    /// then we should validate that it matches the issuing certificate.
    authority_key_id: Option<KeyIdentifier>,

    /// CRL Number, may be included but it's irrelevant in this context
    crl_number: Option<Serial>,
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
        issuer_key: &PublicKey,
        when: Time,
    ) -> Result<(), ValidationError> {
        if self.this_update > when {
            Err(VerificationError::new(
                "CRL thisUpdate time in the future"
            ).into())
        }
        else if self.next_update < when {
            Err(VerificationError::new(
                "CRL nextUpdate time in the past"
            ).into())
        }
        else {
            match self.authority_key_id {
                None => Ok(()),
                Some(aki) => if issuer_key.key_identifier() == aki {
                    Ok(())
                } else {
                    Err(VerificationError::new(
                        "CRL's Authority Key Identifier doesn't match \
                        issuer key"
                    ).into())
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
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            // version. Technically it is optional but we need v2, so it must
            // actually be there. v2 is encoded as an integer of value 1.
            cons.skip_u8_if(1)?;
            let signature = RpkiSignatureAlgorithm::x509_take_from(cons)?;
            let issuer = Name::take_from(cons)?;
            let this_update = Time::take_from(cons)?;
            let next_update = Time::take_from(cons)?;
            let revoked_certs = SignedMessageRevokedCertificates::take_from(cons)?;

            let mut authority_key_id = None;
            let mut crl_number = None;
            cons.take_constructed_if(Tag::CTX_0, |cons| {
                cons.take_sequence(|cons| {
                    while let Some(()) = cons.take_opt_sequence(|cons| {
                        let id = Oid::take_from(cons)?;
                        let _critical = cons.take_opt_bool()?.unwrap_or(false);
                        let value = OctetString::take_from(cons)?;
                        Mode::Der.decode(value.into_source(), |content| {
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
                                // RFC 6492 and 8181 are under-specified.
                                // Just skip extensions as they are very
                                // unlikely to be relevant in any way.
                                content.skip_all()
                            }
                        }).map_err(DecodeError::convert)
                    })? { }
                    Ok(())
                })
            })?;
            
            Ok(Self {
                signature,
                issuer,
                this_update,
                next_update,
                revoked_certs,
                authority_key_id,
                crl_number
            })
        })
    }

    /// Parses the Authority Key Identifier extension.
    fn take_authority_key_identifier<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        authority_key_id: &mut Option<KeyIdentifier>,
    ) -> Result<(), DecodeError<S::Error>> {
        if authority_key_id.is_some() {
            Err(cons.content_err(
                "duplicate Authority Key Identifier extension"
            ))
        }
        else {
            *authority_key_id = Some(
                cons.take_sequence(|cons| {
                    cons.take_value_if(
                        Tag::CTX_0, KeyIdentifier::from_content
                    )
                })?
            );
            Ok(())
        }
    }

    /// Parses the CRL Number extension.
    fn take_crl_number<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        crl_number: &mut Option<Serial>,
    ) -> Result<(), DecodeError<S::Error>> {
        if crl_number.is_some() {
            Err(cons.content_err("duplicate CRL number extension"))
        }
        else {
            *crl_number = Some(
                Serial::take_from(cons)?
            );
            Ok(())
        }
    }
}

/// # Encoding
/// 
impl SignedMessageTbsCrl {
    /// Returns a value encoder for a reference to this value.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            1.encode(), // version
            self.signature.x509_encode(),
            self.issuer.encode_ref(),
            self.this_update.encode_varied(),
            self.next_update.encode_varied(),
            self.revoked_certs.encode_ref(),
            encode::sequence_as(Tag::CTX_0, 
                encode::sequence((
                    self.authority_key_id.as_ref().map(|authority_key_id| {
                        encode_extension(
                            &oid::CE_AUTHORITY_KEY_IDENTIFIER, false,
                            encode::sequence(
                                authority_key_id.encode_ref_as(Tag::CTX_0)
                            )
                        )
                    }),
                    self.crl_number.map(|crl_number| {
                        encode_extension(
                            &oid::CE_CRL_NUMBER, false,
                            crl_number.encode()
                        )
                    }),
                ))
            )
        ))
    }
}


//------------ SignedMessageRevokedCertificates ------------------------------

/// The list of revoked certificates.
///
/// A value of this type wraps the bytes of the DER encoded list. You can
/// check whether a certain serial number is part of this list via the
/// `contains` method.
/// 
/// Note that this almost, but not quite, like the [`RevokedCertificates`]
/// found in RPKI CRLs - as RFC 6492 and RFC 8181 is more permissive than
/// RFC 6487.
#[derive(Clone, Debug)]
pub struct SignedMessageRevokedCertificates(Captured);

impl SignedMessageRevokedCertificates {
    /// Create an empty RevokedCertificates.
    pub fn empty() -> Self {
        let entries: Vec<SignedMessageCrlEntry> = vec![];
        Self::from_iter(entries)
    }

    /// Takes a revoked certificates list from the beginning of a value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        let res = cons.take_opt_sequence(|cons| {
            cons.capture(|cons| {
                while SignedMessageCrlEntry::take_opt_from(cons)?.is_some() { }
                Ok(())
            })
        })?;
        Ok(SignedMessageRevokedCertificates(match res {
            Some(res) => res,
            None => Captured::empty(Mode::Der)
        }))
    }

    /// Returns whether the given serial number is contained on this list.
    ///
    /// The method walks over the list, decoding it on the fly and checking
    /// each entry.
    pub fn contains(&self, serial: Serial) -> bool {
        Mode::Der.decode(self.0.as_ref(), |cons| {
            while let Some(entry) = 
                SignedMessageCrlEntry::take_opt_from(cons).unwrap() {
                if entry.user_certificate == serial {
                    return Ok(true)
                }
            }
            Ok(false)
        }).unwrap()
    }

    /// Returns an iterator over the entries in the list.
    pub fn iter(&self) -> SignedMessageRevokedCertificatesIter {
        SignedMessageRevokedCertificatesIter(self.0.clone())
    }

    /// Returns a value encoder for a reference to the value.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence(&self.0)
    }

    /// Create a value from an iterator over CRL entries.
    ///
    /// This can’t be the `FromIterator` trait because of the `Clone`
    /// requirement on `I::IntoIter`
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = SignedMessageCrlEntry>,
        <I as IntoIterator>::IntoIter: Clone
    {
        SignedMessageRevokedCertificates(Captured::from_values(
            Mode::Der, encode::iter(
                iter.into_iter().map(SignedMessageCrlEntry::encode)
            )
        ))
    }
}


//------------ SignedMessageRevokedCertificatesIter --------------------------

/// An iterator over the entries in the list of revoked certificates.
#[derive(Clone, Debug)]
pub struct SignedMessageRevokedCertificatesIter(Captured);

impl Iterator for SignedMessageRevokedCertificatesIter {
    type Item = SignedMessageCrlEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.decode_partial(|cons| SignedMessageCrlEntry::take_opt_from(cons)).unwrap()
    }
}


//------------ CrlEntry ------------------------------------------------------

/// An entry in the revoked certificates list.
#[derive(Clone, Copy, Debug)]
pub struct SignedMessageCrlEntry {
    /// The serial number of the revoked certificate.
    user_certificate: Serial,

    /// The time of revocation.
    revocation_date: Time,
}

impl SignedMessageCrlEntry {
    /// Creates a new CrlEntry for inclusion on a new Crl
    pub fn new(user_certificate: Serial, revocation_date: Time) -> Self {
        SignedMessageCrlEntry { user_certificate, revocation_date }
    }

    /// Takes a single CRL entry from the beginning of a constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Takes an optional CRL entry from the beginning of a constructed value.
    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(Self::from_constructed)
    }

    /// Parses the content of a CRL entry.
    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        let entry = SignedMessageCrlEntry {
            user_certificate: Serial::take_from(cons)?,
            revocation_date: Time::take_from(cons)?,
        };
        // skip the extensions, they are allowed by the spec which is rather
        // under-specified, but there isn't anything useful we can do with
        // with these.
        cons.take_opt_sequence(|cons| cons.skip_all())?;
        Ok(entry)
    }

    /// Returns a value encoder for the entry.
    pub fn encode(self) -> impl encode::Values {
        encode::sequence((
            self.user_certificate.encode(),
            self.revocation_date.encode_varied(),
        ))
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    
    use super::*;

    #[test]
    fn parse_and_validate_signed_message() {
        let der = include_bytes!("../../test-data/ca/sigmsg/pdu_200.der");
        let msg = SignedMessage::decode(Bytes::from_static(der), false).unwrap();

        let b = include_bytes!("../../test-data/ca/sigmsg/cms_ta.cer");
        let id_cert = IdCert::decode(Bytes::from_static(b)).unwrap();

        msg.validate_at(
            id_cert.public_key(),
            Time::utc(2012, 1, 1, 0, 0, 0)
        ).unwrap();
    }

}

#[cfg(all(test, feature="softkeys"))]
mod signer_test {
    use super::*;

    use crate::{
        ca::idcert::IdCert,
        crypto::{softsigner::OpenSslSigner, PublicKeyFormat}
    };

    
    #[test]
    fn encode_and_sign_signed_message() {
        let signer = OpenSslSigner::new();

        let ta_key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
        let ta_cert = IdCert::new_ta(
            Validity::from_secs(60),
            &ta_key,
            &signer
        ).unwrap();

        let content = Bytes::from_static(b"euj");
        let validity = Validity::from_secs(60);

        // Create and sign message
        let signed_message = SignedMessage::create(
            content,
            validity,
            &ta_key,
            &signer
        ).unwrap();

        // Encode to bytes
        let bytes = signed_message.to_captured().into_bytes();

        // Parse and decode again
        let decoded = SignedMessage::decode(bytes, false).unwrap();

        // Validate it
        decoded.validate(ta_cert.public_key()).unwrap();
    }
}
