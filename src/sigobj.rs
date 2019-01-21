//! Signed Objects

use bcder::decode;
use bcder::{Captured, Mode, Oid, Tag};
use bcder::string::{OctetString, OctetStringSource};
use bytes::Bytes;
use crate::cert::{Cert, ResourceCert};
use crate::oid;
use crate::x509::{Time, ValidationError, update_once};
use crate::crypto::{DigestAlgorithm, Signature, SignatureAlgorithm};


//------------ SignedObject --------------------------------------------------

/// A signed object.
///
/// Signed objects are a more strict profile of a CMS signed-data object.
/// They are specified in [RFC 6088] while CMS is specified in [RFC 5652].
#[derive(Clone, Debug)]
pub struct SignedObject {
    content_type: Oid<Bytes>,
    content: OctetString,
    cert: Cert,
    signer_info: SignerInfo,
}

impl SignedObject {
    pub fn decode<S: decode::Source>(
        source: S,
        strict: bool
    ) -> Result<Self, S::Err> {
        if strict { Mode::Der }
        else { Mode::Ber }
            .decode(source, Self::take_from)
    }

    /// Returns a reference to the object’s content type.
    pub fn content_type(&self) -> &Oid<Bytes> {
        &self.content_type
    }

    /// Returns a reference to the object’s content.
    pub fn content(&self) -> &OctetString {
        &self.content
    }

    pub fn decode_content<F, T>(&self, op: F) -> Result<T, decode::Error>
    where F: FnOnce(&mut decode::Constructed<OctetStringSource>)
                    -> Result<T, decode::Error> {
        // XXX Let’s see if using DER here at least holds.
        Mode::Der.decode(self.content.to_source(), op)
    }

    /// Returns a reference to the certificate the object is signed with.
    pub fn cert(&self) -> &Cert {
        &self.cert
    }
}


impl SignedObject {
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            oid::SIGNED_DATA.skip_if(cons)?; // contentType
            cons.take_constructed_if(Tag::CTX_0, Self::take_signed_data)
        })
    }

    /// Parses a SignedData value.
    ///
    /// RFC 6488:
    ///
    /// ```text
    /// SignedData ::= SEQUENCE {
    ///     version CMSVersion,
    ///     digestAlgorithms DigestAlgorithmIdentifiers,
    ///     encapContentInfo EncapsulatedContentInfo,
    ///     certificates [0] IMPLICIT CertificateSet OPTIONAL,
    ///     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
    ///     signerInfos SignerInfos }
    /// ```
    ///
    /// `version` must be 3, `certificates` present and `crls` not.
    fn take_signed_data<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.skip_u8_if(3)?; // version -- must be 3
            DigestAlgorithm::skip_set(cons)?; // digestAlgorithms
            let (content_type, content)
                = Self::take_encap_content_info(cons)?;
            let cert = Self::take_certificates(cons)?;
            let signer_info = SignerInfo::take_set_from(cons)?;
            Ok(SignedObject {
                content_type, content, cert, signer_info
            })
        })
    }

    /// Parses an EncapsulatedContentInfo value.
    ///
    /// RFC 6488:
    ///
    /// ```text
    /// EncapsulatedContentInfo ::= SEQUENCE {
    ///       eContentType ContentType,
    ///       eContent [0] EXPLICIT OCTET STRING OPTIONAL }
    /// ```
    ///
    /// For a ROA, `eContentType` must be `oid:::ROUTE_ORIGIN_AUTH`.
    pub fn take_encap_content_info<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(Oid<Bytes>, OctetString), S::Err> {
        cons.take_sequence(|cons| {
            Ok((
                Oid::take_from(cons)?,
                cons.take_constructed_if(
                    Tag::CTX_0,
                    OctetString::take_from
                )?
            ))
        })
    }

    /// Parse a certificates field of a SignedData value.
    ///
    /// The field is `[0] IMPLICIT CertificateSet`.
    ///
    /// And then, RFC 5652:
    ///
    /// ```text
    /// CertificateSet ::= SET OF CertificateChoices
    /// CertificateChoices ::= CHOICE {
    ///   certificate Certificate,
    ///   extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
    ///   v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
    ///   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
    ///   other [3] IMPLICIT OtherCertificateFormat }
    /// ```
    /// 
    /// Certificate is a SEQUENCE. For the moment, we don’t implement the
    /// other choices.
    ///
    /// RFC 6288 limites the set to exactly one.
    fn take_certificates<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Cert, S::Err> {
        cons.take_constructed_if(Tag::CTX_0, |cons| {
            cons.take_constructed(|tag, cons| {
                match tag {
                    Tag::SEQUENCE =>  Cert::from_constructed(cons),
                    _ => {
                        xerr!(Err(decode::Unimplemented.into()))
                    }
                }
            })
        })
    }

    /// Validates the signed object.
    ///
    /// The requirements for an object to be valid are given in section 3
    /// of [RFC 6488].
    ///
    /// Upon success, the method returns the validated certificate and the
    /// content.
    pub fn validate(
        self,
        issuer: &ResourceCert,
        strict: bool,
    ) -> Result<ResourceCert, ValidationError> {
        self.validate_at(issuer, strict, Time::now())
    }

    pub fn validate_at(
        self,
        issuer: &ResourceCert,
        strict: bool,
        now: Time,
    ) -> Result<ResourceCert, ValidationError> {
        self.verify_compliance(strict)?;
        self.verify_signature(strict)?;
        self.cert.validate_ee_at(issuer, strict, now)
    }

    /// Validates that the signed object complies with the specification.
    ///
    /// This is item 1 of [RFC 6488]`s section 3.
    fn verify_compliance(
        &self,
        _strict: bool
    ) -> Result<(), ValidationError> {
        // Sub-items a, b, d, e, f, g, i, j, k, l have been validated while
        // parsing. This leaves these:
        //
        // c. cert is an EE cert with the SubjectKeyIdentifer matching
        //    the sid field of the SignerInfo.
        if &self.signer_info.sid != self.cert.subject_key_identifier() {
            return Err(ValidationError)
        }
        // h. eContentType equals the OID in the value of the content-type
        //    signed attribute.
        if self.content_type != self.signer_info.signed_attrs.content_type {
            return Err(ValidationError)
        }
        Ok(())
    }

    /// Verifies the signature of the object against contained certificate.
    ///
    /// This is item 2 of [RFC 6488]’s section 3.
    fn verify_signature(&self, _strict: bool) -> Result<(), ValidationError> {
        let digest = {
            let mut context = self.signer_info.digest_algorithm().start();
            self.content.iter().for_each(|x| context.update(x));
            context.finish()
        };
        if digest.as_ref() != self.signer_info.message_digest() {
            return Err(ValidationError)
        }
        let msg = self.signer_info.signed_attrs.encode_verify();
        self.cert.subject_public_key_info().verify(
            &msg,
            &self.signer_info.signature()
        ).map_err(Into::into)
    }
}


//------------ SignerInfo ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct SignerInfo {
    sid: OctetString,
    digest_algorithm: DigestAlgorithm,
    signed_attrs: SignedAttributes,
    signature: Signature,
}

impl SignerInfo {
    pub fn signed_attrs(&self) -> &SignedAttributes {
        &self.signed_attrs
    }

    pub fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn take_set_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_set(Self::take_from)
    }

    /// Parses a SignerInfo.
    ///
    /// ```text
    /// SignerInfo ::= SEQUENCE {
    ///     version CMSVersion,
    ///     sid SignerIdentifier,
    ///     digestAlgorithm DigestAlgorithmIdentifier,
    ///     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
    ///     signatureAlgorithm SignatureAlgorithmIdentifier,
    ///     signature SignatureValue,
    ///     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
    /// ```
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.skip_u8_if(3)?;
            Ok(SignerInfo {
                sid: cons.take_value_if(Tag::CTX_0, |content| {
                    OctetString::from_content(content)
                })?,
                digest_algorithm: DigestAlgorithm::take_from(cons)?,
                signed_attrs: SignedAttributes::take_from(cons)?,
                signature: Signature::new(
                    SignatureAlgorithm::cms_take_from(cons)?,
                    OctetString::take_from(cons)?.to_bytes()
                )
            })
        })
    }

    pub fn message_digest(&self) -> Bytes {
        self.signed_attrs.message_digest.to_bytes()
    }
}


//------------ SignedAttributes ----------------------------------------------

#[derive(Clone, Debug)]
pub struct SignedAttributes {
    raw: Captured,
    message_digest: OctetString,
    content_type: Oid<Bytes>,
    signing_time: Option<Time>,
    binary_signing_time: Option<u64>,
}

impl SignedAttributes {
    /// Parses Signed Attributes.
    ///
    /// ```text
    /// This appears in the SignerInfo as:
    ///    signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
    ///
    /// Where:
    ///
    ///         SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
    ///
    ///         Attribute ::= SEQUENCE {
    ///           attrType OBJECT IDENTIFIER,
    ///           attrValues SET OF AttributeValue }
    ///
    ///         AttributeValue ::= ANY
    ///
    /// See section 2.1.6.4 of RFC 6488 for specifications.
    /// ```
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let raw = cons.take_constructed_if(Tag::CTX_0, |c| c.capture_all())?;
        raw.clone().decode(|cons| {
            let mut message_digest = None;
            let mut content_type = None;
            let mut signing_time = None;
            let mut binary_signing_time = None;
            while let Some(()) = cons.take_opt_sequence(|cons| {
                let oid = Oid::take_from(cons)?;
                if oid == oid::CONTENT_TYPE {
                    Self::take_content_type(cons, &mut content_type)
                }
                else if oid == oid::MESSAGE_DIGEST {
                    Self::take_message_digest(cons, &mut message_digest)
                }
                else if oid == oid::SIGNING_TIME {
                    Self::take_signing_time(cons, &mut signing_time)
                }
                else if oid == oid::AA_BINARY_SIGNING_TIME {
                    Self::take_bin_signing_time(
                        cons,
                        &mut binary_signing_time
                    )
                }
                else {
                    xerr!(Err(decode::Malformed))
                }
            })? { }
            let message_digest = match message_digest {
                Some(some) => some,
                None => return Err(decode::Malformed)
            };
            let content_type = match content_type {
                Some(some) => some,
                None => return Err(decode::Malformed)
            };
            Ok(SignedAttributes {
                raw,
                message_digest,
                content_type,
                signing_time,
                binary_signing_time,
            })
        }).map_err(Into::into)
    }

    /// Parses the Content Type attribute.
    ///
    /// This attribute is defined in section 11.1. of RFC 5652. The attribute
    /// value is a SET of exactly one OBJECT IDENTIFIER.
    fn take_content_type<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        content_type: &mut Option<Oid<Bytes>>
    ) -> Result<(), S::Err> {
        update_once(content_type, || {
            cons.take_set(|cons| Oid::take_from(cons))
        })
    }

    fn take_message_digest<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        message_digest: &mut Option<OctetString>
    ) -> Result<(), S::Err> {
        update_once(message_digest, || {
            cons.take_set(|cons| OctetString::take_from(cons))
        })
    }

    fn take_signing_time<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        signing_time: &mut Option<Time>
    ) -> Result<(), S::Err> {
        update_once(signing_time, || {
            cons.take_set(Time::take_from)
        })
    }

    fn take_bin_signing_time<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        bin_signing_time: &mut Option<u64>
    ) -> Result<(), S::Err> {
        update_once(bin_signing_time, || {
            cons.take_set(|cons| cons.take_u64())
        })
    }

    pub fn encode_verify(&self) -> Vec<u8> {
        // XXX This may be outdated. Check!
        let mut res = Vec::new();
        res.push(0x31); // SET
        let len = self.raw.len();
        if len < 128 {
            res.push(len as u8)
        }
        else if len < 0x10000 {
            res.push(2);
            res.push((len >> 8) as u8);
            res.push(len as u8);
        }
        else {
            panic!("overly long signed attrs");
        }
        res.extend_from_slice(self.raw.as_ref());
        res
    }
}


/*
//------------ SignedObjectBuilder -------------------------------------------

#[derive(Clone, Debug)]
pub struct SignedObjectBuilder<C> {
    content_type: ConstOid,
    content: C,
    cert: CertBuilder,
}

The actual construction has to work like this:

   o  Produce the signed attributes.

   o  Sign the signed attributes with a one-off key.

   o  Take the public key from that and finish the certificate.

   o  Sign the certificate with the issuing CA certificate.

   o  Put it all together.

*/

