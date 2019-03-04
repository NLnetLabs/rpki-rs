//! Signed Objects

use bcder::{decode, encode};
use bcder::{Captured, ConstOid, Mode, Oid, Tag};
use bcder::encode::PrimitiveContent;
use bcder::string::{OctetString, OctetStringSource};
use bytes::Bytes;
use crate::cert::{Cert, CertBuilder, ResourceCert};
use crate::oid;
use crate::x509::{Time, ValidationError, update_once};
use crate::crypto::{
    DigestAlgorithm, Signature, SignatureAlgorithm, Signer, SigningError
};


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
    fn take_certificates<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Cert, S::Err> {
        cons.take_constructed_if(Tag::CTX_0, Cert::take_from)
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


//------------ SignedObjectBuilder -------------------------------------------

#[derive(Clone, Debug)]
pub struct SignedObjectBuilder<C> {
    content_type: ConstOid,
    content: C,
    cert: CertBuilder,
    signing_time: Option<Time>,
    binary_signing_time: Option<Time>,
}

impl<C> SignedObjectBuilder<C> {
    pub fn new(
        content_type: ConstOid,
        content: C,
        cert: CertBuilder
    ) -> Self {
        SignedObjectBuilder {
            content_type,
            content,
            cert,
            signing_time: None,
            binary_signing_time: None,
        }
    }

    pub fn cert(&self) -> &CertBuilder {
        &self.cert
    }

    pub fn cert_mut(&mut self) -> &mut CertBuilder {
        &mut self.cert
    }

    pub fn signing_time(&mut self, time: Time) {
        self.signing_time = Some(time)
    }

    pub fn binary_signing_time(&mut self, time: Time) {
        self.binary_signing_time = Some(time)
    }
}

impl<C: encode::Values> SignedObjectBuilder<C> {
    pub fn encode<S: Signer>(
        self,
        signer: &S,
        cert_key: &S::KeyId,
        cert_alg: SignatureAlgorithm,
        digest_alg: DigestAlgorithm,
        obj_alg: SignatureAlgorithm,
    ) -> Result<impl encode::Values, SigningError<S::Error>> {
        // Produce signed attributes.
        let signed_attrs = self.encode_signed_attrs(digest_alg);

        // Sign signed attributes with a one-off key.
        let (signature, key_info) = signer.sign_one_off(
            obj_alg, &signed_attrs
        )?;
        let (obj_alg, signature) = signature.unwrap();

        // Complete the certificate.
        let cert = self.cert.encode(signer, cert_key, cert_alg, &key_info)?;

        Ok(encode::sequence((
            oid::SIGNED_DATA.encode(), // contentType
            encode::sequence_as(Tag::CTX_0, // content
                encode::sequence((
                    3u8.encode(), // version
                    digest_alg.encode_set(), // digestAlgorithms
                    encode::sequence(( // encapContentInfo
                        self.content_type.encode(),
                        encode::sequence_as(Tag::CTX_0, self.content),
                    )),
                    encode::sequence_as(Tag::CTX_0, // certificates
                        cert
                    ),
                    // crl -- omitted
                    encode::set( // signerInfo
                        encode::sequence(( // SignerInfo
                            3u8.encode(), // version
                            OctetString::encode_slice_as( // sid
                                key_info.key_identifier(),
                                Tag::CTX_0,
                            ),
                            digest_alg.encode(), // digestAlgorithm
                            signed_attrs, // signedAttrs
                            obj_alg.cms_encode(), // signatureAlgorithm
                            OctetString::encode_slice( // signature
                                signature
                            ),
                            // unsignedAttrs omitted
                        ))
                    )
                ))
            )
        )))
    }

    fn encode_signed_attrs(&self, digest_alg: DigestAlgorithm) -> Captured {
        let mut digest = digest_alg.start();
        self.content.write_encoded(Mode::Der, &mut digest).unwrap();
        let digest = digest.finish();
        Captured::from_values(Mode::Der, encode::sequence_as(Tag::CTX_0, (
            // Content Type
            encode::sequence((
                oid::CONTENT_TYPE.encode(),
                encode::set(
                    self.content_type.encode_ref(),
                )
            )),

            // Message Digest
            encode::sequence((
                oid::MESSAGE_DIGEST.encode(),
                encode::set(
                    OctetString::encode_slice(digest),
                )
            )),

            // Signing Time
            self.signing_time.map(|time| {
                encode::sequence((
                    oid::SIGNING_TIME.encode(),
                    encode::set(
                        time.encode(),
                    )
                ))
            }),

            // Binary Signing Time
            self.binary_signing_time.map(|time| {
                encode::sequence((
                    oid::AA_BINARY_SIGNING_TIME.encode(),
                    encode::set(
                        time.to_binary_time().encode()
                    )
                ))
            })
        )))
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
}

#[cfg(all(test, feature="softkeys"))]
mod signer_test {
    use std::str::FromStr;
    use bcder::encode::Values;
    use crate::cert::Validity;
    use crate::crypto::PublicKeyFormat;
    use crate::crypto::softsigner::OpenSslSigner;
    use crate::resources::{AsId, Prefix};
    use crate::uri;
    use super::*;
        
    #[test]
    fn encode_signed_object() {
        let mut signer = OpenSslSigner::new();
        let key = signer.create_key(PublicKeyFormat).unwrap();
        let pubkey = signer.get_key_info(&key).unwrap();
        let uri = uri::Rsync::from_str("rsync://example.com/m/p").unwrap();

        let mut cert = CertBuilder::new(
            12, pubkey.to_subject_name(), Validity::from_secs(86400), true
        );
        cert.rpki_manifest(uri.clone())
            .v4_blocks(|blocks| blocks.push(Prefix::new(0, 0)))
            .as_blocks(|blocks| blocks.push((AsId::MIN, AsId::MAX)));

        let builder = SignedObjectBuilder::new(
            oid::SIGNED_DATA, // yeah, I know. Whatever.
            b"1234".encode(),
            cert
        );
        let captured = builder.encode(
            &signer, &key, SignatureAlgorithm, DigestAlgorithm,
            SignatureAlgorithm
        ).unwrap().to_captured(Mode::Der);

        let _sigobj = SignedObject::decode(captured.as_slice(), true).unwrap();
    }
}


//============ Specification Documentation ===================================

/// Signed Objects Specification.
///
/// This is a documentation-only module. It summarizes the specification for
/// signed objects, how they are to be parsed and constructed.
///
/// Signed objects are CMS signed objects that have been severly limited in
/// the options of the various fields. They are specified in [RFC 6488] while
/// CMS is specified in [RFC 5652].
///
/// A signed object is a CMS object with a single signed data obhect in it.
///
/// A CMS object is:
///
/// ```txt
/// ContentInfo             ::= SEQUENCE {
///     contentType             ContentType,
///     content                 [0] EXPLICIT ANY DEFINED BY contentType }
/// ```
///
/// The _contentType_ must be `oid::SIGNED_DATA` and the _content_ a
/// _SignedData_ object (however, note the `[0] EXPLICIT` there) as follows:
///
/// ```txt
/// SignedData              ::= SEQUENCE {
///     version                 CMSVersion,
///     digestAlgorithms        DigestAlgorithmIdentifiers,
///     encapContentInfo        EncapsulatedContentInfo,
///     certificates            [0] IMPLICIT CertificateSet OPTIONAL,
///     crls                    [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///     signerInfos             SignerInfos }
///
/// EncapsulatedContentInfo ::= SEQUENCE {
///     eContentType            ContentType,
///     eContent                [0] EXPLICIT OCTET STRING OPTIONAL }
///
/// CertificateSet          ::= SET OF CertificateChoices
///
/// CertificateChoices      ::= CHOICE {
///     certificate             Certificate,
///     extendedCertificate     [0] IMPLICIT ExtendedCertificate,   -- Obsolete
///     v1AttrCert              [1] IMPLICIT AttributeCertificateV1,-- Obsolete
///     v2AttrCert              [2] IMPLICIT AttributeCertificateV2,
///     other                   [3] IMPLICIT OtherCertificateFormat }
/// ```
///
/// Limitations imposed by [RFC 6488] are as follows:
///
/// * The _version_ must be 3.
/// * The _digestAlgorithms_ set must be exactly one algorithm chosen from
///   those defined in [RFC 7935]. The [`DigestAlgorithm`] type implements
///   both the _DigestAlgorithmIdentifier_ and _DigestAlgorithmIndentifiers_
///   definitions (the latter via `take_set_from` and `encode_set`).
/// * The _eContentType_ field of _encapContentInfo_ defines the type of an
///   object. Check the specific signed objects for their matching object ID.
/// * The _eContent_ field of _encapContentInfo_ must be present and contains
///   actual content of the signed object.
/// * There must be exactly one certificate in the `certificates` set. It must
///   be of the _certificate_ choice (that’s not exactly in RFC 6488, but it
///   is the only logical choice for ‘the RPKI end-entity (EE) certificate
///   needed to validate this signed object’), which in practice means it is
///   just one [`Cert`].
/// * The _crls_ field must be omitted.
///
/// The _SignerInfos_ structure:
///
/// ```txt
///
/// SignerInfos             ::= SET OF SignerInfo
///
/// SignerInfo              ::= SEQUENCE {
///     version                 CMSVersion,
///     sid                     SignerIdentifier,
///     digestAlgorithm         DigestAlgorithmIdentifier,
///     signedAttrs             [0] IMPLICIT SignedAttributes OPTIONAL,
///     signatureAlgorithm      SignatureAlgorithmIdentifier,
///     signature               SignatureValue,
///     unsignedAttrs           [1] IMPLICIT UnsignedAttributes OPTIONAL }
///
/// SignerIdentifier        ::= CHOICE {
///     issuerAndSerialNumber   IssuerAndSerialNumber,
///     subjectKeyIdentifier    [0] EXPLICIT SubjectKeyIdentifier }
///
/// SubjectKeyIdentifier    ::= OCTET STRING
/// 
/// SignatureValue          ::= OCTET STRING
/// ```
///
/// Limitations are as follows:
///
/// * There must be exactly one _SignerInfo_ present.
/// * The _version_ must be 3.
/// * The _sid_ must be identical to the value of the Subject Key Identifier
///   extension of the included certificate. I.e., it must be the second
///   choice.
/// * The _digestAlgorithm_ must be the same as the only value in the outer
///   _digestAlgorthm_ field.
/// * The _signedAttrs_ field must be present. See below.
/// * For the content of the _signature_ field, see below.
/// * The _unsignedAttrs_ field must be omitted.
///
/// Finally, _SignedAttributes_ is a sequence of attributes keyed by an OID.
/// RPKI has two mandatory and two optional attributes. Definition for all
/// of these is the following:
///
/// ```text
/// SignedAttributes        ::= SET SIZE (1..MAX) OF Attribute
///
/// Attribute               ::= SEQUENCE {
///     attrType                OBJECT IDENTIFIER,
///     attrValues              SET OF AttributeValue }
///
/// ContentType             ::= OBJECT IDENTIFIER
///
/// MessageDigest           ::= OCTET STRING
///
/// SigningTime             ::= Time
///
/// Time                    ::= CHOICE {
///     utcTime                 UTCTime,
///     generalizedTime         GeneralizedTime }
///
/// BinarySigningTime       ::= BinaryTime
///
/// BinaryTime              ::= INTEGER (0..MAX)
/// ```
///
/// The two mandatory attributes are _ContentType_ and _MessageDigest_. The
/// content type attribute must be the same as the _eContentType_ field of
/// the _encapContentInfo_. The message digest attribute contains the digest
/// value of the (actual) content.
///
/// The _SigningTime_ and _BinarySigningTime_ attributes are optional. Their
/// presence is not considered when validating a signed object.
///
/// No other attribute may be present.
///
/// For the object identifiers of the attributes, see the [`oid`] module.
///
/// The _signature_ field of the signed object contains a signature over the
/// DER encoding of the _signedAttrs_ field.
///
/// [RFC 5652]: https://tools.ietf.org/html/rfc5652
/// [RFC 6488]: https://tools.ietf.org/html/rfc6488
/// [RFC 7935]: https://tools.ietf.org/html/rfc7935
/// [`Cert`]: ../../cert/struct.Cert.html
/// [`DigestAlgorithm`]: ../../crypto/keys/struct.DigestAlgorithm.html
/// [`oid`]: ../../oid/index.html
pub mod spec { }

