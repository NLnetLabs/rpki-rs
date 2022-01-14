//! Support basic identity certificates as used in the remote access
//! protocol CMS messages and XML exchanges.

//! Support for building RPKI Certificates and Objects
use bytes::Bytes;
use log::debug;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use bcder::{
    encode::{PrimitiveContent, Values},
    {decode, encode, Mode, OctetString, Oid, Tag, Unsigned},
};

use crate::repository::{
    crypto::{KeyIdentifier, PublicKey, SignatureAlgorithm},
    oid,
    x509::{encode_extension, update_once, Name, SignedData, Time, ValidationError, Validity},
};


/// Validity Time for the self-signed (TA) Identity certificates used to sign
/// the EE certificates used in CMS exchanges. Note that the EE certificates
/// will of course use much shorter validity times.
pub const ID_CERTIFICATE_VALIDITY_YEARS: i32 = 15;

//------------ IdTbsCertificate ------------------------------------------------

/// This type represents the signed content part of an RPKI Certificate.
#[allow(dead_code)]
struct IdTbsCertificate {
    // The General structure is documented in section 4.1 or RFC5280
    //
    //    TBSCertificate  ::=  SEQUENCE  {
    //        version         [0]  EXPLICIT Version DEFAULT v1,
    //        serialNumber         CertificateSerialNumber,
    //        signature            AlgorithmIdentifier,
    //        issuer               Name,
    //        validity             Validity,
    //        subject              Name,
    //        subjectPublicKeyInfo SubjectPublicKeyInfo,
    //        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    //                             -- If present, version MUST be v2 or v3
    //        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    //                             -- If present, version MUST be v2 or v3
    //        extensions      [3]  EXPLICIT Extensions OPTIONAL
    //                             -- If present, version MUST be v3
    //        }
    //
    //  In the RPKI we always use Version 3 Certificates with certain
    //  extensions (SubjectKeyIdentifier in particular). issuerUniqueID and
    //  subjectUniqueID are not used.
    //

    // version is always 3
    serial_number: u32,
    // signature is always Sha256WithRsaEncryption
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: PublicKey,
    // issuerUniqueID is not used
    // subjectUniqueID is not used
    extensions: IdExtensions,
}


//------------ IdCert --------------------------------------------------------

/// An Identity Certificate.
///
/// Identity Certificates are used in the provisioning and publication
/// protocol. Initially the parent and child CAs and/or the publishing CA
/// and publication server exchange self-signed Identity Certificates, wrapped
/// in XML messages defined in the 'rfc8181' module.
///
/// The private keys corresponding to the subject public keys in these
/// certificates are then used to sign identity EE certificates used to sign
/// CMS messages in support of the provisioning and publication protocols.
///
/// NOTE: For the moment only V3 certificates are supported, because we insist
/// that a TA certificate is self-signed and has the CA bit set, and that an
/// EE certificate does not have this bit set, but does have an AKI that
/// matches the issuer's SKI. Maybe we should take this out... and just care
/// that things are validly signed, or only check AKI/SKI if it's version 3,
/// but skip this for lower versions.
#[derive(Clone, Debug)]
pub struct IdCert {
    /// The outer structure of the certificate.
    signed_data: SignedData,

    /// The serial number.
    serial_number: Unsigned,

    /// The algorithm used for signing the certificate.
    #[allow(dead_code)]
    signature: SignatureAlgorithm,
    
    /// The name of the issuer.
    ///
    /// It isn’t really relevant in RPKI.
    #[allow(dead_code)]
    issuer: Name,
    
    /// The validity of the certificate.
    validity: Validity,
    
    /// The name of the subject of this certificate.
    ///
    /// This isn’t really relevant in RPKI.
    #[allow(dead_code)]
    subject: Name,

    /// Information about the public key of this certificate.
    subject_public_key_info: PublicKey,

    /// The certificate extensions.
    extensions: IdExtensions,
}

/// # Data Access
///
impl IdCert {
    /// Returns a reference to the certificate’s public key.
    pub fn public_key(&self) -> &[u8] {
        self.subject_public_key_info.bits()
    }

    /// Returns the hex encoded SKI
    pub fn ski_hex(&self) -> String {
        self.subject_public_key_info.key_identifier().to_string()
    }

    /// Returns a reference to the entire public key information structure.
    pub fn subject_public_key_info(&self) -> &PublicKey {
        &self.subject_public_key_info
    }

    /// Returns a reference to the certificate’s serial number.
    pub fn serial_number(&self) -> &Unsigned {
        &self.serial_number
    }
}

/// # Decoding and Encoding
///
impl IdCert {
    /// Decodes a source as a certificate.
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded certificate from the beginning of a value.
    pub fn take_from<S: decode::Source>(cons: &mut decode::Constructed<S>) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the content of a Certificate sequence.
    pub fn from_constructed<S: decode::Source>(cons: &mut decode::Constructed<S>) -> Result<Self, S::Err> {
        let signed_data = SignedData::from_constructed(cons)?;

        signed_data
            .data()
            .clone()
            .decode(|cons| {
                cons.take_sequence(|cons| {
                    // version [0] EXPLICIT Version DEFAULT v1.
                    //  -- we need extensions so apparently, we want v3 which,
                    //     confusingly, is 2.
                    cons.take_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(2))?;

                    Ok(IdCert {
                        signed_data,
                        serial_number: Unsigned::take_from(cons)?,
                        signature: SignatureAlgorithm::x509_take_from(cons)?,
                        issuer: Name::take_from(cons)?,
                        validity: Validity::take_from(cons)?,
                        subject: Name::take_from(cons)?,
                        subject_public_key_info: PublicKey::take_from(cons)?,
                        extensions: cons.take_constructed_if(Tag::CTX_3, IdExtensions::take_from)?,
                    })
                })
            })
            .map_err(Into::into)
    }

    #[allow(clippy::needless_lifetimes)]
    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        self.signed_data.encode_ref()
    }

    pub fn to_bytes(&self) -> Bytes {
        self.encode().to_captured(Mode::Der).into_bytes()
    }
}

/// # Validation
///
impl IdCert {
    /// Validates the certificate as a trust anchor.
    ///
    /// This validates that the certificate “is a current, self-signed RPKI
    /// CA certificate that conforms to the profile as specified in
    /// RFC6487” (RFC7730, section 3, step 2).
    pub fn validate_ta(&self) -> Result<(), ValidationError> {
        self.validate_ta_at(Time::now())
    }

    pub fn validate_ta_at(&self, now: Time) -> Result<(), ValidationError> {
        self.validate_basics(now)?;
        self.validate_ca_basics()?;

        // RFC says that the ID certificate ought to be (no normative language) self-signed.. just log if it isn't
        if let Some(aki) = self.extensions.authority_key_id() {
            if aki != self.extensions.subject_key_id() {
                debug!("ID certificate is not self-signed.")
            }
        }

        // RFC says that the ID certificate ought to be (no normative language) self-signed.. just log if it isn't
        if let Err(_e) = self.signed_data.verify_signature(&self.subject_public_key_info) {
            debug!("ID certificate is not self-signed.")
        }

        Ok(())
    }

    /// Validates the certificate as an EE certificate.
    ///
    /// For validation to succeed, the certificate needs to have been signed
    /// by the provided `issuer` certificate.
    ///
    /// Note that this does _not_ check the CRL.
    pub fn validate_ee(&self, issuer: &IdCert) -> Result<(), ValidationError> {
        self.validate_ee_at(issuer, Time::now())
    }

    pub fn validate_ee_at(&self, issuer: &IdCert, now: Time) -> Result<(), ValidationError> {
        self.validate_basics(now)?;
        self.validate_issued(issuer)?;

        // Basic Constraints: Must not be a CA cert.
        if let Some(basic_ca) = self.extensions.basic_ca {
            if basic_ca {
                return Err(ValidationError);
            }
        }

        // Verify that this is signed by the issuer
        self.validate_signature(issuer)?;
        Ok(())
    }

    //--- Validation Components

    /// Validates basic compliance with RFC8183 and RFC6492
    ///
    /// Note the the standards are pretty permissive in this context.
    fn validate_basics(&self, now: Time) -> Result<(), ValidationError> {
        // Validity. Check according to RFC 5280.
        self.validity.validate_at(now)?;

        // Subject Key Identifier must match the subjectPublicKey.
        if *self.extensions.subject_key_id() != self.subject_public_key_info().key_identifier() {
            return Err(ValidationError);
        }

        Ok(())
    }

    /// Validates that the certificate is a correctly issued certificate.
    ///
    /// Note this check is used to check that an EE certificate in an RFC8183,
    /// or RFC6492 message is validly signed by the TA certificate that was
    /// exchanged.
    ///
    /// This check assumes for now that we are always dealing with V3
    /// certificates and AKI and SKI have to match.
    fn validate_issued(&self, issuer: &IdCert) -> Result<(), ValidationError> {
        // Authority Key Identifier. Must be present and match the
        // subject key ID of `issuer`.
        if let Some(aki) = self.extensions.authority_key_id() {
            if aki != issuer.extensions.subject_key_id() {
                return Err(ValidationError);
            }
        } else {
            return Err(ValidationError);
        }

        Ok(())
    }

    /// Validates that the certificate is a valid CA certificate.
    ///
    /// Checks the parts that are common in normal and trust anchor CA
    /// certificates.
    fn validate_ca_basics(&self) -> Result<(), ValidationError> {
        // 4.8.1. Basic Constraints: For a CA it must be present (RFC6487)
        // und the “cA” flag must be set (RFC5280).
        if let Some(ca) = self.extensions.basic_ca {
            if ca {
                return Ok(());
            }
        }

        Err(ValidationError)
    }

    /// Validates the certificate’s signature.
    fn validate_signature(&self, issuer: &IdCert) -> Result<(), ValidationError> {
        self.signed_data.verify_signature(issuer.subject_public_key_info())
    }
}

//--- AsRef

impl AsRef<IdCert> for IdCert {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Serialize for IdCert {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_bytes();
        let str = base64::encode(&bytes);
        str.serialize(serializer)
    }
}

impl PartialEq for IdCert {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().eq(&other.to_bytes())
    }
}

impl Eq for IdCert {}

impl<'de> Deserialize<'de> for IdCert {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de;

        let some = String::deserialize(deserializer)?;
        let dec = base64::decode(&some).map_err(de::Error::custom)?;
        let b = Bytes::from(dec);
        IdCert::decode(b).map_err(de::Error::custom)
    }
}

//------------ IdExtensions --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdExtensions {
    /// Basic Constraints.
    ///
    /// The field indicates whether the extension is present and, if so,
    /// whether the "cA" boolean is set. See 4.8.1. of RFC 6487.
    basic_ca: Option<bool>,

    /// Subject Key Identifier.
    subject_key_id: KeyIdentifier,

    /// Authority Key Identifier
    authority_key_id: Option<KeyIdentifier>,
}

/// # Decoding
///
impl IdExtensions {
    pub fn take_from<S: decode::Source>(cons: &mut decode::Constructed<S>) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            let mut basic_ca = None;
            let mut subject_key_id = None;
            let mut authority_key_id = None;
            while let Some(()) = cons.take_opt_sequence(|cons| {
                let id = Oid::take_from(cons)?;
                let _critical = cons.take_opt_bool()?.unwrap_or(false);
                let value = OctetString::take_from(cons)?;
                Mode::Der.decode(value.to_source(), |content| {
                    if id == oid::CE_BASIC_CONSTRAINTS {
                        Self::take_basic_constraints(content, &mut basic_ca)
                    } else if id == oid::CE_SUBJECT_KEY_IDENTIFIER {
                        Self::take_subject_key_identifier(content, &mut subject_key_id)
                    } else if id == oid::CE_AUTHORITY_KEY_IDENTIFIER {
                        Self::take_authority_key_identifier(content, &mut authority_key_id)
                    } else {
                        // Id Certificates are poorly defined and may
                        // contain critical extensions we do not actually
                        // understand or need.
                        Ok(())
                    }
                })?;
                Ok(())
            })? {}
            Ok(IdExtensions {
                basic_ca,
                subject_key_id: subject_key_id.ok_or(decode::Malformed)?,
                authority_key_id,
            })
        })
    }

    /// Parses the Basic Constraints extension.
    ///
    /// ```text
    /// BasicConstraints        ::= SEQUENCE {
    ///     cA                      BOOLEAN DEFAULT FALSE,
    ///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
    /// }
    /// ```
    ///
    /// For resource certificates, the extension must be critical. It must be
    /// present for CA certificates and must not be present for EE
    /// certificates. RFC 6487 says that the issued decides whether the cA
    /// boolean is to be set or not, but for all CA certificates it must be
    /// set (required indirectly by requiring the keyCertSign bit set in
    /// the key usage extension) so really it must always be true if the
    /// extension is present.
    ///
    /// The pathLenConstraint field must not be present.
    pub(crate) fn take_basic_constraints<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        basic_ca: &mut Option<bool>,
    ) -> Result<(), S::Err> {
        update_once(basic_ca, || {
            cons.take_sequence(|cons| cons.take_opt_bool())
                .map(|ca| ca.unwrap_or(false))
        })
    }

    /// Parses the Subject Key Identifier extension.
    ///
    /// ```text
    /// SubjectKeyIdentifier ::= KeyIdentifier
    /// ```
    ///
    /// The extension must be present and contain the 160 bit SHA-1 hash of
    /// the value of the DER-encoded bit string of the subject public key.
    ///
    /// Conforming CAs MUST mark this extension as non-critical.
    fn take_subject_key_identifier<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        subject_key_id: &mut Option<KeyIdentifier>,
    ) -> Result<(), S::Err> {
        update_once(subject_key_id, || KeyIdentifier::take_from(cons))
    }

    /// Parses the Authority Key Identifer extension.
    ///
    /// ```text
    /// AuthorityKeyIdentifier ::= SEQUENCE {
    ///   keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    ///   authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    ///   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
    /// ```
    ///
    /// Must be present except in self-signed CA certificates where it is
    /// optional. The keyIdentifier field must be present, the other must not
    /// be.
    fn take_authority_key_identifier<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        authority_key_id: &mut Option<KeyIdentifier>,
    ) -> Result<(), S::Err> {
        update_once(authority_key_id, || {
            cons.take_sequence(|cons| cons.take_value_if(Tag::CTX_0, KeyIdentifier::from_content))
        })
    }
}

/// # Encoding
///
// We have to do this the hard way because some extensions are optional.
// Therefore we need logic to determine which ones to encode.
impl IdExtensions {
    #[allow(clippy::needless_lifetimes)]
    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence_as(
            Tag::CTX_3,
            encode::sequence((
                // Basic Constraints
                self.basic_ca.map(|ca| {
                    encode_extension(
                        &oid::CE_BASIC_CONSTRAINTS,
                        true,
                        encode::sequence(if ca { Some(ca.encode()) } else { None }),
                    )
                }),
                // Subject Key Identifier
                encode_extension(&oid::CE_SUBJECT_KEY_IDENTIFIER, false, self.subject_key_id.encode_ref()),
                // Authority Key Identifier
                self.authority_key_id.as_ref().map(|id| {
                    encode_extension(
                        &oid::CE_AUTHORITY_KEY_IDENTIFIER,
                        false,
                        encode::sequence(id.encode_ref_as(Tag::CTX_0)),
                    )
                }),
            )),
        )
    }
}

/// # Creating
///
impl IdExtensions {
    /// Creates extensions to be used on a self-signed TA IdCert
    pub fn for_id_ta_cert(key: &PublicKey) -> Self {
        let ki = key.key_identifier();
        IdExtensions {
            basic_ca: Some(true),
            subject_key_id: ki,
            authority_key_id: Some(ki),
        }
    }

    /// Creates extensions to be used on an EE IdCert in a protocol CMS
    pub fn for_id_ee_cert(subject_key: &PublicKey, issuing_key: &PublicKey) -> Self {
        IdExtensions {
            basic_ca: None,
            subject_key_id: subject_key.key_identifier(),
            authority_key_id: Some(issuing_key.key_identifier()),
        }
    }
}

/// # Data Access
///
impl IdExtensions {
    pub fn subject_key_id(&self) -> &KeyIdentifier {
        &self.subject_key_id
    }

    pub fn authority_key_id(&self) -> Option<&KeyIdentifier> {
        self.authority_key_id.as_ref()
    }
}

impl From<&PublicKey> for IdExtensions {
    fn from(pub_key: &PublicKey) -> Self {
        let basic_ca = Some(true);
        let subject_key_id = pub_key.key_identifier();
        let authority_key_id = Some(subject_key_id);

        IdExtensions {
            basic_ca,
            subject_key_id,
            authority_key_id,
        }
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn parse_id_publisher_ta_cert() {
        let data = include_bytes!("../../test-data/remote/id_publisher_ta.cer");
        let idcert = IdCert::decode(Bytes::from_static(data)).unwrap();
        let idcert_moment = Time::utc(2012, 1, 1, 0, 0, 0);
        idcert.validate_ta_at(idcert_moment).unwrap();
    }
}
