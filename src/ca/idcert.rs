//! Support basic identity certificates as used in the remote access
//! protocol CMS messages and XML exchanges.

//! Support for building RPKI Certificates and Objects

use bcder::{decode, encode};
use bcder::{Captured, Mode, OctetString, Oid, Tag};
use bcder::decode::Error as _;
use bcder::encode::PrimitiveContent;
use bytes::Bytes;
use log::{debug, error};
use std::ops;

use crate::oid;
use crate::crypto::{
    KeyIdentifier, PublicKey, RpkiSignatureAlgorithm, SignatureAlgorithm,
    SignatureVerificationError, Signer, SigningError,
};
use crate::repository::cert::TbsCert;
use crate::repository::x509::{
    encode_extension, Name, Serial, SignedData, Time, ValidationError,
    Validity,
};

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

    /// The actual data of the certificate.
    tbs: TbsIdCert,
}

/// # Creation
///
impl IdCert {
    /// Make a new TA ID certificate
    pub fn new_ta<S: Signer>(
        validity: Validity,
        issuing_key_id: &S::KeyId,
        signer: &S,
    ) -> Result<Self, SigningError<S::Error>> {
        let pub_key = signer.get_key_info(issuing_key_id)?;

        let serial_number = Serial::from(1_u64);

        let issuing_key = &pub_key;
        let subject_key = &pub_key;

        TbsIdCert::new(serial_number, validity, issuing_key, subject_key)
            .into_cert(signer, issuing_key_id)
    }

    /// Make a new EE certificate under an issuing TA certificate
    /// used for signing CMS. Expects that the public key was used
    /// for a one-off signing of a CMS message.
    pub fn new_ee<S: Signer>(
        ee_key: &PublicKey,
        validity: Validity,
        issuing_key_id: &S::KeyId,
        signer: &S,
    ) -> Result<Self, SigningError<S::Error>> {
        let serial_number = Serial::random(signer)?;
        let issuing_key = signer.get_key_info(issuing_key_id)?;

        TbsIdCert::new(serial_number, validity, &issuing_key, ee_key)
            .into_cert(signer, issuing_key_id)
    }
}

/// # Decoding and Encoding
///
impl IdCert {
    /// Decodes a source as a certificate.
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Error> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded certificate from the beginning of a value.
    pub fn take_from<S: decode::Source>(cons: &mut decode::Constructed<S>) -> Result<Self, S::Error> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the content of a Certificate sequence.
    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, S::Error> {
        let signed_data = SignedData::from_constructed(cons)?;
        let tbs = signed_data
            .data()
            .clone()
            .decode(TbsIdCert::from_constructed)?;

        Ok(Self { signed_data, tbs })
    }

    /// Returns a value encoder for a reference to the certificate.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        self.signed_data.encode_ref()
    }

    /// Returns a captured encoding of the certificate.
    pub fn to_captured(&self) -> Captured {
        Captured::from_values(Mode::Der, self.encode_ref())
    }

    /// Returns DER encoded bytes for this certificate.
    pub fn to_bytes(&self) -> Bytes {
        self.to_captured().into_bytes()
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

        // RFC 8183 does not use clear normative language but it refers to the
        // "BPKI TA" certificates as 'self-signed' in many cases. As it turns
        // out the APNIC parent BPKI TA is not self-signed. This should not
        // really matter as it's essentially just a certificate that wraps
        // the public key that will be used to sign CMS messages signed under
        // it.
        //
        // So, in short.. let's just do some debug logging in case we think
        // this is not self-signed, but validate if it does appear to be
        // self-signed.
        if let Some(aki) = self.authority_key_id {
            if aki != self.subject_key_id {
                debug!("ID TA certificate not self-signed, still accepting");
            } else if let Err(e) = self
                .signed_data
                .verify_signature(&self.subject_public_key_info)
            {
                error!("ID TA certificate is *invalidly* self-signed");
                return Err(e.into());
            }
        }

        // // Normally the AKI should be left out - if it is set though, then
        // // we should insist that it matches the SKI.

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
        if let Some(basic_ca) = self.basic_ca {
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
        if self.subject_key_id != self.subject_public_key_info.key_identifier() {
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
        if let Some(aki) = self.authority_key_id {
            if aki != issuer.subject_key_id {
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
        if let Some(ca) = self.basic_ca {
            if ca {
                return Ok(());
            }
        }

        Err(ValidationError)
    }

    /// Validates the certificate’s signature.
    fn validate_signature(
        &self, issuer: &IdCert,
    ) -> Result<(), SignatureVerificationError> {
        self.signed_data.verify_signature(
            issuer.subject_public_key_info()
        )
    }
}

//--- Deref, AsRef

impl ops::Deref for IdCert {
    type Target = TbsIdCert;

    fn deref(&self) -> &Self::Target {
        &self.tbs
    }
}

impl AsRef<IdCert> for IdCert {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<TbsIdCert> for IdCert {
    fn as_ref(&self) -> &TbsIdCert {
        &self.tbs
    }
}

//--- PartialEq and Eq

impl PartialEq for IdCert {
    fn eq(&self, other: &Self) -> bool {
        // We only compare signed_data, because the TbsIdCert is
        // just a parsed representation of the same data.
        self.signed_data == other.signed_data
    }
}

impl Eq for IdCert { }


//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for IdCert {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_captured().into_bytes();
        let str = base64::encode(&bytes);
        str.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for IdCert {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de;

        let some = String::deserialize(deserializer)?;
        let dec = base64::decode(&some).map_err(de::Error::custom)?;
        let b = Bytes::from(dec);
        IdCert::decode(b).map_err(de::Error::custom)
    }
}


//------------ TbsIdCert -------------------------------------------------------

/// The data of an identity certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TbsIdCert {
    /// The serial number.
    serial_number: Serial,

    /// The name of the issuer.
    ///
    /// It isn’t really relevant even in the RPKI remote protocols.
    #[allow(dead_code)]
    issuer: Name,

    /// The validity of the certificate.
    validity: Validity,

    /// The name of the subject of this certificate.
    ///
    /// It isn’t really relevant even in the RPKI remote protocols.
    #[allow(dead_code)]
    subject: Name,

    /// Information about the public key of this certificate.
    subject_public_key_info: PublicKey,

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

/// # Data Access
///
impl TbsIdCert {
    /// Returns a reference to the certificate’s public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.subject_public_key_info
    }

    /// Returns a reference to the entire public key information structure.
    pub fn subject_public_key_info(&self) -> &PublicKey {
        &self.subject_public_key_info
    }

    /// Returns the public key's key identifier
    pub fn subject_key_identifier(&self) -> KeyIdentifier {
        self.subject_key_id
    }

    /// Returns a reference to the certificate’s serial number.
    pub fn serial_number(&self) -> Serial {
        self.serial_number
    }

    pub fn subject_key_id(&self) -> KeyIdentifier {
        self.subject_key_id
    }

    pub fn authority_key_id(&self) -> Option<KeyIdentifier> {
        self.authority_key_id
    }

    pub fn subject(&self) -> &Name {
        &self.subject
    }
}

/// # Decoding and Encoding
///
impl TbsIdCert {
    /// Parses the content of an ID Certificate sequence.
    ///
    /// The General structure is documented in section 4.1 or RFC5280
    ///
    ///    TBSCertificate  ::=  SEQUENCE  {
    ///        version         [0]  EXPLICIT Version DEFAULT v1,
    ///        serialNumber         CertificateSerialNumber,
    ///        signature            AlgorithmIdentifier,
    ///        issuer               Name,
    ///        validity             Validity,
    ///        subject              Name,
    ///        subjectPublicKeyInfo SubjectPublicKeyInfo,
    ///        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    ///                             -- If present, version MUST be v2 or v3
    ///        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    ///                             -- If present, version MUST be v2 or v3
    ///        extensions      [3]  EXPLICIT Extensions OPTIONAL
    ///                             -- If present, version MUST be v3
    ///        }
    ///
    ///  In the RPKI we always use Version 3 Certificates with certain
    ///  extensions (SubjectKeyIdentifier in particular). issuerUniqueID and
    ///  subjectUniqueID are not used. The signature is always
    ///  Sha256WithRsaEncryption
    fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, S::Error> {
        cons.take_sequence(|cons| {
            // version [0] EXPLICIT Version DEFAULT v1.
            //  -- we need extensions so apparently, we want v3 which,
            //     confusingly, is 2.
            cons.take_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(2))?;

            let serial_number = Serial::take_from(cons)?;
            let _sig = RpkiSignatureAlgorithm::x509_take_from(cons)?;
            let issuer = Name::take_from(cons)?;
            let validity = Validity::take_from(cons)?;
            let subject = Name::take_from(cons)?;
            let subject_public_key_info = PublicKey::take_from(cons)?;

            // issuerUniqueID and subjectUniqueID must not be present in
            // resource certificates. So extension is next.

            let mut basic_ca = None;
            let mut subject_key_id = None;
            let mut authority_key_id = None;

            cons.take_constructed_if(Tag::CTX_3, |c| {
                c.take_sequence(|cons| {
                    while let Some(()) = cons.take_opt_sequence(|cons| {
                        let id = Oid::take_from(cons)?;
                        let _critical = cons.take_opt_bool()?.unwrap_or(false);
                        let value = OctetString::take_from(cons)?;
                        Mode::Der.decode(value.to_source(), |content| {
                            if id == oid::CE_BASIC_CONSTRAINTS {
                                TbsCert::take_basic_constraints(content, &mut basic_ca)
                            } else if id == oid::CE_SUBJECT_KEY_IDENTIFIER {
                                TbsCert::take_subject_key_identifier(content, &mut subject_key_id)
                            } else if id == oid::CE_AUTHORITY_KEY_IDENTIFIER {
                                TbsCert::take_authority_key_identifier(
                                    content,
                                    &mut authority_key_id,
                                )
                            } else {
                                // Id Certificates are poorly defined and may
                                // contain critical extensions we do not actually
                                // understand or need.
                                //
                                // E.g. APNIC includes 'key usage', and rpkid
                                // does not. Neither does Krill at this time. We
                                // can ignore this particular one - because the
                                // allowed key usage is unambiguous in the context
                                // of the RPKI remote protocols.
                                Ok(())
                            }
                        })?;
                        Ok(())
                    })? {}
                    Ok(())
                })
            })?;

            Ok(TbsIdCert {
                serial_number,
                issuer,
                validity,
                subject,
                subject_public_key_info,
                basic_ca,
                subject_key_id: subject_key_id.ok_or_else(|| {
                    S::Error::malformed(
                        "missing Subject Key Identifier extension"
                    )
                })?,
                authority_key_id,
            })
        })
    }

    /// Returns an encoder for the value.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            encode::sequence_as(Tag::CTX_0, 2.encode()), // version
            self.serial_number.encode(),
            RpkiSignatureAlgorithm::default().x509_encode(),
            self.issuer.encode_ref(),
            self.validity.encode(),
            self.subject.encode_ref(),
            self.subject_public_key_info.encode_ref(),
            // no issuerUniqueID
            // no subjectUniqueID
            // extensions
            encode::sequence_as(
                Tag::CTX_3,
                encode::sequence((
                    // Basic Constraints
                    self.basic_ca.map(|ca| {
                        encode_extension(
                            &oid::CE_BASIC_CONSTRAINTS,
                            true,
                            encode::sequence(
                                if ca { Some(ca.encode()) } else { None }
                            ),
                        )
                    }),
                    // Subject Key Identifier
                    encode_extension(
                        &oid::CE_SUBJECT_KEY_IDENTIFIER,
                        false,
                        self.subject_key_id.encode_ref(),
                    ),
                    // Authority Key Identifier
                    self.authority_key_id.as_ref().map(|id| {
                        encode_extension(
                            &oid::CE_AUTHORITY_KEY_IDENTIFIER,
                            false,
                            encode::sequence(id.encode_ref_as(Tag::CTX_0)),
                        )
                    }),
                )),
            ),
        ))
    }
}

/// # Creation and Conversion
///
impl TbsIdCert {
    /// Creates an TbsIdCert to be signed with the Signer trait.
    ///
    /// Note that this function is private - it is used by the specific
    /// public functions for creating a TA ID cert, or CMS EE ID cert.
    fn new(
        serial_number: Serial,
        validity: Validity,
        issuing_key: &PublicKey,
        subject_key: &PublicKey,
    ) -> TbsIdCert {
        let issuer = Name::from_pub_key(issuing_key);
        let subject = Name::from_pub_key(subject_key);

        let basic_ca = if issuing_key == subject_key {
            Some(true)
        } else {
            None
        };

        let subject_key_id = subject_key.key_identifier();

        let authority_key_id = if issuing_key == subject_key {
            None
        } else {
            Some(issuing_key.key_identifier())
        };

        TbsIdCert {
            serial_number,
            issuer,
            validity,
            subject,
            subject_public_key_info: subject_key.clone(),
            basic_ca,
            subject_key_id,
            authority_key_id,
        }
    }

    /// Converts the value into a signed ID certificate.
    fn into_cert<S: Signer>(
        self,
        signer: &S,
        key: &S::KeyId,
    ) -> Result<IdCert, SigningError<S::Error>> {
        let data = Captured::from_values(Mode::Der, self.encode_ref());
        let signature = signer.sign(
            key, RpkiSignatureAlgorithm::default(), &data
        )?;
        Ok(IdCert {
            signed_data: SignedData::new(data, signature),
            tbs: self,
        })
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn parse_id_publisher_ta_cert() {
        let data = include_bytes!("../../test-data/ca/id_ta.cer");
        let idcert = IdCert::decode(Bytes::from_static(data)).unwrap();
        let idcert_moment = Time::utc(2012, 1, 1, 0, 0, 0);
        idcert.validate_ta_at(idcert_moment).unwrap();
    }
}

#[cfg(all(test, feature = "softkeys"))]
mod signer_test {
    use crate::crypto::softsigner::OpenSslSigner;
    use crate::crypto::PublicKeyFormat;

    use super::*;

    #[test]
    fn build_id_ta_cert() {
        let signer = OpenSslSigner::new();
        let ta_key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
        let ta_cert = IdCert::new_ta(Validity::from_secs(60), &ta_key, &signer).unwrap();
        ta_cert.validate_ta().unwrap();
    }
}
