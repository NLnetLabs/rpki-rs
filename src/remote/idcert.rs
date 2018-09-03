//! Identity Certificates.
//!

use std::io;
use ber::{Captured, Mode, OctetString, Oid, Tag, Unsigned};
use ber::{decode, encode};
use ber::encode::{PrimitiveContent, Values};
use bytes::Bytes;
use cert::{SubjectPublicKeyInfo, Validity};
use cert::ext::{BasicCa, Extensions, SubjectKeyIdentifier};
use cert::ext::oid;
use chrono::Duration;
use signing::SignatureAlgorithm;
use x509::{Name, SignedData, ValidationError};


//------------ IdCert --------------------------------------------------------

/// An Identity Certificate.
///
/// Identity Certificates are used in the provisioning and publication
/// protocol. Initially the parent and child CAs and/or the publishing CA
/// and publication server exchange self-signed Identity Certificates, wrapped
/// in XML messages defined in the 'exchange.rs' module.
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
    signature: SignatureAlgorithm,

    /// The name of the issuer.
    ///
    /// It isn’t really relevant in RPKI.
    issuer: Name,

    /// The validity of the certificate.
    validity: Validity,

    /// The name of the subject of this certificate.
    ///
    /// This isn’t really relevant in RPKI.
    subject: Name,

    /// Information about the public key of this certificate.
    subject_public_key_info: SubjectPublicKeyInfo,

    /// The certificate extensions.
    extensions: IdExtensions,
}

/// # Data Access
///
impl IdCert {
    /// Returns a reference to the certificate’s public key.
    pub fn public_key(&self) -> &[u8] {
        self.subject_public_key_info
            .subject_public_key().octet_slice().unwrap()
    }

    /// Returns a reference to the subject key identifier.
    pub fn subject_key_identifier(&self) -> &OctetString {
        &self.extensions.subject_key_id.subject_key_id()
    }

    /// Returns a reference to the entire public key information structure.
    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
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
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::take_content_from)
    }

    /// Parses the content of a Certificate sequence.
    pub fn take_content_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::take_content_from(cons)?;

        signed_data.data().clone().decode(|cons| {
            cons.take_sequence(|cons| {
                // version [0] EXPLICIT Version DEFAULT v1.
                //  -- we need extensions so apparently, we want v3 which,
                //     confusingly, is 2.
                cons.take_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(2))?;

                Ok(IdCert {
                    signed_data,
                    serial_number: Unsigned::take_from(cons)?,
                    signature: SignatureAlgorithm::take_from(cons)?,
                    issuer: Name::take_from(cons)?,
                    validity: Validity::take_from(cons)?,
                    subject: Name::take_from(cons)?,
                    subject_public_key_info:
                    SubjectPublicKeyInfo::take_from(cons)?,
                    extensions: cons.take_constructed_if(
                        Tag::CTX_3,
                        IdExtensions::take_from
                    )?,
                })
            })
        }).map_err(Into::into)
    }

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        self.signed_data.encode()
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut b = Vec::new();
        self.encode().write_encoded(Mode::Der, &mut b).unwrap(); // Writing to vec will not fail
        Bytes::from(b)
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
    pub fn validate_ta(self) -> Result<Self, ValidationError> {
        self.validate_basics()?;
        self.validate_ca_basics()?;

        // Authority Key Identifier. May be present, if so, must be
        // equal to the subject key identifier.
        if let Some(ref aki) = self.extensions.authority_key_id {
            if aki != self.extensions.subject_key_id() {
                return Err(ValidationError);
            }
        }

        // Verify that this is self signed
        self.signed_data.verify_signature(
            self.subject_public_key_info
                .subject_public_key().octet_slice().unwrap()
        )?;

        Ok(self)
    }

    /// Validates the certificate as an EE certificate.
    ///
    /// For validation to succeed, the certificate needs to have been signed
    /// by the provided `issuer` certificate.
    ///
    /// Note that this does _not_ check the CRL.
    pub fn validate_ee(
        self,
        issuer: &IdCert,
    ) -> Result<Self, ValidationError> {
        self.validate_basics()?;
        self.validate_issued(issuer)?;

        // Basic Constraints: Must not be present.
        if self.extensions.basic_ca != None {
            return Err(ValidationError)
        }

        // Verify that this is signed by the issuer
        self.validate_signature(issuer)?;
        Ok(self)
    }


    //--- Validation Components

    /// Validates basic compliance with RFC8183 and RFC6492
    ///
    /// Note the the standards are pretty permissive in this context.
    fn validate_basics(&self) -> Result<(), ValidationError> {
        // Validity. Check according to RFC 5280.
        self.validity.validate()?;

        // Subject Key Identifer. Must be the SHA-1 hash of the octets
        // of the subjectPublicKey.
        if self.extensions.subject_key_id().as_slice().unwrap()
            != self.subject_public_key_info().key_identifier().as_ref()
        {
            return Err(ValidationError)
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
    fn validate_issued(
        &self,
        issuer: &IdCert,
    ) -> Result<(), ValidationError> {
        // Authority Key Identifier. Must be present and match the
        // subject key ID of `issuer`.
        if let Some(ref aki) = self.extensions.authority_key_id {
            if aki != issuer.extensions.subject_key_id() {
                return Err(ValidationError)
            }
        }
        else {
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
        if self.extensions.basic_ca != Some(true) {
            return Err(ValidationError)
        }

        Ok(())
    }

    /// Validates the certificate’s signature.
    fn validate_signature(
        &self,
        issuer: &IdCert
    ) -> Result<(), ValidationError> {
        self.signed_data.verify_signature(issuer.public_key())
    }
}


//--- AsRef

impl AsRef<IdCert> for IdCert {
    fn as_ref(&self) -> &Self {
        self
    }
}


//------------ IdExtensions --------------------------------------------------

#[derive(Clone, Debug)]
pub struct IdExtensions {
    /// Basic Constraints.
    ///
    /// The field indicates whether the extension is present and, if so,
    /// whether the "cA" boolean is set. See 4.8.1. of RFC 6487.
    basic_ca: Option<bool>,

    /// Subject Key Identifier.
    subject_key_id: SubjectKeyIdentifier,

    /// Authority Key Identifier
    authority_key_id: Option<OctetString>,
}

impl IdExtensions {
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            let mut basic_ca = None;
            let mut subject_key_id = None;
            let mut authority_key_id = None;
            while let Some(()) = cons.take_opt_sequence(|cons| {
                let id = Oid::take_from(cons)?;
                let critical = cons.take_opt_bool()?.unwrap_or(false);
                let value = OctetString::take_from(cons)?;
                Mode::Der.decode(value.to_source(), |content| {
                    if id == oid::CE_BASIC_CONSTRAINTS {
                        BasicCa::take(content, critical, &mut basic_ca)
                    } else if id == oid::CE_SUBJECT_KEY_IDENTIFIER {
                        SubjectKeyIdentifier::take(
                            content, critical, &mut subject_key_id
                        )
                    } else if id == oid::CE_AUTHORITY_KEY_IDENTIFIER {
                        Extensions::take_authority_key_identifier(
                            content, &mut authority_key_id
                        )
                    } else if critical {
                        xerr!(Err(decode::Malformed))
                    } else {
                        // RFC 5280 says we can ignore non-critical
                        // extensions we don’t know of. RFC 6487
                        // agrees. So let’s do that.
                        Ok(())
                    }
                })?;
                Ok(())
            })? {}
            Ok(IdExtensions {
                basic_ca: basic_ca.map(|ca| ca.ca()),
                subject_key_id: subject_key_id.ok_or(decode::Malformed)?,
                authority_key_id,
            })
        })
    }

    pub fn subject_key_id(&self) -> &OctetString {
        &self.subject_key_id.subject_key_id()
    }

    pub fn from_key_infos(
        _issuer_info: &SubjectPublicKeyInfo,
        _subject_info: &SubjectPublicKeyInfo
    ) -> Self {
        unimplemented!()
    }

}


//------------ IdCertSignRequest ---------------------------------------------

/// An IdCertSignRequest to be used with the Signer trait.
pub struct IdCertSignRequest {
    data: Captured
}

impl IdCertSignRequest {
    /// Creates an IdCertSingRequest to be signed with the Signer trait.
    ///
    /// There is some magic here. Since we always use a structure where we
    /// have one self-signed CA certificate used as identity trust anchors,
    /// or EE certificates signed directly below this, we can make some
    /// assumptions and save on method parameters.
    ///
    /// If the issuing_key and the subject_key are the same we will assume
    /// that this is for a self-signed CA (TA even) certificate. So we will
    /// set the appropriate extensions: basic_ca and subject_key_id, but no
    /// authority_key_id.
    ///
    /// If the issuing_key and the subject_key are different then we will use
    /// the extensions: subject_key_id and authority_key_id, but no basic_ca.
    pub fn new(
        serial_number: u32,
        duration: Duration,
        issuing_key: &SubjectPublicKeyInfo,
        subject_key: &SubjectPublicKeyInfo
    ) -> Self
    {
        let mut v = Vec::new();
        let w = &mut v;
        let m = Mode::Der;

        Self::write(serial_number.value(), m, w);
        Self::write(SignatureAlgorithm::Sha256WithRsaEncryption.encode(), m, w);

        let issuer = Name::from_pub_key(issuing_key);
        Self::write(issuer.encode(), m, w);

        let val = Validity::from_duration(duration);
        Self::write(val.encode(), m, w);

        let subject = Name::from_pub_key(subject_key);
        Self::write(subject.encode(), m, w);

        Self::write(subject_key.encode(), m, w);

        // Encode extensions!

        unimplemented!()
    }

    fn write(data: impl Values, mode: Mode, target: &mut impl io::Write) {
        data.write_encoded(mode, target).unwrap();
    }

    pub fn get_data(&self) -> &Captured {
        &self.data
    }

}



//------------ Tests ---------------------------------------------------------

// is pub so that we can use a parsed test IdCert for now for testing
#[cfg(test)]
pub mod tests {

    use super::*;
    use bytes::Bytes;
    use time;
    use chrono::{TimeZone, Utc};

    // Useful until we can create IdCerts of our own
    pub fn test_id_certificate() -> IdCert {
        let data = include_bytes!("../../test/oob/id-publisher-ta.cer");
        IdCert::decode(Bytes::from_static(data)).unwrap()
    }

    #[test]
    fn should_parse_id_publisher_ta_cert() {
        let d = Utc.ymd(2012, 1, 1).and_hms(0, 0, 0);
        time::with_now(d, || {
            let cert = test_id_certificate();
            assert!(cert.validate_ta().is_ok());
        });
    }
}
