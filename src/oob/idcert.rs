//! Identity Certificates.
//!


use ber::{
    BitString, Constructed, Error, Mode, OctetString, Oid, Source, Tag,
    Unsigned
};
use ring::digest::{self, Digest};
use x509::{
    update_once, Name, SignatureAlgorithm, SignedData, Time, ValidationError
};


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
    extensions: Extensions,
}

impl IdCert {
    /// Decodes a source as a certificate.
    pub fn decode<S: Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded certificate from the beginning of a value.
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::take_content_from)
    }

    /// Parses the content of a Certificate sequence.
    pub fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::take_content_from(cons)?;

        Mode::Der.decode(signed_data.data().clone(), |cons| {
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
                        Extensions::take_from
                    )?,
                })
            })
        }).map_err(Into::into)
    }

    /// Returns a reference to the certificate’s public key.
    pub fn public_key(&self) -> &[u8] {
        self.subject_public_key_info
            .subject_public_key.octet_slice().unwrap()
    }

    /// Returns a reference to the subject key identifier.
    pub fn subject_key_identifier(&self) -> &OctetString {
        &self.extensions.subject_key_id
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
        // equal to the subject key indentifier.
        if let Some(ref aki) = self.extensions.authority_key_id {
            if *aki != self.extensions.subject_key_id {
                return Err(ValidationError);
            }
        }

        // Verify that this is self signed
        self.signed_data.verify_signature(
            self.subject_public_key_info
                .subject_public_key.octet_slice().unwrap()
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
        if self.extensions.subject_key_id.as_slice().unwrap()
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
            if *aki != issuer.extensions.subject_key_id {
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

//------------ Validity ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Validity {
    not_before: Time,
    not_after: Time,
}

impl Validity {
    pub fn new(not_before: Time, not_after: Time) -> Self {
        Validity { not_before, not_after }
    }

    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            Ok(Validity::new(
                Time::take_from(cons)?,
                Time::take_from(cons)?,
            ))
        })
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        self.not_before.validate_not_before()?;
        self.not_after.validate_not_after()?;
        Ok(())
    }
}


//------------ SubjectPublicKeyInfo ------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo {
    algorithm: PublicKeyAlgorithm,
    subject_public_key: BitString,
}

impl SubjectPublicKeyInfo {
    pub fn decode<S: Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            Ok(SubjectPublicKeyInfo {
                algorithm: PublicKeyAlgorithm::take_from(cons)?,
                subject_public_key: BitString::take_from(cons)?
            })
        })
    }

    pub fn key_identifier(&self) -> Digest {
        digest::digest(
            &digest::SHA1,
            self.subject_public_key.octet_slice().unwrap()
        )
    }
}


//------------ PublicKeyAlgorithm --------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicKeyAlgorithm {
    RsaEncryption,
}

impl PublicKeyAlgorithm {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::take_content_from)
    }

    pub fn take_content_from<S: Source>(
        cons: &mut Constructed<S>
    ) -> Result<Self, S::Err> {
        oid::RSA_ENCRYPTION.skip_if(cons)?;
        cons.take_opt_null()?;
        Ok(PublicKeyAlgorithm::RsaEncryption)
    }
}


//------------ Extensions ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct Extensions {
    /// Basic Contraints.
    ///
    /// The field indicates whether the extension is present and, if so,
    /// whether the "cA" boolean is set. See 4.8.1. of RFC 6487.
    basic_ca: Option<bool>,

    /// Subject Key Identifier.
    subject_key_id: OctetString,

    /// Authority Key Identifier
    authority_key_id: Option<OctetString>,
}

impl Extensions {
    pub fn take_from<S: Source>(
        cons: &mut Constructed<S>
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
                        Self::take_basic_ca(content, &mut basic_ca)
                    } else if id == oid::CE_SUBJECT_KEY_IDENTIFIER {
                        Self::take_subject_key_identifier(
                            content, &mut subject_key_id
                        )
                    } else if id == oid::CE_AUTHORITY_KEY_IDENTIFIER {
                        Self::take_authority_key_identifier(
                            content, &mut authority_key_id
                        )
                    } else if critical {
                        xerr!(Err(Error::Malformed))
                    } else {
                        // RFC 5280 says we can ignore non-critical
                        // extensions we don’t know of. RFC 6487
                        // agrees. So let’s do that.
                        Ok(())
                    }
                })?;
                Ok(())
            })? {}
            Ok(Extensions {
                basic_ca,
                subject_key_id: subject_key_id.ok_or(Error::Malformed)?,
                authority_key_id,
            })
        })
    }

    /// Parses the Basic Constraints Extension.
    ///
    /// The extension must be present in CA certificates and must not be
    /// present in EE certificats.
    ///
    /// ```text
    ///   BasicConstraints ::= SEQUENCE {
    ///        cA                      BOOLEAN DEFAULT FALSE,
    ///        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
    /// ```
    ///
    /// The cA field gets chosen by the CA. The pathLenConstraint field must
    /// not be present.
    fn take_basic_ca<S: Source>(
        cons: &mut Constructed<S>,
        basic_ca: &mut Option<bool>
    ) -> Result<(), S::Err> {
        update_once(basic_ca, || {
            match cons.take_sequence(|cons| cons.take_opt_bool())? {
                Some(res) => Ok(res),
                None => Ok(false)
            }
        })
    }

    /// Parses the Subject Key Identifier Extension.
    ///
    /// The extension must be present and contain the 160 bit SHA-1 hash of
    /// the value of the DER-encoded bit string of the subject public key.
    ///
    /// ```text
    /// SubjectKeyIdentifier ::= KeyIdentifier
    /// KeyIdentifier        ::= OCTET STRING
    /// ```
    fn take_subject_key_identifier<S: Source>(
        cons: &mut Constructed<S>,
        subject_key_id: &mut Option<OctetString>
    ) -> Result<(), S::Err> {
        update_once(subject_key_id, || {
            let id = OctetString::take_from(cons)?;
            if id.len() != 20 {
                xerr!(Err(Error::Malformed.into()))
            } else {
                Ok(id)
            }
        })
    }

    /// Parses the Authority Key Identifier Extension.
    ///
    /// Must be present except in self-signed CA certificates where it is
    /// optional.
    ///
    /// ```text
    /// AuthorityKeyIdentifier ::= SEQUENCE {
    ///   keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    ///   authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    ///   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
    ///
    /// KeyIdentifier ::= OCTET STRING
    /// ```
    ///
    /// Only keyIdentifier must be present.
    fn take_authority_key_identifier<S: Source>(
        cons: &mut Constructed<S>,
        authority_key_id: &mut Option<OctetString>
    ) -> Result<(), S::Err> {
        update_once(authority_key_id, || {
            let res = cons.take_sequence(|cons| {
                cons.take_value_if(Tag::CTX_0, OctetString::take_content_from)
            })?;
            if res.len() != 20 {
                return Err(Error::Malformed.into())
            } else {
                Ok(res)
            }
        })
    }
}


//------------ OIDs ----------------------------------------------------------

mod oid {
    use ::ber::Oid;

    pub const RSA_ENCRYPTION: Oid<&[u8]>
    = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]);

    pub const CE_SUBJECT_KEY_IDENTIFIER: Oid<&[u8]> = Oid(&[85, 29, 14]);
    pub const CE_BASIC_CONSTRAINTS: Oid<&[u8]> = Oid(&[85, 29, 19]);
    pub const CE_AUTHORITY_KEY_IDENTIFIER: Oid<&[u8]> = Oid(&[85, 29, 35]);
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::fs;
    use bytes::Bytes;
    use time;
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_parse_id_publisher_ta_cert() {
        let d = Utc.ymd(2012, 1, 1).and_hms(0, 0, 0);
        time::with_now(d, || {
        let data = fs::read("test/oob/id-publisher-ta.cer").unwrap();
        let cert = IdCert::decode(Bytes::from(data)).unwrap();
            assert!(cert.validate_ta().is_ok());
        });
    }
}

