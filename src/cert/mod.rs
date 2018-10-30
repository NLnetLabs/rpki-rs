//! Resource certificates.
//!
//! The certificates used in RPKI are called _resource certificates._ They
//! are defined in [RFC 6487] as a profile on regular Internet PKI
//! certificates defined in [RFC 5280]. While they use the format defined
//! for X.509 certificates, the allowed vales for various fields are limited
//! making the overall structure more simple and predictable.
//!
//! This module implements raw resource certificates in the type [`Cert`] and
//! validated certificates in the type [`ResourceCert`]. The latter type is
//! used for issuer certificates when validating other certificates.
//!
//! In addition, there are several types for the components of a certificate.
//!
//! [`Cert`]: struct.Cert.html
//! [`ResourceCert`]: struct.ResourceCert.html
//! [RFC 5280]: https://tools.ietf.org/html/rfc5280
//! [RFC 6487]: https://tools.ietf.org/html/rfc5487

use bcder::{decode, encode};
use bcder::encode::PrimitiveContent;
use bcder::{BitString, Mode, OctetString, Tag, Unsigned};
use cert::ext::{Extensions, UriGeneralName, UriGeneralNames};
use ring::digest::{self, Digest};
use super::asres::AsBlocks;
use super::uri;
use super::ipres::IpAddressBlocks;
use super::x509::{Name, SignedData, Time, ValidationError};
use signing::{PublicKeyAlgorithm, SignatureAlgorithm};
use chrono::Utc;


pub mod ext;


//------------ Cert ----------------------------------------------------------

/// A resource certificate.
///
/// A value of this type represents a resource certificate. It can be one of
/// three different variants.
///
/// A _CA certificate_ appears in its own file in the repository. Its main
/// use is to sign other certificates.
///
/// An _EE certificate_ is used to sign other objects in the repository, such
/// as manifests or ROAs and is included in the file of these objects. In
/// RPKI, EE certificates are used only once.  Whenever a new object is
/// created, a new EE certificate is created, signed by its CA, used to sign
/// the object, and then the private key is thrown away.
///
/// Finally, _TA certificates_ are the installed trust anchors. These are
/// self-signed.
/// 
/// If a certificate is stored in a file, you can use the [`decode`] function
/// to parse the entire file. If the certificate is part of some other
/// structure, the [`take_from`] and [`from_constructed`] functions can be
/// used during parsing of that structure.
///
/// Once parsing succeeded, the three methods [`validate_ca`],
/// [`validate_ee`], and [`validate_ta`] can be used to validate the
/// certificate and turn it into a [`ResourceCert`] so it can be used for
/// further processing. In addition, various methods exist to access
/// information contained in the certificate.
///
/// [`ResourceCert`]: struct.ResourceCert.html
/// [`decode`]: #method.decode
/// [`take_from`]: #method.take_from
/// [`from_constructed`]: #method.from_constructed
/// [`validate_ca`]: #method.validate_ca
/// [`validate_ee`]: #method.validate_ee
/// [`validate_ta`]: #method.validate_ta
#[derive(Clone, Debug)]
pub struct Cert {
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

    /// The optional Issuer Unique ID.
    issuer_unique_id: Option<BitString>,

    /// The optional Subject Unique ID.
    subject_unique_id: Option<BitString>,

    /// The certificate extensions.
    extensions: Extensions,
}

impl Cert {
    /// Decodes a source as a certificate.
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded certificate from the beginning of a value.
    ///
    /// This function assumes that the certificate is encoded in the next
    /// constructed value tagged as a sequence.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the content of a Certificate sequence.
    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::from_constructed(cons)?;

        signed_data.data().clone().decode(|cons| {
            cons.take_sequence(|cons| {
                // version [0] EXPLICIT Version DEFAULT v1.
                //  -- we need extensions so apparently, we want v3 which,
                //     confusingly, is 2.
                cons.take_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(2))?;

                Ok(Cert {
                    signed_data,
                    serial_number: Unsigned::take_from(cons)?,
                    signature: SignatureAlgorithm::take_from(cons)?,
                    issuer: Name::take_from(cons)?,
                    validity: Validity::take_from(cons)?,
                    subject: Name::take_from(cons)?,
                    subject_public_key_info: 
                        SubjectPublicKeyInfo::take_from(cons)?,
                    issuer_unique_id: cons.take_opt_value_if(
                        Tag::CTX_1,
                        |c| BitString::from_content(c)
                    )?,
                    subject_unique_id: cons.take_opt_value_if(
                        Tag::CTX_2,
                        |c| BitString::from_content(c)
                    )?,
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
        &self.extensions.subject_key_id()
    }

    /// Returns a reference to the entire public key information structure.
    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        &self.subject_public_key_info
    }

    /// Returns a reference to the certificate’s CRL distributionb point.
    ///
    /// If present, this will be an `rsync` URI. 
    pub fn crl_distribution(&self) -> Option<&UriGeneralNames> {
        self.extensions.crl_distribution()
    }

    /// Returns a reference to the certificate’s serial number.
    pub fn serial_number(&self) -> &Unsigned {
        &self.serial_number
    }
}

/// # Validation
///
impl Cert {
    /// Validates the certificate as a trust anchor.
    ///
    /// This validates that the certificate “is a current, self-signed RPKI
    /// CA certificate that conforms to the profile as specified in
    /// RFC6487” (RFC7730, section 3, step 2).
    pub fn validate_ta(
        self,
        strict: bool
    ) -> Result<ResourceCert, ValidationError> {
        self.validate_basics(strict)?;
        self.validate_ca_basics(strict)?;

        // 4.8.3. Authority Key Identifier. May be present, if so, must be
        // equal to the subject key indentifier.
        if let Some(ref aki) = self.extensions.authority_key_id() {
            if *aki != self.extensions.subject_key_id() {
                return Err(ValidationError);
            }
        }

        // 4.8.6. CRL Distribution Points. There musn’t be one.
        if self.extensions.crl_distribution().is_some() {
            return Err(ValidationError)
        }

        // 4.8.7. Authority Information Access. Must not be present.
        if self.extensions.authority_info_access().is_some() {
            return Err(ValidationError)
        }

        // 4.8.10.  IP Resources. If present, musn’t be "inherit".
        let ip_resources = IpAddressBlocks::from_resources(
            self.extensions.ip_resources()
        )?;
 
        // 4.8.11.  AS Resources. If present, musn’t be "inherit". That
        // IP resources (logical) or AS resources are present has already
        // been checked during parsing.
        let as_resources = AsBlocks::from_resources(
            self.extensions.as_resources()
        )?;

        self.signed_data.verify_signature(
            self.subject_public_key_info
                .subject_public_key.octet_slice().unwrap()
        )?;

        Ok(ResourceCert {
            cert: self,
            ip_resources,
            as_resources,
        })
    }

    /// Validates the certificate as a CA certificate.
    ///
    /// For validation to succeed, the certificate needs to have been signed
    /// by the provided `issuer` certificate.
    ///
    /// Note that this does _not_ check the CRL.
    pub fn validate_ca(
        self,
        issuer: &ResourceCert,
        strict: bool
    ) -> Result<ResourceCert, ValidationError> {
        self.validate_basics(strict)?;
        self.validate_ca_basics(strict)?;
        self.validate_issued(issuer, strict)?;
        self.validate_signature(issuer, strict)?;
        self.validate_resources(issuer, strict)
    }

    /// Validates the certificate as an EE certificate.
    ///
    /// For validation to succeed, the certificate needs to have been signed
    /// by the provided `issuer` certificate.
    ///
    /// Note that this does _not_ check the CRL.
    pub fn validate_ee(
        self,
        issuer: &ResourceCert,
        strict: bool
    ) -> Result<ResourceCert, ValidationError>  {
        self.validate_basics(strict)?;
        self.validate_issued(issuer, strict)?;

        // 4.8.1. Basic Constraints: Must not be present.
        if self.extensions.basic_ca().is_some(){
            return Err(ValidationError)
        }

        // 4.8.4. Key Usage. Bits for CA or not CA have been checked during
        // parsing already.
        if self.extensions.key_usage_ca() {
            return Err(ValidationError)
        }

        // 4.8.8.  Subject Information Access.
        if self.extensions.subject_info_access().ca() {
            return Err(ValidationError)
        }

        self.validate_signature(issuer, strict)?;
        self.validate_resources(issuer, strict)
    }


    //--- Validation Components

    /// Validates basic compliance with section 4 of RFC 6487.
    fn validate_basics(&self, strict: bool) -> Result<(), ValidationError> {
        // The following lists all such constraints in the RFC, noting those
        // that we cannot check here.

        // 4.2 Serial Number: must be unique over the CA. We cannot check
        // here, and -- XXX --- probably don’t care?

        // 4.3 Signature Algorithm: limited to those in RFC 6485. Already
        // checked in parsing.

        // 4.4 Issuer: must have certain format. 
        Name::validate_rpki(&self.issuer, strict)?;

        // 4.5 Subject: same as 4.4.
        Name::validate_rpki(&self.subject, strict)?;
        
        // 4.6 Validity. Check according to RFC 5280.
        self.validity.validate()?;

        // 4.7 Subject Public Key Info: limited algorithms. Already checked
        // during parsing.

        // 4.8.1. Basic Constraints. Differing requirements for CA and EE
        // certificates.
        
        // 4.8.2. Subject Key Identifer. Must be the SHA-1 hash of the octets
        // of the subjectPublicKey.
        if self.extensions.subject_key_id().as_slice().unwrap()
                != self.subject_public_key_info().key_identifier().as_ref()
        {
            return Err(ValidationError)
        }

        // 4.8.3. Authority Key Identifier. Differing requirements of TA and
        // other certificates.

        // 4.8.4. Key Usage. Differs between CA and EE certificates.

        // 4.8.5. Extended Key Usage. Must not be present for the kind of
        // certificates we use here.
        if self.extensions.extended_key_usage().is_some() {
            return Err(ValidationError)
        }

        // 4.8.6. CRL Distribution Points. Differs between TA and other
        // certificates.

        // 4.8.7. Authority Information Access. Differs between TA and other
        // certificates.

        // 4.8.8.  Subject Information Access. Differs between CA and EE
        // certificates.

        // 4.8.9.  Certificate Policies. XXX I think this can be ignored.
        // At least for now.

        // 4.8.10.  IP Resources. Differs between trust anchor and issued
        // certificates.
        
        // 4.8.11.  AS Resources. Differs between trust anchor and issued
        // certificates.

        Ok(())
    }

    /// Validates that the certificate is a correctly issued certificate.
    fn validate_issued(
        &self,
        issuer: &ResourceCert,
        _strict: bool,
    ) -> Result<(), ValidationError> {
        // 4.8.3. Authority Key Identifier. Must be present and match the
        // subject key ID of `issuer`.
        if let Some(ref aki) = self.extensions.authority_key_id() {
            if *aki != issuer.cert.extensions.subject_key_id() {
                return Err(ValidationError)
            }
        }
        else {
            return Err(ValidationError);
        }

        // 4.8.6. CRL Distribution Points. There must be one. There’s a rule
        // that there must be at least one rsync URI. This will be implicitely
        // checked when verifying the CRL later.
        if self.extensions.crl_distribution().is_none() {
            return Err(ValidationError)
        }

        // 4.8.7. Authority Information Access. Must be present and contain
        // the URI of the issuer certificate. Since we do top-down validation,
        // we don’t really need that URI so – XXX – leave it unchecked for
        // now.
        if self.extensions.authority_info_access().is_none() {
            return Err(ValidationError);
        }

        Ok(())
    }

    /// Validates that the certificate is a valid CA certificate.
    ///
    /// Checks the parts that are common in normal and trust anchor CA
    /// certificates.
    fn validate_ca_basics(
        &self,
        _strict: bool
    ) -> Result<(), ValidationError> {
        // 4.8.1. Basic Constraints: For a CA it must be present (RFC6487)
        // und the “cA” flag must be set (RFC5280).
        if self.extensions.basic_ca() != Some(true) {
            return Err(ValidationError)
        }

        // 4.8.4. Key Usage. Bits for CA or not CA have been checked during
        // parsing already.
        if !self.extensions.key_usage_ca() {
            return Err(ValidationError)
        }

        // 4.8.8.  Subject Information Access.
        if !self.extensions.subject_info_access().ca() {
            return Err(ValidationError)
        }
        
        Ok(())
    }

    /// Validates the certificate’s signature.
    fn validate_signature(
        &self,
        issuer: &ResourceCert,
        _strict: bool
    ) -> Result<(), ValidationError> {
        self.signed_data.verify_signature(issuer.cert.public_key())
    }

    /// Validates and extracts the IP and AS resources.
    ///
    /// Upon success, this converts the certificate into a `ResourceCert`.
    fn validate_resources(
        self,
        issuer: &ResourceCert,
        _strict: bool
    ) -> Result<ResourceCert, ValidationError> {
        // 4.8.10.  IP Resources. If present, must be encompassed by issuer.
        // certificates.
        let ip_resources = issuer.ip_resources.encompasses(
            self.extensions.ip_resources()
        )?;
        
        // 4.8.11.  AS Resources. If present, must be encompassed by issuer.
        // That IP or AS resources need to be present has been
        // checked during parsing.
        let as_resources = issuer.as_resources.encompasses(
            self.extensions.as_resources()
        )?;

        Ok(ResourceCert {
            cert: self,
            ip_resources,
            as_resources,
        })
    }
}


//--- AsRef

impl AsRef<Cert> for Cert {
    fn as_ref(&self) -> &Self {
        self
    }
}



//------------ ResourceCert --------------------------------------------------

/// A validated resource certificate.
///
/// This differs from a normal [`Cert`] in that its IP and AS resources are
/// resolved into concrete values.
#[derive(Clone, Debug)]
pub struct ResourceCert {
    /// The underlying resource certificate.
    cert: Cert,

    /// The resolved IP resources.
    ip_resources: IpAddressBlocks,

    /// The resolved AS resources.
    as_resources: AsBlocks,
}

impl ResourceCert {
    /// Returns a reference to the IP resources of this certificate.
    pub fn ip_resources(&self) -> &IpAddressBlocks {
        &self.ip_resources
    }

    /// Returns a reference to the AS resources of this certificate.
    pub fn as_resources(&self) -> &AsBlocks {
        &self.as_resources
    }

    /// Returns an iterator over the manifest URIs of this certificate.
    pub fn manifest_uris(&self) -> impl Iterator<Item=UriGeneralName> {
        self.cert.extensions.manifest_uris()
    }

    /// Returns the repository rsync URI of this certificate if available.
    pub fn repository_uri(&self) -> Option<uri::Rsync> {
        self.cert.extensions.repository_uri()
    }
}


//--- AsRef

impl AsRef<Cert> for ResourceCert {
    fn as_ref(&self) -> &Cert {
        &self.cert
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

    pub fn from_duration(duration: ::chrono::Duration) -> Self {
        let not_before = Time::new(Utc::now());
        let not_after = Time::new(Utc::now() + duration);

        Validity { not_before, not_after }
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
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

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence(
            (
                self.not_before.encode(),
                self.not_after.encode(),
            )
        )
    }
}


//------------ SubjectPublicKeyInfo ------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo {
    algorithm: PublicKeyAlgorithm,
    subject_public_key: BitString,
}

impl SubjectPublicKeyInfo {
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn subject_public_key(&self) -> &BitString {
        &self.subject_public_key
    }

    pub fn algorithm(&self) -> &PublicKeyAlgorithm {
        &self.algorithm
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
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

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence(
            (
                self.algorithm.encode(),
                self.subject_public_key.encode()
            )
        )
    }
}

