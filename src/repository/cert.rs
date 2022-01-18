//! Resource certificates.
//!
//! The certificates used in RPKI are called _resource certificates._ They
//! are defined in [RFC 6487] as a profile on regular Internet PKI
//! certificates defined in [RFC 5280]. While they use the format defined
//! for X.509 certificates, the allowed values for various fields are limited
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

use std::{borrow, ops};
use std::iter::FromIterator;
use std::sync::Arc;
use bcder::{decode, encode};
use bcder::xerr;
use bcder::encode::PrimitiveContent;
use bcder::{
    BitString, Captured, ConstOid, Ia5String, Mode, OctetString, Oid, Tag
};
use bytes::Bytes;
use crate::uri;
use super::crypto::{
    KeyIdentifier, PublicKey, SignatureAlgorithm, Signer, SigningError
};
use super::oid;
use super::resources::{
    AsBlock, AsBlocks, AsBlocksBuilder, AsResources, AsResourcesBuilder,
    IpBlock, IpBlocks, IpBlocksBuilder, IpResources, IpResourcesBuilder
};
use super::tal::TalInfo;
use super::x509::{
    Name, SignedData, Serial, Time, Validity, ValidationError,
    encode_extension, update_first, update_once
};


//------------ Cert ----------------------------------------------------------

/// A raw resource certificate.
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

    /// The actual data of the certificate.
    tbs: TbsCert,
}


/// # Decoding and Encoding
///
impl Cert {
    /// Decodes a source as a certificate.
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded certificate from the beginning of a value.
    ///
    /// This function assumes that the certificate is encoded in the next
    /// constructed value in `cons` tagged as a sequence.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Takes an optional certificate from the beginning of a value.
    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_sequence(Self::from_constructed)
    }

    /// Parses the content of a Certificate sequence.
    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::from_constructed(cons)?;
        let tbs = signed_data.data().clone().decode(
            TbsCert::from_constructed
        )?;
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
}


/// # Validation
///
/// When validating a certificate, two properties are checked: whether the
/// certificate’s structure and content comply with the specification for
/// resource certificates laid out in [RFC 6487] and whether the certificate
/// has been correctly issued by its CA.
///
/// In some cases it is useful to perform these two steps separately.
/// Therefore, methods are available both for each step and for doing both
/// steps at once. Since we need to name these consistently, we devised the
/// following convention:
///
/// The first step that validates compliance with the specification is called
/// _inspection._ Methods are available to inspect different kinds of
/// certificates. They all have the verb _inspect_ in their name. Only the
/// certificate itself is necessary to perform inspection.
///
/// The second step checking whether the certificate was correctly issued is
/// called _verification._ Methods are available to verify different kinds of
/// certificates. They all have the verb _verify_ in their name and, in
/// most cases, require access to the issuer certificate.
///
/// In addition, methods are available to perform both steps at once for
/// different kinds of certificates. These all have _validate_ in their name.
impl Cert {
    //--- Validation

    /// Validates the certificate as a trust anchor.
    ///
    /// This validates that the certificate “is a current, self-signed RPKI
    /// CA certificate that conforms to the profile as specified in
    /// RFC6487” (RFC7730, section 3, step 2).
    pub fn validate_ta(
        self,
        tal: Arc<TalInfo>,
        strict: bool
    ) -> Result<ResourceCert, ValidationError> {
        self.validate_ta_at(tal, strict, Time::now())
    }

    pub fn validate_ta_at(
        self,
        tal: Arc<TalInfo>,
        strict: bool,
        now: Time,
    ) -> Result<ResourceCert, ValidationError> {
        self.inspect_ta_at(strict, now)?;
        self.verify_ta(tal, strict)
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
        self.validate_ca_at(issuer, strict, Time::now())
    }

    pub fn validate_ca_at(
        self,
        issuer: &ResourceCert,
        strict: bool,
        now: Time,
    ) -> Result<ResourceCert, ValidationError> {
        self.inspect_ca_at(strict, now)?;
        self.verify_ca(issuer, strict)
    }

    /// Validates the certificate as an EE RPKI-internal certificate.
    ///
    /// For validation to succeed, the certificate needs to have been signed
    /// by the provided `issuer` certificate.
    ///
    /// Note that this does _not_ check the CRL.
    ///
    /// Note further that this method should not be used for router
    /// certificates. Use `validate_router` for that.
    pub fn validate_ee(
        self,
        issuer: &ResourceCert,
        strict: bool
    ) -> Result<ResourceCert, ValidationError>  {
        self.validate_ee_at(issuer, strict, Time::now())
    }

    pub fn validate_ee_at(
        self,
        issuer: &ResourceCert,
        strict: bool,
        now: Time,
    ) -> Result<ResourceCert, ValidationError>  {
        self.inspect_ee_at(strict, now)?;
        self.verify_ee(issuer, strict)
    }

    pub fn validate_detached_ee(
        self,
        issuer: &ResourceCert,
        strict: bool
    ) -> Result<ResourceCert, ValidationError>  {
        self.validate_detached_ee_at(issuer, strict, Time::now())
    }

    pub fn validate_detached_ee_at(
        self,
        issuer: &ResourceCert,
        strict: bool,
        now: Time,
    ) -> Result<ResourceCert, ValidationError>  {
        self.inspect_detached_ee_at(strict, now)?;
        self.verify_ee(issuer, strict)
    }

    pub fn validate_router(
        &self,
        issuer: &ResourceCert,
        strict: bool
    ) -> Result<(), ValidationError> {
        self.validate_router_at(issuer, strict, Time::now())
    }

    pub fn validate_router_at(
        &self,
        issuer: &ResourceCert,
        strict: bool,
        now: Time,
    ) -> Result<(), ValidationError> {
        self.inspect_router_at(strict, now)?;
        self.verify_router(issuer, strict)
    }


    //--- Inspection

    pub fn inspect_ta(&self, strict: bool) -> Result<(), ValidationError> {
        self.inspect_ta_at(strict, Time::now())
    }

    pub fn inspect_ta_at(
        &self,
        strict: bool,
        now: Time
    ) -> Result<(), ValidationError> {
        self.inspect_basics(strict, now)?;
        self.inspect_ca_basics(strict)?;

        // 4.8.3. Authority Key Identifier. May be present, if so, must be
        // equal to the subject key identifier.
        if let Some(ref aki) = self.authority_key_identifier {
            if *aki != self.subject_key_identifier {
                return Err(ValidationError);
            }
        }

        // 4.8.6. CRL Distribution Points. There mustn’t be one.
        if self.crl_uri.is_some() {
            return Err(ValidationError)
        }

        // 4.8.7. Authority Information Access. Must not be present.
        if self.ca_issuer.is_some() {
            return Err(ValidationError)
        }

        // 4.8.10. IP Resources.
        // 4.8.11. AS Resources.
        //
        // Are checked as part of verification.

        Ok(())
    }

    pub fn inspect_ca(&self, strict: bool) -> Result<(), ValidationError> {
        self.inspect_ca_at(strict, Time::now())
    }

    pub fn inspect_ca_at(
        &self, strict: bool, now: Time
    ) -> Result<(), ValidationError> {
        self.inspect_basics(strict, now)?;
        self.inspect_ca_basics(strict)?;
        self.inspect_issued(strict)
    }

    pub fn inspect_ee(&self, strict: bool) -> Result<(), ValidationError> {
        self.inspect_ee_at(strict, Time::now())
    }

    pub fn inspect_ee_at(
        &self, strict: bool, now: Time
    ) -> Result<(), ValidationError> {
        self.inspect_basics(strict, now)?;
        self.inspect_issued(strict)?;

        // 4.8.1. Basic Constraints: Must not be present.
        if self.basic_ca.is_some(){
            xerr!(return Err(ValidationError))
        }

        // 4.8.4. Key Usage. Bits for CA or not CA have been checked during
        // parsing already.
        if self.key_usage != KeyUsage::Ee {
            xerr!(return Err(ValidationError))
        }

        // 4.8.8.  Subject Information Access. We need the signed object
        // but not the other ones.
        if self.ca_repository.is_some() || self.rpki_manifest.is_some()
            || self.signed_object.is_none()
        {
            xerr!(return Err(ValidationError))
        }

        Ok(())
    }

    pub fn inspect_detached_ee(
        &self, strict: bool
    ) -> Result<(), ValidationError> {
        self.inspect_detached_ee_at(strict, Time::now())
    }

    pub fn inspect_detached_ee_at(
        &self, strict: bool, now: Time
    ) -> Result<(), ValidationError> {
        self.inspect_basics(strict, now)?;
        self.inspect_issued(strict)?;

        // 4.8.1. Basic Constraints: Must not be present.
        if self.basic_ca.is_some(){
            xerr!(return Err(ValidationError))
        }

        // 4.8.4. Key Usage. Bits for CA or not CA have been checked during
        // parsing already.
        if self.key_usage != KeyUsage::Ee {
            xerr!(return Err(ValidationError))
        }

        // 4.8.8.  Subject Information Access. We allow the signed object one
        // but not the other ones.
        if self.ca_repository.is_some() || self.rpki_manifest.is_some() {
            xerr!(return Err(ValidationError))
        }

        Ok(())
    }

    pub fn inspect_router(
        &self, strict: bool
    ) -> Result<(), ValidationError> {
        self.inspect_router_at(strict, Time::now())
    }

    pub fn inspect_router_at(
        &self, strict: bool, now: Time
    ) -> Result<(), ValidationError> {
        // 4.2 Serial Number: must be unique over the CA. We cannot check
        // here, and -- XXX --- probably don’t care?

        // 4.3 Signature Algorithm: limited to those in RFC 6485. Already
        // checked in parsing.
        //
        // However, RFC 5280 demands that the two mentions of the signature
        // algorithm are the same. So we do that here.
        if self.signature != self.signed_data.signature().algorithm() {
            return Err(ValidationError)
        }

        // 4.4 Issuer: must have certain format.
        Name::validate_rpki(&self.issuer, strict)?;

        // 4.5 Subject: same as 4.4.
        Name::validate_router(&self.subject, strict)?;

        // 4.6 Validity. Check according to RFC 5280.
        self.validity.validate_at(now)?;

        // 4.7 Subject Public Key Info: limited algorithms.
        if !self.subject_public_key_info().allow_router_cert() {
            xerr!(return Err(ValidationError))
        }

        // 4.8.1. Basic Constraints. Must not be present.
        if self.basic_ca.is_some(){
            xerr!(return Err(ValidationError))
        }

        // 4.8.2. Subject Key Identifier. Must be the SHA-1 hash of the octets
        // of the subjectPublicKey.
        if self.subject_key_identifier() !=
                             self.subject_public_key_info().key_identifier() {
            return Err(ValidationError)
        }

        // 4.8.3. Authority Key Identifier. Will be checked during
        // verification later.

        // 4.8.4. Key Usage. Must be EE.
        if self.key_usage != KeyUsage::Ee {
            xerr!(return Err(ValidationError))
        }

        // 4.8.5. Extended Key Usage.
        //
        // Must be present and contain at least the kp-bgpsec-router OID.
        self.inspect_router_eku(strict)?;

        // 4.8.6. CRL Distribution Points. There must be one.
        if self.crl_uri().is_none() {
            return Err(ValidationError)
        }

        // 4.8.7. Authority Information Access. Differs between TA and other
        // certificates.

        // 4.8.8.  Subject Information Access. There must be none.
        if self.ca_repository().is_some() || self.rpki_manifest().is_some()
            || self.signed_object().is_some() || self.rpki_notify().is_some()
        {
            return Err(ValidationError)
        }

        // 4.8.9.  Certificate Policies. XXX I think this can be ignored.
        // At least for now.

        // 4.8.10.  IP Resources.  Must not be present.
        if self.v4_resources().is_present() || self.v6_resources().is_present()
        {
            return Err(ValidationError)
        }

        // 4.8.11.  AS Resources. Differs between trust anchor and issued
        // certificates.
        if !self.as_resources().is_present()
            || self.as_resources().is_inherited()
        {
            return Err(ValidationError)
        }

        Ok(())
    }

    //--- Verification

    pub fn verify_ta(
        self, tal: Arc<TalInfo>, _strict: bool
    ) -> Result<ResourceCert, ValidationError> {
        // 4.8.10. IP Resources. If present, mustn’t be "inherit".
        let v4_resources = IpBlocks::from_resources(
            self.v4_resources.clone()
        )?;
        let v6_resources = IpBlocks::from_resources(
            self.v6_resources.clone()
        )?;

        // 4.8.11.  AS Resources. If present, mustn’t be "inherit". That
        // IP resources (logical) or AS resources are present has already
        // been checked during parsing.
        let as_resources = AsBlocks::from_resources(
            self.as_resources.clone()
        )?;

        self.signed_data.verify_signature(
            &self.subject_public_key_info
        )?;

        Ok(ResourceCert {
            cert: self,
            v4_resources,
            v6_resources,
            as_resources,
            tal
        })
    }

    pub fn verify_ta_ref(
        &self, _strict: bool
    ) -> Result<(), ValidationError> {
        // 4.8.10. IP Resources. If present, mustn’t be "inherit".
        if self.v4_resources.is_inherited() {
            return Err(ValidationError)
        }
        if self.v6_resources.is_inherited() {
            return Err(ValidationError)
        }

        // 4.8.11.  AS Resources. If present, mustn’t be "inherit".
        if self.as_resources.is_inherited() {
            return Err(ValidationError)
        }

        self.signed_data.verify_signature(
            &self.subject_public_key_info
        )?;

        Ok(())
    }

    pub fn verify_ca(
        self, issuer: &ResourceCert, strict: bool
    ) -> Result<ResourceCert, ValidationError> {
        self.verify_issuer_claim(issuer, strict)?;
        self.verify_signature(issuer, strict)?;
        self.verify_resources(issuer, strict)
    }

    pub fn verify_ee(
        self, issuer: &ResourceCert, strict: bool
    ) -> Result<ResourceCert, ValidationError> {
        self.verify_issuer_claim(issuer, strict)?;
        self.verify_signature(issuer, strict)?;
        self.verify_resources(issuer, strict)
    }

    pub fn verify_router(
        &self, issuer: &ResourceCert, strict: bool
    ) -> Result<(), ValidationError> {
        self.verify_issuer_claim(issuer, strict)?;
        self.verify_signature(issuer, strict)?;
        self.verify_as_resources(issuer, strict)
    }


    //--- Validation Components

    /// Inspects basic compliance with section 4 of RFC 6487.
    fn inspect_basics(
        &self,
        strict: bool,
        now: Time
    ) -> Result<(), ValidationError> {
        // The following lists all such constraints in the RFC, noting those
        // that we cannot check here.

        // 4.2 Serial Number: must be unique over the CA. We cannot check
        // here, and -- XXX --- probably don’t care?

        // 4.3 Signature Algorithm: limited to those in RFC 6485. Already
        // checked in parsing.
        //
        // However, RFC 5280 demands that the two mentions of the signature
        // algorithm are the same. So we do that here.
        if self.signature != self.signed_data.signature().algorithm() {
            return Err(ValidationError)
        }

        // 4.4 Issuer: must have certain format.
        Name::validate_rpki(&self.issuer, strict)?;

        // 4.5 Subject: same as 4.4.
        Name::validate_rpki(&self.subject, strict)?;

        // 4.6 Validity. Check according to RFC 5280.
        self.validity.validate_at(now)?;

        // 4.7 Subject Public Key Info: limited algorithms.
        if !self.subject_public_key_info().allow_rpki_cert() {
            xerr!(return Err(ValidationError))
        }

        // 4.8.1. Basic Constraints. Differing requirements for CA and EE
        // certificates.

        // 4.8.2. Subject Key Identifier. Must be the SHA-1 hash of the octets
        // of the subjectPublicKey.
        if self.subject_key_identifier() !=
                             self.subject_public_key_info().key_identifier() {
            return Err(ValidationError)
        }

        // 4.8.3. Authority Key Identifier. Differing requirements of TA and
        // other certificates.

        // 4.8.4. Key Usage. Differs between CA and EE certificates.

        // 4.8.5. Extended Key Usage. Must not be present for the kind of
        // certificates we use here.
        if self.extended_key_usage().is_some() {
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

    fn inspect_issued(&self, _strict: bool) -> Result<(), ValidationError> {
        // 4.8.6. CRL Distribution Points. There must be one.
        if self.crl_uri().is_none() {
            return Err(ValidationError)
        }

        Ok(())
    }

    /// Validates that the certificate is a valid CA certificate.
    ///
    /// Checks the parts that are common in normal and trust anchor CA
    /// certificates.
    fn inspect_ca_basics(
        &self,
        _strict: bool
    ) -> Result<(), ValidationError> {
        // 4.8.1. Basic Constraints: For a CA it must be present (RFC6487)
        // und the “cA” flag must be set (RFC5280).
        if self.basic_ca() != Some(true) {
            return Err(ValidationError)
        }

        // 4.8.4. Key Usage. Bits for CA or not CA have been checked during
        // parsing already.
        if self.key_usage() != KeyUsage::Ca {
            return Err(ValidationError)
        }

        // 4.8.8.  Subject Information Access.
        if self.ca_repository().is_none() || self.rpki_manifest().is_none()
            || self.signed_object().is_some()
        {
            return Err(ValidationError)
        }

        Ok(())
    }

    /// Inspects a router certificate’s extended key usage.
    fn inspect_router_eku(
        &self, _strict: bool
    ) -> Result<(), ValidationError> {
        match self.extended_key_usage() {
            Some(captured) => {
                // We already know that the content is a sequence of OIDs
                // (that has been tested in take_extended_key_usage). So we
                // can return successfully as soon as we find our OID.
                let mut captured = captured.clone();
                while let Some(oid) = captured.decode_partial(|cons| {
                    Oid::take_opt_from(cons)
                })? {
                    if oid == oid::KP_BGPSEC_ROUTER {
                        return Ok(())
                    }
                }
                Err(ValidationError)
            }
            None => Err(ValidationError)
        }
    }

    /// Verifies that the certificate claims to have been issued by `issuer`.
    ///
    /// This is only the first part of verification. You _must_ call
    /// `verified_signature`, too.
    pub fn verify_issuer_claim(
        &self,
        issuer: &ResourceCert,
        _strict: bool,
    ) -> Result<(), ValidationError> {
        // 4.8.3. Authority Key Identifier. Must be present and match the
        // subject key ID of `issuer`.
        if self.authority_key_identifier()
            != Some(issuer.cert.subject_key_identifier())
        {
            return Err(ValidationError)
        }

        // 4.8.7. Authority Information Access. Must be present and contain
        // the URI of the issuer certificate. Since we do top-down validation,
        // we don’t really need that URI so – XXX – leave it unchecked for
        // now.
        if self.ca_issuer().is_none() {
            return Err(ValidationError);
        }

        Ok(())
    }

    /// Validates the certificate’s signature.
    pub fn verify_signature(
        &self,
        issuer: &Cert,
        _strict: bool
    ) -> Result<(), ValidationError> {
        self.signed_data.verify_signature(
            issuer.subject_public_key_info()
        )
    }

    /// Validates and extracts the IP and AS resources.
    ///
    /// Upon success, this converts the certificate into a `ResourceCert`.
    fn verify_resources(
        self,
        issuer: &ResourceCert,
        _strict: bool
    ) -> Result<ResourceCert, ValidationError> {
        Ok(ResourceCert {
            // 4.8.10.  IP Resources. If present, must be encompassed by or
            // trimmed down to the issuer certificate.
            v4_resources: issuer.v4_resources.validate_issued(
                self.v4_resources(), self.overclaim
            )?,
            v6_resources: issuer.v6_resources.validate_issued(
                self.v6_resources(), self.overclaim
            )?,
            // 4.8.11.  AS Resources. If present, must be encompassed by or
            // trimmed down to the issuer.
            as_resources: issuer.as_resources.validate_issued(
                self.as_resources(), self.overclaim()
            )?,
            cert: self,
            tal: issuer.tal.clone(),
        })
    }

    /// Validates the AS resources for router certificates.
    fn verify_as_resources(
        &self,
        issuer: &ResourceCert,
        _strict: bool
    ) -> Result<(), ValidationError> {
        let _ = issuer.as_resources.validate_issued(
            self.as_resources(), self.overclaim()
        )?;
        Ok(())
    }
}


//--- Deref, AsRef, and Borrow

impl ops::Deref for Cert {
    type Target = TbsCert;

    fn deref(&self) -> &Self::Target {
        &self.tbs
    }
}

impl AsRef<Cert> for Cert {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<TbsCert> for Cert {
    fn as_ref(&self) -> &TbsCert {
        &self.tbs
    }
}

impl borrow::Borrow<TbsCert> for Cert {
    fn borrow(&self) -> &TbsCert {
        &self.tbs
    }
}


//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for Cert {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let bytes = self.to_captured().into_bytes();
        let b64 = base64::encode(&bytes);
        b64.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Cert {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        let string = String::deserialize(deserializer)?;
        let decoded = base64::decode(&string).map_err(de::Error::custom)?;
        let bytes = Bytes::from(decoded);
        Cert::decode(bytes).map_err(de::Error::custom)
    }
}


//------------ TbsCert -------------------------------------------------------

/// The data of a resource certificate.
#[derive(Clone, Debug)]
pub struct TbsCert {
    /// The serial number.
    serial_number: Serial,

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
    subject_public_key_info: PublicKey,

    /// Basic Constraints extension.
    ///
    /// The field indicates whether the extension is present and, if so,
    /// whether the "cA" boolean is set. See 4.8.1. of RFC 6487.
    basic_ca: Option<bool>,

    /// Subject Key Identifier extension.
    subject_key_identifier: KeyIdentifier,

    /// Authority Key Identifier extension.
    authority_key_identifier: Option<KeyIdentifier>,

    /// Key Usage.
    ///
    key_usage: KeyUsage,

    /// Extended Key Usage.
    ///
    /// The value is the content of the DER-encoded sequence of object
    /// identifiers.
    extended_key_usage: Option<Captured>,

    // The following fields are lists of URIs. Each has to have at least one
    // rsync or HTTPS URI but may contain more. We only support those primary
    // URIs for now, so we don’t keep the full list but only the one URI we
    // need.

    /// CRL Distribution Points.
    crl_uri: Option<uri::Rsync>,

    /// Authority Information Access of type `id-ad-caIssuer`.
    ca_issuer: Option<uri::Rsync>,

    /// Subject Information Access of type `id-ad-caRepository`
    ca_repository: Option<uri::Rsync>,

    /// Subject Information Access of type `id-ad-rpkiManifest`
    rpki_manifest: Option<uri::Rsync>,

    /// Subject Information Access of type `id-ad-signedObject`
    signed_object: Option<uri::Rsync>,

    /// Subject Information Access of type `id-ad-rpkiNotify`
    rpki_notify: Option<uri::Https>,

    /// Certificate Policies
    ///
    /// Must be present and critical. RFC 6484 demands there to be a single
    /// policy with a specific OID and no parameters. RFC 8630 adds a second
    /// OID for a different way of handling overclaim of resources.
    ///
    /// We reflect this choice of policy with an overclaim mode.
    overclaim: Overclaim,

    /// IP Resources for the IPv4 address family.
    v4_resources: IpResources,

    /// IP Resources for the IPv6 address family.
    v6_resources: IpResources,

    /// AS Resources
    as_resources: AsResources,
}


/// # Creation and Conversion
///
impl TbsCert {
    /// Creates a new value from the necessary data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        serial_number: Serial,
        issuer: Name,
        validity: Validity,
        subject: Option<Name>,
        subject_public_key_info: PublicKey,
        key_usage: KeyUsage,
        overclaim: Overclaim,
    ) -> Self {
        Self {
            serial_number,
            signature: SignatureAlgorithm::default(),
            issuer,
            validity,
            subject: {
                subject.unwrap_or_else(||
                    subject_public_key_info.to_subject_name()
                )
            },
            subject_key_identifier: subject_public_key_info.key_identifier(),
            subject_public_key_info,
            basic_ca: None,
            authority_key_identifier: None,
            key_usage,
            extended_key_usage: None,
            crl_uri: None,
            ca_issuer: None,
            ca_repository: None,
            rpki_manifest: None,
            signed_object: None,
            rpki_notify: None,
            overclaim,
            v4_resources: IpResources::missing(),
            v6_resources: IpResources::missing(),
            as_resources: AsResources::missing(),
        }
    }

    /// Converts the value into a signed certificate.
    pub fn into_cert<S: Signer>(
        self,
        signer: &S,
        key: &S::KeyId,
    ) -> Result<Cert, SigningError<S::Error>> {
        let data = Captured::from_values(Mode::Der, self.encode_ref());
        let signature = signer.sign(key, self.signature, &data)?;
        Ok(Cert {
            signed_data: SignedData::new(data, signature),
            tbs: self
        })
    }
}


/// # Data Access
///
impl TbsCert {
    /// Returns the serial number of the certificate.
    pub fn serial_number(&self) -> Serial {
        self.serial_number
    }

    /// Set the serial number of the certificate.
    pub fn set_serial_number<S: Into<Serial>>(&mut self, serial: S) {
        self.serial_number = serial.into()
    }

    /// Returns a reference to the issuer.
    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    /// Sets the issuer.
    pub fn set_issuer(&mut self, name: Name) {
        self.issuer = name
    }

    /// Returns a reference to the validity.
    pub fn validity(&self) -> Validity {
        self.validity
    }

    /// Sets the validity.
    pub fn set_validity(&mut self, validity: Validity) {
        self.validity = validity
    }

    /// Returns a reference to the subject.
    pub fn subject(&self) -> &Name {
        &self.subject
    }

    /// Sets the subject.
    pub fn set_subject(&mut self, subject: Name) {
        self.subject = subject
    }

    /// Returns a reference to the public key.
    pub fn subject_public_key_info(&self) -> &PublicKey {
        &self.subject_public_key_info
    }

    /// Sets the public key.
    ///
    /// This sets both the value of the `subject_public_key_info` field to
    /// the public key itself as well as the `subject_public_key_identifier`
    /// to the identifier of that key.
    pub fn set_subject_public_key(&mut self, key: PublicKey) {
        self.subject_key_identifier = key.key_identifier();
        self.subject_public_key_info = key;
    }

    /// Returns the cA field of the basic constraints extension if present.
    pub fn basic_ca(&self) -> Option<bool> {
        self.basic_ca
    }

    /// Sets the basic constraints extension.
    ///
    /// If `value` is `None`, the extension will be absent. If it is some
    /// value, the boolean is the value of the `cA` field of the extension.
    pub fn set_basic_ca(&mut self, value: Option<bool>) {
        self.basic_ca = value
    }

    /// Returns a reference to the subject key identifier.
    ///
    /// There is no method to set this extension as this happens automatically
    /// when the subject public key is set via [`set_subject_public_key`].
    ///
    /// [`set_subject_public_key`]: #method.set_subject_public_key
    pub fn subject_key_identifier(&self) -> KeyIdentifier {
        self.subject_key_identifier
    }

    /// Returns a reference to the authority key identifier if present.
    pub fn authority_key_identifier(&self) -> Option<KeyIdentifier> {
        self.authority_key_identifier
    }

    /// Sets the authority key identifier extension.
    pub fn set_authority_key_identifier(
        &mut self,
        id: Option<KeyIdentifier>
    ) {
        self.authority_key_identifier = id
    }

    /// Returns the key usage of the certificate.
    pub fn key_usage(&self) -> KeyUsage {
        self.key_usage
    }

    /// Sets the key usage of the certificate.
    pub fn set_key_usage(&mut self, key_usage: KeyUsage) {
        self.key_usage = key_usage
    }

    /// Returns a reference to the extended key usage if present.
    ///
    /// Since this field isn’t allowed in any certificate used for RPKI
    /// objects directly, we do not currently support setting this field.
    pub fn extended_key_usage(&self) -> Option<&Captured> {
        self.extended_key_usage.as_ref()
    }

    /// Returns a reference to the certificate’s CRL distribution point.
    pub fn crl_uri(&self) -> Option<&uri::Rsync> {
        self.crl_uri.as_ref()
    }

    /// Sets the CRL distribution point.
    pub fn set_crl_uri(&mut self, uri: Option<uri::Rsync>) {
        self.crl_uri = uri
    }

    /// Returns a reference to *caIssuer* AIA rsync URI if present.
    pub fn ca_issuer(&self) -> Option<&uri::Rsync> {
        self.ca_issuer.as_ref()
    }

    /// Sets the *caIssuer* AIA rsync URI.
    pub fn set_ca_issuer(&mut self, uri: Option<uri::Rsync>) {
        self.ca_issuer= uri
    }

    /// Returns a reference to the *caRepository* SIA rsync URI if present.
    pub fn ca_repository(&self) -> Option<&uri::Rsync> {
        self.ca_repository.as_ref()
    }

    /// Sets the *caRepository* SIA rsync URI.
    pub fn set_ca_repository(&mut self, uri: Option<uri::Rsync>) {
        self.ca_repository = uri
    }

    /// Returns a reference to the *rpkiManifest* SIA rsync URI if present.
    pub fn rpki_manifest(&self) -> Option<&uri::Rsync> {
        self.rpki_manifest.as_ref()
    }

    /// Sets the *rpkiManifest* SIA rsync URI.
    pub fn set_rpki_manifest(&mut self, uri: Option<uri::Rsync>) {
        self.rpki_manifest = uri
    }

    /// Returns a reference to the *signedObject* SIA rsync URI if present.
    pub fn signed_object(&self) -> Option<&uri::Rsync> {
        self.signed_object.as_ref()
    }

    /// Sets the *signedObject* SIA rsync URI.
    pub fn set_signed_object(&mut self, uri: Option<uri::Rsync>) {
        self.signed_object = uri
    }

    /// Returns a reference to the *rpkiNotify* SIA HTTPS URI if present.
    pub fn rpki_notify(&self) -> Option<&uri::Https> {
        self.rpki_notify.as_ref()
    }

    /// Sets the *rpkiNotify* SIA HTTPS URI.
    pub fn set_rpki_notify(&mut self, uri: Option<uri::Https>) {
        self.rpki_notify = uri
    }

    /// Returns the overclaim mode of the certificate.
    pub fn overclaim(&self) -> Overclaim {
        self.overclaim
    }

    /// Sets the overclaim mode of the certificate.
    pub fn set_overclaim(&mut self, overclaim: Overclaim) {
        self.overclaim = overclaim
    }

    /// Returns a reference to the IPv4 address resources if present.
    pub fn v4_resources(&self) -> &IpResources {
        &self.v4_resources
    }

    /// Set the IPv4 address resources.
    pub fn set_v4_resources(&mut self, resources: IpResources) {
        self.v4_resources = resources
    }

    /// Sets the IPv4 address resources to inherit.
    pub fn set_v4_resources_inherit(&mut self) {
        self.set_v4_resources(IpResources::inherit())
    }

    /// Builds the blocks IPv4 address resources.
    pub fn build_v4_resource_blocks<F>(&mut self, op: F)
    where F: FnOnce(&mut IpBlocksBuilder) {
        let mut builder = IpResourcesBuilder::new();
        builder.blocks(op);
        self.set_v4_resources(builder.finalize())
    }

    /// Builds the IPv4 address resources from an iterator over blocks.
    pub fn v4_resources_from_iter<I>(&mut self, iter: I)
    where I: IntoIterator<Item=IpBlock> {
        self.v4_resources = IpResources::blocks(IpBlocks::from_iter(iter))
    }

    /// Returns a reference to the IPv6 address resources if present.
    pub fn v6_resources(&self) -> &IpResources {
        &self.v6_resources
    }

    /// Set the IPv6 address resources.
    pub fn set_v6_resources(&mut self, resources: IpResources) {
        self.v6_resources = resources
    }

    /// Sets the IPv6 address resources to inherit.
    pub fn set_v6_resources_inherit(&mut self) {
        self.set_v6_resources(IpResources::inherit())
    }

    /// Builds the blocks IPv6 address resources.
    pub fn build_v6_resource_blocks<F>(&mut self, op: F)
    where F: FnOnce(&mut IpBlocksBuilder) {
        let mut builder = IpResourcesBuilder::new();
        builder.blocks(op);
        self.set_v6_resources(builder.finalize())
    }

    /// Builds the IPv6 address resources from an iterator over blocks
    pub fn v6_resources_from_iter<I>(&mut self, iter: I)
    where I: IntoIterator<Item=IpBlock> {
        self.v6_resources = IpResources::blocks(IpBlocks::from_iter(iter))
    }

    /// Returns whether the certificate has any IP resources at all.
    pub fn has_ip_resources(&self) -> bool {
        self.v4_resources.is_present() || self.v6_resources().is_present()
    }

    /// Returns a reference to the AS resources.
    pub fn as_resources(&self) -> &AsResources {
        &self.as_resources
    }

    /// Set the AS resources.
    pub fn set_as_resources(&mut self, resources: AsResources) {
        self.as_resources = resources
    }

    /// Sets the AS resources to inherit.
    pub fn set_as_resources_inherit(&mut self) {
        self.set_as_resources(AsResources::inherit())
    }

    /// Builds the blocks AS resources.
    pub fn build_as_resource_blocks<F>(&mut self, op: F)
    where F: FnOnce(&mut AsBlocksBuilder) {
        let mut builder = AsResourcesBuilder::new();
        builder.blocks(op);
        self.set_as_resources(builder.finalize())
    }

    /// Builds the AS resources from an iterator over blocks.
    pub fn as_resources_from_iter<I>(&mut self, iter: I)
    where I: IntoIterator<Item = AsBlock> {
        self.as_resources = AsResources::blocks(AsBlocks::from_iter(iter))
    }

    /// Returns whether this is a CA certificate if validation succeeds.
    pub fn is_ca(&self) -> bool {
        self.basic_ca.unwrap_or(false)
    }

    /// Returns whether this is a self-signed certificate if valid.
    pub fn is_self_signed(&self) -> bool {
        match self.authority_key_identifier {
            Some(aki) => aki == self.subject_key_identifier,
            None => true
        }
    }
}


/// # Decoding and Encoding
///
impl TbsCert {
    /// Parses the content of a Certificate sequence.
    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            // version [0] EXPLICIT Version DEFAULT v1.
            //  -- we need extensions so apparently, we want v3 which,
            //     confusingly, is 2.
            cons.take_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(2))?;

            let serial_number = Serial::take_from(cons)?;
            let signature = SignatureAlgorithm::x509_take_from(cons)?;
            let issuer = Name::take_from(cons)?;
            let validity = Validity::take_from(cons)?;
            let subject = Name::take_from(cons)?;
            let subject_public_key_info = PublicKey::take_from(cons)?;


            // issuerUniqueID and subjectUniqueID must not be present in
            // resource certificates. So extension is next.

            let mut basic_ca = None;
            let mut subject_key_id = None;
            let mut authority_key_id = None;
            let mut key_usage = None;
            let mut extended_key_usage = None;
            let mut crl_uri = None;
            let mut ca_issuer = None;
            let mut sia = None;
            let mut overclaim = None;
            let mut ip_resources = None;
            let mut ip_overclaim = None;
            let mut as_resources = None;
            let mut as_overclaim = None;

            cons.take_constructed_if(Tag::CTX_3, |c| c.take_sequence(|cons| {
                while let Some(()) = cons.take_opt_sequence(|cons| {
                    let id = Oid::take_from(cons)?;
                    let critical = cons.take_opt_bool()?.unwrap_or(false);
                    let value = OctetString::take_from(cons)?;
                    Mode::Der.decode(value.to_source(), |content| {
                        if id == oid::CE_BASIC_CONSTRAINTS {
                            Self::take_basic_constraints(
                                content, &mut basic_ca
                            )
                        } else if id == oid::CE_SUBJECT_KEY_IDENTIFIER {
                            Self::take_subject_key_identifier(
                                content, &mut subject_key_id
                            )
                        } else if id == oid::CE_AUTHORITY_KEY_IDENTIFIER {
                            Self::take_authority_key_identifier(
                                content, &mut authority_key_id
                            )
                        } else if id == oid::CE_KEY_USAGE {
                            Self::take_key_usage(
                                content, &mut key_usage
                            )
                        } else if id == oid::CE_EXTENDED_KEY_USAGE {
                            Self::take_extended_key_usage(
                                content, &mut extended_key_usage
                            )
                        } else if id == oid::CE_CRL_DISTRIBUTION_POINTS {
                            Self::take_crl_distribution_points(
                                content, &mut crl_uri
                            )
                        } else if id == oid::PE_AUTHORITY_INFO_ACCESS {
                            Self::take_authority_info_access(
                                content, &mut ca_issuer
                            )
                        } else if id == oid::PE_SUBJECT_INFO_ACCESS {
                            Self::take_subject_info_access(
                                content, &mut sia
                            )
                        } else if id == oid::CE_CERTIFICATE_POLICIES {
                            Self::take_certificate_policies(
                                content, &mut overclaim
                            )
                        } else if let Some(m) = Overclaim::from_ip_res(&id) {
                            ip_overclaim = Some(m);
                            Self::take_ip_resources(content, &mut ip_resources)
                        } else if let Some(m) = Overclaim::from_as_res(&id) {
                            as_overclaim = Some(m);
                            Self::take_as_resources(content, &mut as_resources)
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
                })? { }
                Ok(())
            }))?;

            if ip_resources.is_none() && as_resources.is_none() {
                xerr!(return Err(decode::Malformed.into()))
            }
            if ip_resources.is_some() && ip_overclaim != overclaim {
                xerr!(return Err(decode::Malformed.into()))
            }
            if as_resources.is_some() && as_overclaim != overclaim {
                xerr!(return Err(decode::Malformed.into()))
            }
            let (v4_resources, v6_resources) = match ip_resources {
                Some(res) => res,
                None => (None, None)
            };
            let (ca_repository, rpki_manifest, signed_object, rpki_notify) = {
                match sia {
                    Some(sia) => (
                        sia.ca_repository, sia.rpki_manifest,
                        sia.signed_object, sia.rpki_notify
                    ),
                    None => (None, None, None, None)
                }
            };

            Ok(Self {
                serial_number,
                signature,
                issuer,
                validity,
                subject,
                subject_public_key_info,
                basic_ca,
                subject_key_identifier:
                    subject_key_id.ok_or(decode::Malformed)?,
                authority_key_identifier: authority_key_id,
                key_usage: key_usage.ok_or(decode::Malformed)?,
                extended_key_usage,
                crl_uri,
                ca_issuer,
                ca_repository,
                rpki_manifest,
                signed_object,
                rpki_notify,
                overclaim: overclaim.ok_or(decode::Malformed)?,
                v4_resources: v4_resources.unwrap_or_else(
                    IpResources::missing
                ),
                v6_resources: v6_resources.unwrap_or_else(
                    IpResources::missing
                ),
                as_resources: as_resources.unwrap_or_else(
                    AsResources::missing
                ),
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
    pub(crate) fn take_subject_key_identifier<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        subject_key_id: &mut Option<KeyIdentifier>,
    ) -> Result<(), S::Err> {
        update_once(subject_key_id, || KeyIdentifier::take_from(cons))
    }

    /// Parses the Authority Key Identifier extension.
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
    pub(crate) fn take_authority_key_identifier<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        authority_key_id: &mut Option<KeyIdentifier>,
    ) -> Result<(), S::Err> {
        update_once(authority_key_id, || {
            cons.take_sequence(|cons| {
                cons.take_value_if(Tag::CTX_0, KeyIdentifier::from_content)
            })
        })
    }

    /// Parses the Key Usage extension.
    ///
    /// ```text
    /// KeyUsage ::= BIT STRING {
    ///      digitalSignature        (0),
    ///      nonRepudiation          (1), -- recent editions of X.509 have
    ///                           -- renamed this bit to contentCommitment
    ///      keyEncipherment         (2),
    ///      dataEncipherment        (3),
    ///      keyAgreement            (4),
    ///      keyCertSign             (5),
    ///      cRLSign                 (6),
    ///      encipherOnly            (7),
    ///      decipherOnly            (8) }
    ///
    /// Must be present. In CA certificates, keyCertSign and
    /// CRLSign must be set, in EE certificates, digitalSignatures must be
    /// set.
    pub(crate) fn take_key_usage<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        key_usage: &mut Option<KeyUsage>
    ) -> Result<(), S::Err> {
        update_once(key_usage, || {
            let bits = BitString::take_from(cons)?;
            if bits.bit(5) && bits.bit(6) {
                Ok(KeyUsage::Ca)
            }
            else if bits.bit(0) {
                Ok(KeyUsage::Ee)
            }
            else {
                Err(decode::Malformed.into())
            }
        })
    }

    /// Parses the Extended Key Usage extension.
    ///
    /// ```text
    /// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
    /// KeyPurposeId ::= OBJECT IDENTIFIER
    /// ```
    ///
    /// May only be present in EE certificates issued to devices.
    pub(crate) fn take_extended_key_usage<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        extended_key_usage: &mut Option<Captured>
    ) -> Result<(), S::Err> {
        update_once(extended_key_usage, || {
            let res = cons.take_sequence(|c| c.capture_all())?;
            res.clone().decode(|cons| {
                Oid::skip_in(cons)?;
                while Oid::skip_opt_in(cons)?.is_some() { }
                Ok(res)
            }).map_err(Into::into)
        })
    }

    /// Parses the CRL Distribution Points extension.
    ///
    /// ```text
    /// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
    ///
    /// DistributionPoint ::= SEQUENCE {
    ///    distributionPoint       [0]     DistributionPointName OPTIONAL,
    ///    reasons                 [1]     ReasonFlags OPTIONAL,
    ///    cRLIssuer               [2]     GeneralNames OPTIONAL }
    ///
    /// DistributionPointName ::= CHOICE {
    ///    fullName                [0]     GeneralNames,
    ///    nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
    /// ```
    ///
    /// Must be present except in self-signed certificates.
    ///
    /// It must contain exactly one Distribution Point. Only its
    /// distributionPoint field must be present and it must contain
    /// the fullName choice which can be one or more uniformResourceIdentifier
    /// choices.
    fn take_crl_distribution_points<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        crl_uri: &mut Option<uri::Rsync>
    ) -> Result<(), S::Err> {
        update_once(crl_uri, || {
            // CRLDistributionPoints
            cons.take_sequence(|cons| {
                // DistributionPoint
                cons.take_sequence(|cons| {
                    // distributionPoint
                    cons.take_constructed_if(Tag::CTX_0, |cons| {
                        // fullName
                        cons.take_constructed_if(Tag::CTX_0, |cons| {
                            // GeneralNames content
                            take_general_names_content(
                                cons, uri::Rsync::from_bytes
                            )
                        })
                    })
                })
            })
        })
    }

    /// Parses the Authority Information Access extension.
    ///
    /// ```text
    /// AuthorityInfoAccessSyntax  ::=
    ///         SEQUENCE SIZE (1..MAX) OF AccessDescription
    ///
    /// AccessDescription  ::=  SEQUENCE {
    ///         accessMethod          OBJECT IDENTIFIER,
    ///         accessLocation        GeneralName  }
    /// ```
    ///
    /// Must be present except in self-signed certificates. Must contain
    /// exactly one entry with accessMethod id-ad-caIssuers and URIs in the
    /// generalName. There must be one rsync URI, there may be more. We only
    /// support the one, though, so we’ll ignore the rest.
    fn take_authority_info_access<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        ca_issuer: &mut Option<uri::Rsync>
    ) -> Result<(), S::Err> {
        update_once(ca_issuer, || {
            cons.take_sequence(|cons| {
                cons.take_sequence(|cons| {
                    oid::AD_CA_ISSUERS.skip_if(cons)?;
                    take_general_names_content(cons, uri::Rsync::from_bytes)
                })
            })
        })
    }

    /// Parses the Subject Information Access extension.
    ///
    /// ```text
    /// SubjectInfoAccessSyntax  ::=
    ///         SEQUENCE SIZE (1..MAX) OF AccessDescription
    ///
    /// AccessDescription  ::=  SEQUENCE {
    ///         accessMethod          OBJECT IDENTIFIER,
    ///         accessLocation        GeneralName  }
    /// ```
    ///
    /// Must be present.
    ///
    /// For CA certificates, there must be two AccessDescriptions, one with
    /// id-ad-caRepository and one with id-ad-rpkiManifest, both with rsync
    /// URIs. Additional id-ad-rpkiManifest descriptions may be present with
    /// additional access mechanisms for the manifest.
    ///
    /// Additionally, an id-ad-rpkiNotify may be present with a HTTPS URI.
    ///
    /// For EE certificates, there must at least one AccessDescription value
    /// with an id-ad-signedObject access method.
    ///
    /// Since we don’t necessarily know what kind of certificate we have yet,
    /// we may accept the wrong kind here. This needs to be checked later.
    pub(crate) fn take_subject_info_access<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        sia: &mut Option<Sia>,
    ) -> Result<(), S::Err> {
        update_once(sia, || {
            let mut sia = Sia::default();
            let mut others_seen = false;
            cons.take_sequence(|cons| {
                while let Some(()) = cons.take_opt_sequence(|cons| {
                    let oid = Oid::take_from(cons)?;
                    if oid == oid::AD_CA_REPOSITORY {
                        update_first(&mut sia.ca_repository, || {
                            take_general_name(
                                cons, uri::Rsync::from_bytes
                            )
                        })
                    }
                    else if oid == oid::AD_RPKI_MANIFEST {
                        update_first(&mut sia.rpki_manifest, || {
                            take_general_name(
                                cons, uri::Rsync::from_bytes
                            )
                        })
                    }
                    else if oid == oid::AD_SIGNED_OBJECT {
                        update_first(&mut sia.signed_object, || {
                            take_general_name(
                                cons, uri::Rsync::from_bytes
                            )
                        })
                    }
                    else if oid == oid::AD_RPKI_NOTIFY {
                        update_first(&mut sia.rpki_notify, || {
                            take_general_name(
                                cons, uri::Https::from_bytes
                            )
                        })
                    }
                    else {
                        others_seen = true;
                        // XXX Presumably it is fine to just skip over these
                        //     things. Since this is DER, it can’t be tricked
                        //     into reading forever.
                        cons.skip_all()
                    }
                })? { }
                Ok(())
            })?;
            Ok(sia)
        })
    }

    /// Parses the Certificate Policies extension.
    ///
    /// ```text
    /// certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
    ///
    /// PolicyInformation ::= SEQUENCE {
    ///     policyIdentifier   CertPolicyId,
    ///     policyQualifiers   SEQUENCE SIZE (1..MAX) OF
    ///                             PolicyQualifierInfo OPTIONAL }
    ///
    /// CertPolicyId ::= OBJECT IDENTIFIER
    ///
    /// [...]
    /// ```
    ///
    /// Must be present. There are two policyIdentifiers for resource
    /// certificates. They define how we deal with overclaim of resources.
    /// The policyQualifiers are not interesting for us.
    fn take_certificate_policies<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        overclaim: &mut Option<Overclaim>,
    ) -> Result<(), S::Err> {
        update_once(overclaim, || {
            cons.take_sequence(|cons| {
                cons.take_sequence(|cons| {
                    let res = Overclaim::from_policy(&Oid::take_from(cons)?)?;
                    // policyQualifiers. This is a sequence of sequences with
                    // stuff we don’t really care about. Let’s skip all the
                    // rest.
                    cons.skip_all()?;
                    Ok(res)
                })
            })
        })
    }

    /// Parses the IP Resources extension.
    fn take_ip_resources<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        ip_resources: &mut Option<(Option<IpResources>, Option<IpResources>)>
    ) -> Result<(), S::Err> {
        update_once(ip_resources, || IpResources::take_families_from(cons))
    }

    /// Parses the AS Resources extension.
    fn take_as_resources<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        as_resources: &mut Option<AsResources>
    ) -> Result<(), S::Err> {
        update_once(as_resources, || {
            AsResources::take_from(cons)
        })
    }

    /// Returns an encoder for the value.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            encode::sequence_as(Tag::CTX_0, 2.encode()), // version
            self.serial_number.encode(),
            self.signature.x509_encode(),
            self.issuer.encode_ref(),
            self.validity.encode(),
            self.subject.encode_ref(),
            self.subject_public_key_info.encode_ref(),
            // no issuerUniqueID
            // no subjectUniqueID
            // extensions
            encode::sequence_as(Tag::CTX_3, encode::sequence((
                // Basic Constraints
                self.basic_ca.map(|ca| {
                    encode_extension(
                        &oid::CE_BASIC_CONSTRAINTS, true,
                        encode::sequence(
                            if ca {
                                Some(ca.encode())
                            }
                            else {
                                None
                            }
                        )
                    )
                }),

                // Subject Key Identifier
                encode_extension(
                    &oid::CE_SUBJECT_KEY_IDENTIFIER, false,
                    self.subject_key_identifier.encode_ref(),
                ),

                // Authority Key Identifier
                self.authority_key_identifier.as_ref().map(|id| {
                    encode_extension(
                        &oid::CE_AUTHORITY_KEY_IDENTIFIER, false,
                        encode::sequence(id.encode_ref_as(Tag::CTX_0))
                    )
                }),

                // Key Usage
                encode_extension(
                    &oid::CE_KEY_USAGE, true,
                    self.key_usage.encode()
                ),

                // Extended Key Usage
                self.extended_key_usage.as_ref().map(|captured| {
                    encode_extension(
                        &oid::CE_EXTENDED_KEY_USAGE, false,
                        encode::sequence(captured)
                    )
                }),

                // CRL Distribution Points
                self.crl_uri.as_ref().map(|uri| {
                    encode_extension(
                        &oid::CE_CRL_DISTRIBUTION_POINTS, false,
                        encode::sequence( // CRLDistributionPoints
                            encode::sequence( // DistributionPoint
                                encode::sequence_as(Tag::CTX_0, // distrib.Pt.
                                    encode::sequence_as(Tag::CTX_0, // fullName
                                        uri.encode_general_name()
                                    )
                                )
                            )
                        )
                    )
                }),

                // Authority Information Access
                self.ca_issuer.as_ref().map(|uri| {
                    encode_extension(
                    &oid::PE_AUTHORITY_INFO_ACCESS, false,
                        encode::sequence(
                            encode::sequence((
                                oid::AD_CA_ISSUERS.encode(),
                                uri.encode_general_name()
                            ))
                        )
                    )
                }),

                // Subject Information Access
                encode_extension(
                    &oid::PE_SUBJECT_INFO_ACCESS, false,
                    encode::sequence((
                        self.ca_repository.as_ref().map(|uri| {
                            encode::sequence((
                                oid::AD_CA_REPOSITORY.encode(),
                                uri.encode_general_name()
                            ))
                        }),
                        self.rpki_manifest.as_ref().map(|uri| {
                            encode::sequence((
                                oid::AD_RPKI_MANIFEST.encode(),
                                uri.encode_general_name()
                            ))
                        }),
                        self.signed_object.as_ref().map(|uri| {
                            encode::sequence((
                                oid::AD_SIGNED_OBJECT.encode(),
                                uri.encode_general_name()
                            ))
                        }),
                        self.rpki_notify.as_ref().map(|uri| {
                            encode::sequence((
                                oid::AD_RPKI_NOTIFY.encode(),
                                uri.encode_general_name()
                            ))
                        })
                    ))
                ),

                // Certificate Policies
                encode_extension(
                    &oid::CE_CERTIFICATE_POLICIES, true,
                    encode::sequence(
                        encode::sequence(
                            self.overclaim.policy_id().encode()
                            // policyQualifiers sequence is optional
                        )
                    )
                ),

                // IP Resources
                IpResources::encode_extension(
                    self.overclaim(),
                    self.v4_resources(),
                    self.v6_resources()
                ),

                // AS Resources
                self.as_resources.encode_extension(self.overclaim)
            )))
        ))
    }
}


//------------ Helpers for Decoding and Encoding -----------------------------

/// Parses a URI from the content of a GeneralNames sequence.
///
/// ```text
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
///
/// GeneralName ::= CHOICE {
///    ...
///    uniformResourceIdentifier       [6]     IA5String,
///    ... }
/// ```
///
/// Takes the first name for which the closure returns successfully. Ignores
/// values where the closure produces an error. If there is more than one case
/// where the closure returns successfully, that’s an error, too.
fn take_general_names_content<S: decode::Source, F, T, E>(
    cons: &mut decode::Constructed<S>,
    mut op: F
) -> Result<T, S::Err>
where F: FnMut(Bytes) -> Result<T, E> {
    let mut res = None;
    while let Some(()) = cons.take_opt_value_if(Tag::CTX_6, |content| {
        let uri = Ia5String::from_content(content)?;
        if let Ok(uri) = op(uri.into_bytes()) {
            if res.is_some() {
                xerr!(return Err(decode::Malformed.into()))
            }
            res = Some(uri)
        }
        Ok(())
    })? {}
    match res {
        Some(res) => Ok(res),
        None => xerr!(Err(decode::Malformed.into()))
    }
}

fn take_general_name<S: decode::Source, F, T, E>(
    cons: &mut decode::Constructed<S>,
    mut op: F
) -> Result<Option<T>, S::Err>
where F: FnMut(Bytes) -> Result<T, E> {
    cons.take_value_if(Tag::CTX_6, |content| {
        Ia5String::from_content(content).map(|uri| {
            op(uri.into_bytes()).ok()
        })
    })
}

/// Internal helper type for parsing Subject Information Access.
#[derive(Clone, Debug, Default)]
pub(crate) struct Sia {
    ca_repository: Option<uri::Rsync>,
    rpki_manifest: Option<uri::Rsync>,
    signed_object: Option<uri::Rsync>,
    rpki_notify: Option<uri::Https>,
}

impl Sia {
    pub(crate) fn ca_repository(&self) -> Option<&uri::Rsync> {
        self.ca_repository.as_ref()
    }
    pub(crate) fn rpki_manifest(&self) -> Option<&uri::Rsync> {
        self.rpki_manifest.as_ref()
    }
    pub(crate) fn rpki_notify(&self) -> Option<&uri::Https> {
        self.rpki_notify.as_ref()
    }
}


//------------ CertBuilder ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct CertBuilder {
    //  The following lists how all the parts to go into the final certificate
    //  are to be generated. It also mentions all the parts that don’t need to
    //  be stored in the builder.

    //--- Certificate
    //
    //  tbsCertificate: see below,
    //  signatureAlgorithm and signature: generated when signing the final
    //     certificate

    //--- TBSCertificate

    //  Version.
    //
    //  This is always present and v3, which really is 2.

    /// Serial number.
    ///
    /// This is required for all certificates. The standard demands twenty
    /// digits, u128 gives us 38, so this should be fine.
    serial_number: u128,

    /// Signature.
    ///
    /// This is the signature algorithm and must be identical to the one used
    /// on the outer value. Thus, it needs to be set when constructing the
    /// certificate for signing.

    /// Issuer.
    ///
    /// This needs to be identical to the subject of the issuing certificate.
    /// It needs to be presented when creating the builder.
    issuer: Name,    

    /// Validity.
    ///
    /// This needs to be present for all certificates.
    validity: Validity,

    /// Subject.
    ///
    /// This needs to be present for all certifications. In RPKI, we commonly
    /// derive the name from the public key of the certificate, so this is an
    /// option. If it is not set explicitly, we derive the name.
    subject: Option<Name>, // XXX NameBuilder?

    /// Subject Public Key Info
    ///
    /// This is required for all certificates. However, because we sometimes
    /// use one-off certificates that only receive their key info very late
    /// in the process, we won’t store the key info but take it as an
    /// argument for encoding.

    //  Issuer Unique ID, Subject Unique ID
    //
    //  These must not be present.

    //--- Extensions

    /// Basic Constraints
    ///
    /// Needs to be present and critical and the cA boolean set to true for
    /// a CA and TA certificate. We simply remember whether we are making a
    /// CA certificate here.
    ca: bool,

    //  Subject Key Identifier
    //
    //  Must be present and non-critical. It is the SHA1 of the BIT STRING
    //  of the Subject Public Key, so we take it from
    //  subject_public_key_info.

    /// Authority Key Identifier
    ///
    /// Must be present except in trust-anchor certificates and non-critical.
    /// It must contain the subject key identifier of issuing certificate.
    authority_key_identifier: Option<OctetString>, 

    //  Key Usage.
    //
    //  Must be present and critical. For CA certificates, keyCertSign and
    //  CRLSign are set, for EE certificates, digitalSignature bit is set.

    //  Extended Key Usage
    //
    //  This is only allowed in router keys. For now, we will not support
    //  this.
    
    /// CRL Distribution Points
    ///
    /// Must be present and non-critical except in self-signed certificates.
    /// For RPKI it is very restricted and boils down to a list of URIs. Most
    /// likely, it will be exactly one. So for now, we allow at most one.
    crl_distribution: Option<uri::Rsync>,

    /// Authority Information Access
    ///
    /// Except for self-signed certificates, must be present and non-critical.
    /// There must be one rsync URI as a id-ad-caIssuer. Additional URIs may
    /// be present, but we don’t support that as of now.
    authority_info_access: Option<uri::Rsync>,

    //  Subject Information Access
    // 
    //  Must be present and non-critical. There are essentially three
    //  access methods that may be present. id-ad-rpkiManifest points to the
    //  manifest of a CA, id-ad-signedObject points to the signed object of
    //  an EE certificate. id-ad-rpkiNotify points to the RRDP notification
    //  file of a CA. We only support one of each and simply add whatever is
    //  there.

    /// Subject Information Access of type `id-ad-caRepository`
    ca_repository: Option<uri::Rsync>,

    /// Subject Information Access of type `id-ad-rpkiManifest`
    rpki_manifest: Option<uri::Rsync>,

    /// Subject Information Access of type `id-ad-signedObject`
    signed_object: Option<uri::Rsync>,

    /// Subject Information Access of type `id-ad-rpkiNotify`
    rpki_notify: Option<uri::Https>,

    /// Certificate Policies
    ///
    /// This is chosen via the value of the overclaim mode,
    overclaim: Overclaim,

    /// IPv4 Resources
    ///
    /// One of the resources must be present. The IPv4 resources are part of
    /// the IP resources which, if present, it must be critical.
    v4_resources: IpResourcesBuilder,

    /// IPv6 Resources
    ///
    /// One of the resources must be present. The IPv4 resources are part of
    /// the IP resources which, if present, it must be critical.
    v6_resources: IpResourcesBuilder,

    /// AS Resources
    ///
    /// If present, it must be critical. One of the resources must be
    /// present.
    as_resources: AsResourcesBuilder,
}

impl CertBuilder {
    pub fn new(
        serial_number: u128,
        issuer: Name,
        validity: Validity,
        ca: bool
    ) -> Self {
        CertBuilder {
            serial_number,
            issuer,
            validity,
            subject: None,
            ca,
            authority_key_identifier: None,
            crl_distribution: None,
            authority_info_access: None,
            ca_repository: None,
            rpki_manifest: None,
            signed_object: None,
            rpki_notify: None,
            overclaim: Overclaim::Refuse,
            v4_resources: IpResourcesBuilder::new(),
            v6_resources: IpResourcesBuilder::new(),
            as_resources: AsResourcesBuilder::new(),
        }
    }

    pub fn subject(&mut self, name: Name) -> &mut Self {
        self.subject = Some(name);
        self
    }

    pub fn authority_key_identifier(
        &mut self, id: OctetString
    ) -> &mut Self {
        self.authority_key_identifier = Some(id);
        self
    }

    pub fn crl_distribution(&mut self, uri: uri::Rsync) -> &mut Self {
        self.crl_distribution = Some(uri);
        self
    }

    pub fn authority_info_access(&mut self, uri: uri::Rsync) -> &mut Self {
        self.authority_info_access = Some(uri);
        self
    }

    pub fn ca_repository(&mut self, uri: uri::Rsync) -> &mut Self {
        self.ca_repository = Some(uri);
        self
    }

    pub fn rpki_manifest(&mut self, uri: uri::Rsync) -> &mut Self {
        self.rpki_manifest = Some(uri);
        self
    }

    pub fn signed_object(&mut self, uri: uri::Rsync) -> &mut Self {
        self.signed_object = Some(uri);
        self
    }

    pub fn rpki_notify(&mut self, uri: uri::Https) -> &mut Self {
        self.rpki_notify = Some(uri);
        self
    }

    pub fn overclaim(&mut self, overclaim: Overclaim) -> &mut Self {
        self.overclaim = overclaim;
        self
    }

    pub fn inherit_v4(&mut self) -> &mut Self {
        self.v4_resources.inherit();
        self
    }

    pub fn inherit_v6(&mut self) -> &mut Self {
        self.v6_resources.inherit();
        self
    }

    pub fn inherit_as(&mut self) -> &mut Self {
        self.as_resources.inherit();
        self
    }

    pub fn v4_blocks<F>(&mut self, build: F) -> &mut Self
    where F: FnOnce(&mut IpBlocksBuilder) {
        self.v4_resources.blocks(build);
        self
    }

    pub fn v6_blocks<F>(&mut self, build: F) -> &mut Self
    where F: FnOnce(&mut IpBlocksBuilder) {
        self.v6_resources.blocks(build);
        self
    }

    pub fn as_blocks<F>(&mut self, build: F) -> &mut Self
    where F: FnOnce(&mut AsBlocksBuilder) {
        self.as_resources.blocks(build);
        self
    }
    
    /// Finalizes the certificate and returns an encoder for it.
    pub fn encode<S: Signer>(
        self,
        signer: &S,
        key: &S::KeyId,
        alg: SignatureAlgorithm,
        public_key: &PublicKey,
    ) -> Result<impl encode::Values, SigningError<S::Error>> {
        let tbs_cert = self.encode_tbs_cert(alg, public_key);
        let (alg, signature) = signer.sign(key, alg, &tbs_cert)?.unwrap();
        Ok(encode::sequence((
            tbs_cert,
            alg.x509_encode(),
            BitString::new(0, signature).encode()
        )))
    }

    fn encode_tbs_cert(
        mut self,
        alg: SignatureAlgorithm,
        public_key: &PublicKey,
    ) -> Captured {
        if self.subject.is_none() {
            self.subject = Some(Name::from_pub_key(public_key))
        }
        Captured::from_values(Mode::Der, encode::sequence((
            encode::sequence_as(Tag::CTX_0, 2.encode()), // version
            self.serial_number.encode(),
            alg.x509_encode(),
            self.issuer.encode_ref(),
            self.validity.encode(),
            match self.subject.as_ref() {
                Some(subject) => encode::Choice2::One(subject.encode_ref()),
                None => {
                    encode::Choice2::Two(
                        public_key.encode_subject_name()
                    )
                }
            },
            public_key.encode_ref(),
            // no issuerUniqueID, no subjectUniqueID
            encode::sequence_as(Tag::CTX_3, encode::sequence((
                // Basic Constraints
                if self.ca {
                    Some(Self::extension(
                        &oid::CE_BASIC_CONSTRAINTS, true,
                        encode::sequence(true.encode())
                    ))
                }
                else { None },

                // Subject Key Identifier
                Self::extension(
                    &oid::CE_SUBJECT_KEY_IDENTIFIER, false,
                    OctetString::encode_slice(
                        public_key.key_identifier()
                    )
                ),

                // Authority Key Identifier
                self.authority_key_identifier.as_ref().map(|id| {
                    Self::extension(
                        &oid::CE_AUTHORITY_KEY_IDENTIFIER, false,
                        encode::sequence(id.encode_ref_as(Tag::CTX_0))
                    )
                }),

                // Key Usage
                Self::extension(
                    &oid::CE_KEY_USAGE, true,
                    if self.ca {
                        // Bits 5 and 6 must be set.
                        b"\x01\x06".encode_as(Tag::BIT_STRING)
                    }
                    else {
                        // Bit 0 must be set.
                        b"\x07\x80".encode_as(Tag::BIT_STRING)
                    }
                ),

                // Extended Key Usage: currently not supported.

                // CRL Distribution Points
                self.crl_distribution.as_ref().map(|uri| {
                    Self::extension(
                        &oid::CE_CRL_DISTRIBUTION_POINTS, false,
                        encode::sequence( // CRLDistributionPoints
                            encode::sequence( // DistributionPoint
                                encode::sequence_as(Tag::CTX_0, // distrib.Pt.
                                    encode::sequence_as(Tag::CTX_0, // fullName
                                        encode::sequence( // GeneralNames
                                            uri.encode_general_name()
                                        )
                                    )
                                )
                            )
                        )
                    )
                }),

                // Authority Information Access
                self.authority_info_access.as_ref().map(|uri| {
                    Self::extension(
                        &oid::PE_AUTHORITY_INFO_ACCESS, false,
                        encode::sequence(
                            encode::sequence((
                                oid::AD_CA_ISSUERS.encode(),
                                uri.encode_general_name()
                            ))
                        )
                    )
                }),

                // Subject Information Access
                Self::extension(
                    &oid::PE_SUBJECT_INFO_ACCESS, false,
                    encode::sequence((
                        self.ca_repository.as_ref().map(|uri| {
                            encode::sequence((
                                oid::AD_CA_REPOSITORY.encode(),
                                uri.encode_general_name()
                            ))
                        }),
                        self.rpki_manifest.as_ref().map(|uri| {
                            encode::sequence((
                                oid::AD_RPKI_MANIFEST.encode(),
                                uri.encode_general_name()
                            ))
                        }),
                        self.signed_object.as_ref().map(|uri| {
                            encode::sequence((
                                oid::AD_SIGNED_OBJECT.encode(),
                                uri.encode_general_name()
                            ))
                        }),
                        self.rpki_notify.as_ref().map(|uri| {
                            encode::sequence((
                                oid::AD_RPKI_NOTIFY.encode(),
                                uri.encode_general_name()
                            ))
                        })
                    ))
                ),

                // Certificate Policies
                Self::extension(
                    &oid::CE_CERTIFICATE_POLICIES, true,
                    encode::sequence(
                        encode::sequence(
                            oid::CP_IPADDR_ASNUMBER.encode()
                        )
                    )
                ),

                // IP Resources
                IpResources::encode_extension(
                    self.overclaim,
                    &self.v4_resources.finalize(),
                    &self.v6_resources.finalize()
                ),

                // AS Resources
                self.as_resources.finalize().encode_extension(
                    self.overclaim
                ),
            )))
        )))
    }

    pub(crate) fn extension<V: encode::Values>(
        oid: &'static ConstOid,
        critical: bool,
        content: V
    ) -> impl encode::Values {
        encode::sequence((
            oid.encode(),
            critical.encode(),
            OctetString::encode_wrapped(Mode::Der, content)
        ))
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

    /// The resolved IPv4 resources.
    v4_resources: IpBlocks,

    /// The resolved IPv6 resources.
    v6_resources: IpBlocks,

    /// The resolved AS resources.
    as_resources: AsBlocks,

    /// The TAL this is based on.
    tal: Arc<TalInfo>,
}

impl ResourceCert {
    /// Returns a reference to the underlying certificate.
    pub fn as_cert(&self) -> &Cert {
        &self.cert
    }

    /// Returns a reference to the IPv4 resources of this certificate.
    pub fn v4_resources(&self) -> &IpBlocks {
        &self.v4_resources
    }

    /// Returns a reference to the IPv6 resources of this certificate.
    pub fn v6_resources(&self) -> &IpBlocks {
        &self.v6_resources
    }

    /// Returns a reference to the AS resources of this certificate.
    pub fn as_resources(&self) -> &AsBlocks {
        &self.as_resources
    }

    /// Returns information about the TAL this certificate is based on.
    pub fn tal(&self) -> &Arc<TalInfo> {
        &self.tal
    }

    /// Converts the certificate into its TAL info.
    pub fn into_tal(self) -> Arc<TalInfo> {
        self.tal
    }
}


//--- Deref and AsRef

impl ops::Deref for ResourceCert {
    type Target = Cert;

    fn deref(&self) -> &Cert {
        self.as_cert()
    }
}

impl AsRef<Cert> for ResourceCert {
    fn as_ref(&self) -> &Cert {
        self.as_cert()
    }
}

impl AsRef<TbsCert> for ResourceCert {
    fn as_ref(&self) -> &TbsCert {
        self.as_cert().as_ref()
    }
}


//------------ KeyUsage ------------------------------------------------------

/// The allowed key usages of a resource certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyUsage {
    /// A CA certificate.
    Ca,

    /// An end-entity certificate.
    Ee,
}

impl KeyUsage {
    /// Returns a value encoder for the key usage.
    pub fn encode(self) -> impl encode::Values {
        let s = match self {
            KeyUsage::Ca => b"\x01\x06", // Bits 5 and 6
            KeyUsage::Ee => b"\x07\x80", // Bit 0
        };
        s.encode_as(Tag::BIT_STRING)
    }
}


//------------ Overclaim -----------------------------------------------------

/// The overclaim mode for resource validation.
///
/// In the original RPKI specification, a certificate becomes valid if it
/// claims more resources than its issuer, a condition known as
/// ‘overclaiming’. [RFC 8360] proposed an alternative approach where in this
/// case the resources of the certificate are simply trimmed back to what the
/// issuer certificate allows. This makes handling cases where a CA loses some
/// resources easier.
///
/// A certificate can choose to use the old or new method by using different
/// OIDs for the certificate policy and the resource extensions.
///
/// This type specifies which mode a certificate uses.
///
/// [RFC 8380]: https://tools.ietf.org/html/rfc8360
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Overclaim {
    /// A certificate becomes invalid if it overclaims resources.
    Refuse,

    /// Overclaimed resources are trimmed to the by encompassed by the issuer.
    Trim,
}

impl Overclaim {
    fn from_policy(oid: &Oid) -> Result<Self, decode::Error> {
        if oid == &oid::CP_IPADDR_ASNUMBER {
            Ok(Overclaim::Refuse)
        }
        else if oid == &oid::CP_IPADDR_ASNUMBER_V2 {
            Ok(Overclaim::Trim)
        }
        else {
            xerr!(Err(decode::Malformed))
        }
    }

    fn from_ip_res(oid: &Oid) -> Option<Self> {
        if oid == &oid::PE_IP_ADDR_BLOCK {
            Some(Overclaim::Refuse)
        }
        else if oid == &oid::PE_IP_ADDR_BLOCK_V2 {
            Some(Overclaim::Trim)
        }
        else {
            None
        }
    }

    fn from_as_res(oid: &Oid) -> Option<Self> {
        if oid == &oid::PE_AUTONOMOUS_SYS_IDS {
            Some(Overclaim::Refuse)
        }
        else if oid == &oid::PE_AUTONOMOUS_SYS_IDS_V2 {
            Some(Overclaim::Trim)
        }
        else {
            None
        }
    }

    pub fn policy_id(self) -> &'static ConstOid {
        match self {
            Overclaim::Refuse => &oid::CP_IPADDR_ASNUMBER,
            Overclaim::Trim => &oid::CP_IPADDR_ASNUMBER_V2
        }
    }

    pub fn ip_res_id(self) -> &'static ConstOid {
        match self {
            Overclaim::Refuse => &oid::PE_IP_ADDR_BLOCK,
            Overclaim::Trim => &oid::PE_IP_ADDR_BLOCK_V2
        }
    }

    pub fn as_res_id(self) -> &'static ConstOid {
        match self {
            Overclaim::Refuse => &oid::PE_AUTONOMOUS_SYS_IDS,
            Overclaim::Trim => &oid::PE_AUTONOMOUS_SYS_IDS_V2
        }
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn decode_and_inspect_certs() {
        Cert::decode(
            include_bytes!("../../test-data/ta.cer").as_ref()
        ).unwrap().inspect_ta_at(
            true, Time::utc(2020, 11, 1, 12, 0, 0)
        ).unwrap();
        Cert::decode(
            include_bytes!("../../test-data/ca1.cer").as_ref()
        ).unwrap().inspect_ca_at(
            true, Time::utc(2020, 5, 1, 12, 0, 0)
        ).unwrap();
        Cert::decode(
            include_bytes!("../../test-data/router.cer").as_ref()
        ).unwrap().inspect_router_at(
            true, Time::utc(2020, 11, 1, 12, 0, 0)
        ).unwrap();
    }

    /// Tests that inconsistent algorithm encoding fail validation.
    ///
    /// Specifically, tests that a certificate with different encoding of
    /// the signature algorithm parameters (NULL value v. not present) in
    /// the outer certificate structure and inside the TbsCertificate will
    /// be rejected during the inspection step.
    #[test]
    fn signature_algorithm_mismatch() {
        let roa = crate::repository::roa::Roa::decode(
            include_bytes!(
                "../../test-data/example-ripe.roa"
            ).as_ref(),
            false
        ).unwrap();
        assert!(
            roa.cert().inspect_ee_at(
                true, Time::utc(2020, 5, 1, 0, 0, 0)
            ).is_ok()
        );

        let mft = crate::repository::manifest::Manifest::decode(
            include_bytes!(
                "../../test-data/signature-alg-mismatch.mft"
            ).as_ref(),
            false
        ).unwrap();
        assert!(
            mft.cert().inspect_ee_at(
                true, Time::utc(2020, 5, 1, 0, 0, 0)
            ).is_err()
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_cert() {
        let der = include_bytes!("../../test-data/ta.cer");
        let cert = Cert::decode(Bytes::from_static(der)).unwrap();

        let serialize = serde_json::to_string(&cert).unwrap();
        let des_cert: Cert = serde_json::from_str(&serialize).unwrap();

        assert_eq!(cert.to_captured().into_bytes(), des_cert.to_captured().into_bytes());

    }
}

#[cfg(all(test, feature="softkeys"))]
mod signer_test {
    use std::str::FromStr;
    use crate::repository::cert::Cert;
    use crate::repository::crypto::PublicKeyFormat;
    use crate::repository::crypto::softsigner::OpenSslSigner;
    use crate::repository::resources::{Asn, Prefix};
    use crate::repository::tal::TalInfo;
    use super::*;


    #[test]
    fn build_ta_cert() {
        let signer = OpenSslSigner::new();
        let key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
        let pubkey = signer.get_key_info(&key).unwrap();
        let uri = uri::Rsync::from_str("rsync://example.com/m/p").unwrap();
        let mut cert = TbsCert::new(
            12u64.into(), pubkey.to_subject_name(),
            Validity::from_secs(86400), None, pubkey, KeyUsage::Ca,
            Overclaim::Trim
        );
        cert.set_basic_ca(Some(true));
        cert.set_ca_repository(Some(uri.clone()));
        cert.set_rpki_manifest(Some(uri));
        cert.build_v4_resource_blocks(|b| b.push(Prefix::new(0, 0)));
        cert.build_v6_resource_blocks(|b| b.push(Prefix::new(0, 0)));
        cert.build_as_resource_blocks(|b| b.push((Asn::MIN, Asn::MAX)));
        let cert = cert.into_cert(&signer, &key).unwrap().to_captured();
        let cert = Cert::decode(cert.as_slice()).unwrap();
        let talinfo = TalInfo::from_name("foo".into()).into_arc();
        cert.validate_ta(talinfo, true).unwrap();
    }
}


