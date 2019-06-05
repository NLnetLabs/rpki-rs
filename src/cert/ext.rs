//! X509 Extensions

use std::fmt;
use bcder::{decode, encode};
use bcder::{
    BitString, Captured, ConstOid, Mode, OctetString, Oid, Tag, Unsigned,
    xerr
};
use bcder::encode::PrimitiveContent;
use bytes::Bytes;
use crate::crypto::PublicKey;
use crate::oid;
use crate::resources::{AsResources, IpResources};
use crate::uri;
use crate::x509::update_once;
use super::Overclaim;


//------------ Extensions ----------------------------------------------------

/// Extensions used in RPKI Certificates.
#[derive(Clone, Debug)]
pub struct Extensions {
    /// Basic Contraints.
    ///
    /// The field indicates whether the extension is present and, if so,
    /// whether the "cA" boolean is set. See 4.8.1. of RFC 6487.
    basic_ca: Option<BasicCa>,

    /// Subject Key Identifier.
    subject_key_id: SubjectKeyIdentifier,

    /// Authority Key Identifier
    authority_key_id: Option<AuthorityKeyIdentifier>,

    /// Key Usage.
    ///
    key_usage_ca: bool,

    /// Extended Key Usage.
    ///
    /// The value is the content of the DER-encoded sequence of object
    /// identifiers.
    extended_key_usage: Option<Captured>,

    /// CRL Distribution Points
    crl_distribution: Option<UriGeneralNames>,

    /// Authority Information Access
    authority_info_access: Option<UriGeneralName>,

    /// Subject Information Access
    ///
    /// This value contains the content of the SubjectInfoAccessSyntax
    /// sequence.
    subject_info_access: SubjectInfoAccess,

    /// Certificate Policies
    ///
    /// Must be present and critical. RFC 6484 demands there to be a single
    /// policy with a specific OID and no paramters. RFC 8630 adds a second
    /// OID for a different way of handling overclaim of resources.
    ///
    /// We reflect this choice of policy with an overclaim mode.
    overclaim: Overclaim,

    /// IP Resources for the IPv4 address family.
    v4_resources: Option<IpResources>,

    /// IP Resources for the IPv6 address family.
    v6_resources: Option<IpResources>,

    /// AS Resources
    as_resources: Option<AsResources>,
}


/// # Data Access
///
impl Extensions {
    pub fn basic_ca(&self) -> Option<bool> {
        match &self.basic_ca {
            Some(ca) => Some(ca.ca),
            None => None
        }
    }

    pub fn subject_key_id(&self) -> &OctetString {
        &self.subject_key_id.subject_key_id()
    }

    pub fn crl_distribution(&self) -> Option<&UriGeneralNames> {
        self.crl_distribution.as_ref()
    }

    pub fn authority_key_id(&self) -> Option<&OctetString> {
        match &self.authority_key_id {
            Some(a) => Some(a.authority_key_id()),
            None => None
        }
    }

    pub fn authority_info_access(&self) -> Option<&UriGeneralName> {
        self.authority_info_access.as_ref()
    }

    pub fn key_usage_ca(&self) -> bool {
        self.key_usage_ca
    }

    pub fn extended_key_usage(&self) -> Option<&Captured> {
        self.extended_key_usage.as_ref()
    }

    pub fn subject_info_access(&self) -> &SubjectInfoAccess {
        &self.subject_info_access
    }

    pub fn ca_repository_uri(&self) -> Option<&uri::Rsync> {
        self.subject_info_access.ca_repository()
    }

    pub fn manifest_uri(&self) -> Option<&uri::Rsync> {
        self.subject_info_access.rpki_manifest()
    }

    pub fn signed_object_uri(&self) -> Option<&uri::Rsync> {
        self.subject_info_access.signed_object()
    }

    pub fn rpki_notify_uri(&self) -> Option<&uri::Https> {
        self.subject_info_access.rpki_notify()
    }

    pub fn overclaim(&self) -> Overclaim {
        self.overclaim
    }

    pub fn v4_resources(&self) -> Option<&IpResources> {
        self.v4_resources.as_ref()
    }

    pub fn v6_resources(&self) -> Option<&IpResources> {
        self.v6_resources.as_ref()
    }

    pub fn as_resources(&self) -> Option<&AsResources> {
        self.as_resources.as_ref()
    }
}


/// # Decoding
///
impl Extensions {
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            let mut basic_ca = None;
            let mut subject_key_id = None;
            let mut authority_key_id = None;
            let mut key_usage_ca = None;
            let mut extended_key_usage = None;
            let mut crl_distribution = None;
            let mut authority_info_access = None;
            let mut subject_info_access = None;
            let mut overclaim = None;
            let mut ip_resources = None;
            let mut ip_overclaim = None;
            let mut as_resources = None;
            let mut as_overclaim = None;
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
                        AuthorityKeyIdentifier::take(
                            content, critical, &mut authority_key_id
                        )
                    } else if id == oid::CE_KEY_USAGE {
                        Self::take_key_usage(
                            content, &mut key_usage_ca
                        )
                    } else if id == oid::CE_EXTENDED_KEY_USAGE {
                        Self::take_extended_key_usage(
                            content, &mut extended_key_usage
                        )
                    } else if id == oid::CE_CRL_DISTRIBUTION_POINTS {
                        Self::take_crl_distribution_points(
                            content, &mut crl_distribution
                        )
                    } else if id == oid::PE_AUTHORITY_INFO_ACCESS {
                        Self::take_authority_info_access(
                            content, &mut authority_info_access
                        )
                    } else if id == oid::PE_SUBJECT_INFO_ACCESS {
                        Self::take_subject_info_access(
                            content, &mut subject_info_access
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
            if ip_resources.is_none() && as_resources.is_none() {
                xerr!(return Err(decode::Malformed.into()))
            }
            if ip_resources.is_some() && ip_overclaim != overclaim {
                xerr!(return Err(decode::Malformed.into()))
            }
            if as_resources.is_some() && as_overclaim != overclaim {
                xerr!(return Err(decode::Malformed.into()))
            }
            let ip_resources = match ip_resources {
                None => (None, None),
                Some((a, b)) => (a, b),
            };
            Ok(Extensions {
                basic_ca,
                subject_key_id: subject_key_id.ok_or(decode::Malformed)?,
                authority_key_id,
                key_usage_ca: key_usage_ca.ok_or(decode::Malformed)?,
                extended_key_usage,
                crl_distribution,
                authority_info_access,
                subject_info_access:
                    subject_info_access.ok_or(decode::Malformed)?,
                overclaim: overclaim.ok_or(decode::Malformed)?,
                v4_resources: ip_resources.0,
                v6_resources: ip_resources.1,
                as_resources,
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
    /// set. This field therefore simply describes whether the certificate
    /// is for a CA.
    fn take_key_usage<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        key_usage_ca: &mut Option<bool>
    ) -> Result<(), S::Err> {
        update_once(key_usage_ca, || {
            let bits = BitString::take_from(cons)?;
            if bits.bit(5) && bits.bit(6) {
                Ok(true)
            }
            else if bits.bit(0) {
                Ok(false)
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
    fn take_extended_key_usage<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        extended_key_usage: &mut Option<Captured>
    ) -> Result<(), S::Err> {
        update_once(extended_key_usage, || {
            let res = cons.take_sequence(|c| c.capture_all())?;
            res.clone().decode(|cons| {
                Oid::skip_in(cons)?;
                while let Some(_) = Oid::skip_opt_in(cons)? { }
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
        crl_distribution: &mut Option<UriGeneralNames>
    ) -> Result<(), S::Err> {
        update_once(crl_distribution, || {
            cons.take_sequence(|cons| {
                cons.take_sequence(|cons| {
                    cons.take_constructed_if(Tag::CTX_0, |cons| {
                        cons.take_constructed_if(Tag::CTX_0, |cons| {
                            UriGeneralNames::take_content_from(cons)
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
    /// exactly one entry with accessMethod id-ad-caIssuers and a URI as a
    /// generalName.
    fn take_authority_info_access<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        authority_info_access: &mut Option<UriGeneralName>
    ) -> Result<(), S::Err> {
        update_once(authority_info_access, || {
            cons.take_sequence(|cons| {
                cons.take_sequence(|cons| {
                    oid::AD_CA_ISSUERS.skip_if(cons)?;
                    UriGeneralName::take_from(cons)
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
    /// For EE certificates, there must at least one AccessDescription value
    /// with an id-ad-signedObject access method.
    ///
    /// Since we don’t necessarily know what kind of certificate we have yet,
    /// we may accept the wrong kind here. This needs to be checked later.
    fn take_subject_info_access<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        subject_info_access: &mut Option<SubjectInfoAccess>,
    ) -> Result<(), S::Err> {
        update_once(
            subject_info_access,
            || SubjectInfoAccess::take_from(cons)
        )
    }

    /// Parses the Certificate Policies extension.
    ///
    /// Must be present.
    fn take_certificate_policies<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        overclaim: &mut Option<Overclaim>,
    ) -> Result<(), S::Err> {
        update_once(overclaim, || {
            cons.take_sequence(|cons| {
                cons.take_sequence(|cons| {
                    // policyIdentifier. This can be one of two options and
                    // decides how we deal with overclaim.
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
}


//------------ BasicCa -------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicCa {
    // RFC5280 section 4.2.1.9 MAY appear as critical or non-critical
    critical: bool,
    ca: bool,
}

/// # Creation and Data Access
///
impl BasicCa {
    pub fn new(critical: bool, ca: bool) -> Self {
        Self { critical, ca }
    }

    pub fn ca(&self) -> bool {
        self.ca
    }

    pub fn is_critical(&self) -> bool {
        self.critical
    }
}


/// # Decoding and Encoding
///
impl BasicCa {
    /// Parses the Basic Constraints Extension.
    ///
    /// The extension must be present in CA certificates and must not be
    /// present in EE certificates.
    ///
    /// ```text
    ///   BasicConstraints ::= SEQUENCE {
    ///        cA                      BOOLEAN DEFAULT FALSE,
    ///        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
    /// ```
    ///
    /// The cA field gets chosen by the CA. The pathLenConstraint field must
    /// not be present.
    pub fn take<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        critical: bool,
        basic_ca: &mut Option<Self>
    ) -> Result<(), S::Err> {
        update_once(basic_ca, || {
            let ca = match cons.take_sequence(|cons| cons.take_opt_bool())? {
                Some(res) => res,
                None => false
            };

            Ok(Self{critical, ca})
        })
    }

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode_extension(
            oid::CE_BASIC_CONSTRAINTS,
            self.critical,
            encode::sequence(
                self.ca.encode()
            )
        )
    }
}


//------------ KeyIdentifier -------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyIdentifier(OctetString);

impl KeyIdentifier {
    pub fn new(key_info: &PublicKey) -> Self {
        let ki = key_info.key_identifier();
        let b = Bytes::from(ki.as_ref());
        KeyIdentifier(OctetString::new(b))
    }

    pub fn key_id(&self) -> &OctetString {
        &self.0
    }

    pub fn encode(self) -> impl encode::Values {
        self.0.encode()
    }

    pub fn encode_as(self, tag: Tag) -> impl encode::Values {
        self.0.encode_as(tag)
    }

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        self.0.encode_ref()
    }

    pub fn encode_ref_as<'a>(&'a self, tag: Tag) -> impl encode::Values + 'a {
        self.0.encode_ref_as(tag)
    }
}

impl From<OctetString> for KeyIdentifier {
    fn from(o: OctetString) -> Self {
        KeyIdentifier(o)
    }
}


//------------ SubjectKeyIdentifier ------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectKeyIdentifier {
    subject_key_id: KeyIdentifier
}

/// # Creating and Data Access
///
impl SubjectKeyIdentifier {
    pub fn new(key_info: &PublicKey) -> Self {
        Self{subject_key_id: KeyIdentifier::new(key_info)}
    }

    pub fn subject_key_id(&self) -> &OctetString {
        self.subject_key_id.key_id()
    }
}


/// # Decoding and Encoding
///
impl SubjectKeyIdentifier {
    /// Parses the Subject Key Identifier Extension.
    ///
    /// The extension must be present and contain the 160 bit SHA-1 hash of
    /// the value of the DER-encoded bit string of the subject public key.
    ///
    /// ```text
    /// SubjectKeyIdentifier ::= KeyIdentifier
    /// KeyIdentifier        ::= OCTET STRING
    /// ```
    ///
    /// Conforming CAs MUST mark this extension as non-critical.
    pub fn take<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        critical: bool,
        subject_key_id: &mut Option<Self>
    ) -> Result<(), S::Err> {
        update_once(subject_key_id, || {
            let subject_key_id = OctetString::take_from(cons)?;
            if critical || subject_key_id.len() != 20 {
                xerr!(Err(decode::Malformed.into()))
            }
            else {
                Ok(Self{subject_key_id: subject_key_id.into()} )
            }
        })
    }

    pub fn encode(self) -> impl encode::Values {
        encode_extension(
            oid::CE_SUBJECT_KEY_IDENTIFIER,
            false,
            self.subject_key_id.encode()
        )
    }

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode_extension(
            oid::CE_SUBJECT_KEY_IDENTIFIER,
            false,
            self.subject_key_id.encode_ref()
        )
    }
}


//------------ AuthorityKeyIdentifier ----------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityKeyIdentifier {
    authority_key_id: OctetString
}

/// # Creating and Data Access
///
impl AuthorityKeyIdentifier {
    pub fn new(key_info: &PublicKey) -> Self {
        let ki = key_info.key_identifier();
        let b = Bytes::from(ki.as_ref());

        Self{authority_key_id: OctetString::new(b)}
    }

    pub fn authority_key_id(&self) -> &OctetString {
        &self.authority_key_id
    }

}


/// # Decoding and Encoding
///
impl AuthorityKeyIdentifier {
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
    /// Only keyIdentifier MUST be present.
    pub fn take<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        critical: bool,
        authority_key_id: &mut Option<Self>
    ) -> Result<(), S::Err> {
        update_once(authority_key_id, || {
            let authority_key_id = cons.take_sequence(|cons| {
                cons.take_value_if(Tag::CTX_0, OctetString::from_content)
            })?;
            if critical || authority_key_id.len() != 20 {
                Err(decode::Malformed.into())
            }
            else {
                Ok(AuthorityKeyIdentifier{authority_key_id})
            }
        })
    }

    pub fn encode(self) -> impl encode::Values {
        encode_extension(
            oid::CE_AUTHORITY_KEY_IDENTIFIER,
            false,
            encode::sequence(
                 self.authority_key_id.encode_as(Tag::CTX_0)
            )
        )
    }

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode_extension(
            oid::CE_AUTHORITY_KEY_IDENTIFIER,
            false,
            encode::sequence(
                 self.authority_key_id.encode_ref_as(Tag::CTX_0)
            )
        )
    }
}


//------------ SubjectInfoAccess ---------------------------------------------

#[derive(Clone, Debug)]
pub struct SubjectInfoAccess {
    ca_repository: Option<uri::Rsync>,
    rpki_manifest: Option<uri::Rsync>,
    signed_object: Option<uri::Rsync>,
    rpki_notify: Option<uri::Https>,
    content: Captured,
}

/// # Data Access
///
impl SubjectInfoAccess {
    pub fn ca_repository(&self) -> Option<&uri::Rsync> {
        self.ca_repository.as_ref()
    }

    pub fn rpki_manifest(&self) -> Option<&uri::Rsync> {
        self.rpki_manifest.as_ref()
    }

    pub fn signed_object(&self) -> Option<&uri::Rsync> {
        self.signed_object.as_ref()
    }

    pub fn rpki_notify(&self) -> Option<&uri::Https> {
        self.rpki_notify.as_ref()
    }

    pub fn iter(&self) -> SiaIter {
        SiaIter { content: self.content.clone() }
    }

    pub fn ca(&self) -> bool {
        self.ca_repository.is_some()
    }
}

/// # Decoding
///
impl SubjectInfoAccess {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            let mut ca_repository = None;
            let mut ca_repository_seen = false;
            let mut rpki_manifest = None;
            let mut rpki_manifest_seen = false;
            let mut signed_object = None;
            let mut signed_object_seen = false;
            let mut rpki_notify = None;
            let mut rpki_notify_seen = false;
            let mut other_seen = false;
            let content = cons.capture(|cons| {
                while let Some(()) = cons.take_opt_sequence(|cons| {
                    let oid = Oid::take_from(cons)?;
                    let uri = UriGeneralName::take_any_from(cons)?;
                    if oid == oid::AD_CA_REPOSITORY {
                        ca_repository_seen = true;
                        if ca_repository.is_none() {
                            if let Some(uri) = uri {
                                if let Some(uri) = uri.into_rsync_uri() {
                                    ca_repository = Some(uri)
                                }
                            }
                        }
                    }
                    else if oid == oid::AD_RPKI_MANIFEST {
                        rpki_manifest_seen = true;
                        if rpki_manifest.is_none() {
                            if let Some(uri) = uri {
                                if let Some(uri) = uri.into_rsync_uri() {
                                    rpki_manifest = Some(uri)
                                }
                            }
                        }
                    }
                    else if oid == oid::AD_SIGNED_OBJECT {
                        signed_object_seen = true;
                        if signed_object.is_none() {
                            if let Some(uri) = uri {
                                if let Some(uri) = uri.into_rsync_uri() {
                                    signed_object = Some(uri)
                                }
                            }
                        }
                    }
                    else if oid == oid::AD_RPKI_NOTIFY {
                        rpki_notify_seen = true;
                        // This one must be a HTTP URI.
                        //
                        // XXX We are a bit lenient here: The RFC hints at
                        //     having exactly one of these but it isn’t
                        //     specific. We will therefore allow more than
                        //     one but will ignore all but the first.
                        let uri = match uri {
                            Some(uri) => uri,
                            None => {
                                return xerr!(Err(decode::Malformed.into()))
                            }
                        };
                        let uri = match uri.into_https_uri() {
                            Some(uri) => uri,
                            None => {
                                return xerr!(Err(decode::Malformed.into()))
                            }
                        };
                        if rpki_notify.is_none() {
                            rpki_notify = Some(uri)
                        }
                    }
                    else {
                        other_seen = true
                    }
                    Ok(())
                })? { }
                Ok(())
            })?;
            
            // Check that we have a valid combination.
            if ca_repository.is_some() {
                // CA Certificate
                //
                // Requires also rpki_manifest. rpki_notify is optional.
                //
                // RFC 6487 doesn’t say that others aren’t allowed in CA
                // certificates but it does say so for EE certificates so I
                // guess it must be fine to have others in CA certificates.
                if rpki_manifest.is_none() {
                    return xerr!(Err(decode::Malformed.into()))
                }
            }
            else {
                // EE Certificate
                //
                // Only signed_object. Note that signed_object is not required
                // in EE certificates for router keys etc. So we shouldn’t
                // check that here.
                if rpki_manifest.is_some() || rpki_notify.is_some()
                    || other_seen
                {
                    return xerr!(Err(decode::Malformed.into()))
                }
            }
            Ok(SubjectInfoAccess {
                ca_repository, rpki_manifest, signed_object, rpki_notify,
                content
            })
        })
    }
}


//------------ SiaIter -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SiaIter {
    content: Captured,
}

impl SiaIter {
    pub fn filter_oid<O: AsRef<[u8]>>(
        self,
        expected: Oid<O>
    ) -> impl Iterator<Item=UriGeneralName> {
        self.filter_map(move |(oid, uri)| {
            if oid == expected {
                Some(uri)
            }
                else {
                    None
                }
        })
    }
}

impl Iterator for SiaIter {
    type Item = (Oid, UriGeneralName);

    fn next(&mut self) -> Option<Self::Item> {
        self.content.decode_partial(|cons| {
            cons.take_opt_sequence(|cons| {
                Ok((
                    Oid::take_from(cons)?,
                    UriGeneralName::take_from(cons)?
                ))
            })
        }).unwrap()
    }
}


//------------ CrlNumber -----------------------------------------------------

/// This extension is used in CRLs.
#[derive(Clone, Debug)]
pub struct CrlNumber {
    number: Unsigned
}

/// # Creating
///
impl CrlNumber {
    pub fn new(number: u32) -> Self {
        CrlNumber{ number: number.into() }
    }
}

/// # Decoding and Encoding
///
impl CrlNumber {
    /// Parses the CRL Number Extension.
    ///
    /// Must be present
    ///
    /// ```text
    /// CRLNumber ::= INTEGER (0..MAX)
    /// ```
    pub fn take<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        _critical: bool,
        crl_number: &mut Option<Self>
    ) -> Result<(), S::Err> {
        update_once(crl_number, || {
            Ok(CrlNumber { number: Unsigned::take_from(cons)? })
        })
    }

    pub fn encode<'a>(& 'a self) -> impl encode::Values + 'a {
        encode::sequence((
            oid::CE_CRL_NUMBER.encode(),
            OctetString::encode_wrapped(Mode::Der, self.number.encode())
        ))
    }
}



//------------ URIGeneralNames -----------------------------------------------

/// A GeneralNames value limited to uniformResourceIdentifier choices.
#[derive(Clone, Debug)]
pub struct UriGeneralNames(Captured);

impl<'a> UriGeneralNames {
    /// ```text
    /// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    ///
    /// GeneralName ::= CHOICE {
    ///    ...
    ///    uniformResourceIdentifier       [6]     IA5String,
    ///    ... }
    /// ```
    fn take_content_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        Ok(UriGeneralNames(cons.capture(|cons| {
            if UriGeneralName::skip_opt(cons)?.is_none() {
                xerr!(return Err(decode::Malformed.into()))
            }
            while let Some(()) = UriGeneralName::skip_opt(cons)? { }
            Ok(())
        })?))
    }

    pub fn iter(&self) -> UriGeneralNameIter {
        UriGeneralNameIter(self.0.clone())
    }
}


//------------ UriGeneralNameIter --------------------------------------------

// XXX This can be improved quite a bit.
#[derive(Clone, Debug)]
pub struct UriGeneralNameIter(Captured);

impl Iterator for UriGeneralNameIter {
    type Item = UriGeneralName;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        }
            else {
                self.0.decode_partial(|cons| {
                    UriGeneralName::take_opt_from(cons)
                }).unwrap()
            }
    }
}


//------------ UriGeneralName ------------------------------------------------

#[derive(Clone, Debug)]
pub struct UriGeneralName(Bytes);

impl UriGeneralName {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_primitive_if(Tag::CTX_6, |prim| {
            let res = prim.take_all()?;
            if res.is_ascii() {
                Ok(UriGeneralName(res))
            }
                else {
                    xerr!(Err(decode::Malformed.into()))
                }
        })
    }

    /// Takes a general name from the source that doesn’t need to be a URI.
    ///
    /// The next element in `cons` needs to be a GeneralName but it doesn’t
    /// have to have the URI form. In this case, returns `Ok(None)`.
    fn take_any_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_value(|tag, content| {
            if !tag.is_context_specific() || tag.number() > 8 {
                return xerr!(Err(decode::Malformed.into()))
            }
            if tag == Tag::CTX_6 {
                let res = content.as_primitive()?.take_all()?;
                if res.is_ascii() {
                    Ok(Some(UriGeneralName(res)))
                }
                else {
                    xerr!(Err(decode::Malformed.into()))
                }
            }
            else {
                Ok(None)
            }
        })
    }


    fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_primitive_if(Tag::CTX_6, |prim| {
            let res = prim.take_all()?;
            if res.is_ascii() {
                Ok(UriGeneralName(res))
            }
                else {
                    xerr!(Err(decode::Malformed.into()))
                }
        })
    }

    fn skip_opt<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        cons.take_opt_primitive_if(Tag::CTX_6, |prim| {
            if prim.slice_all()?.is_ascii() {
                prim.skip_all()?;
                Ok(())
            }
                else {
                    xerr!(Err(decode::Malformed.into()))
                }
        })
    }

    pub fn into_rsync_uri(self) -> Option<uri::Rsync> {
        uri::Rsync::from_bytes(self.0).ok()
    }

    pub fn into_https_uri(self) -> Option<uri::Https> {
        uri::Https::from_bytes(self.0).ok()
    }
}


//--- Display

impl fmt::Display for UriGeneralName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}


//------------ Helper Functions ----------------------------------------------

/// Returns an encoder for an extension.
///
/// The encoder will implement the following ASN.1 grammar:
///
/// ```text
///  Extension  ::=  SEQUENCE  {
///      extnID      OBJECT IDENTIFIER,
///      critical    BOOLEAN DEFAULT FALSE,
///      extnValue   OCTET STRING
///                  -- contains the DER encoding of an ASN.1 value
///                  -- corresponding to the extension type identified
///                  -- by extnID
///      }
/// ```
fn encode_extension<'a, V: encode::Values + 'a>(
    oid: ConstOid,
    critical: bool,
    content: V
) -> impl encode::Values + 'a {
    encode::sequence((
        oid.encode(),
        critical.encode(),
        OctetString::encode_wrapped(Mode::Der, content)
    ))
}


//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bcder::encode::Values;

    #[test]
    fn should_encode_basic_ca() {
        let ba = BasicCa::new(true, true);
        let mut v = Vec::new();
        ba.encode().write_encoded(Mode::Der, &mut v).unwrap();

        // 48 15            Sequence with length 15
        //  6 3 85 29 19       OID 2.5.29.19 basicConstraints
        //  1 1 255              Boolean true
        //  4 5                OctetString of length 5
        //     48 3               Sequence with length 3
        //        1 1 255           Boolean true

        assert_eq!(
            vec![48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255 ],
            v
        );
    }
}

