//! X509 Extensions

use ber::{BitString, Captured, Mode, OctetString, Oid, Tag};
use ber::{decode, encode};
use ber::encode::PrimitiveContent;
use crl;
use bytes::Bytes;
use ipres::IpResources;
use asres::AsResources;
use x509::update_once;
use uri;
use cert::SubjectPublicKeyInfo;
use ber::Unsigned;


//------------ Encoding ------------------------------------------------------

pub fn encode_extension<'a, V: encode::Values + 'a>(
    oid: &'static Oid<&'static [u8]>,
    critical: &'a bool,
    content: V
) -> impl encode::Values + 'a {
    //  Extension  ::=  SEQUENCE  {
    //      extnID      OBJECT IDENTIFIER,
    //      critical    BOOLEAN DEFAULT FALSE,
    //      extnValue   OCTET STRING
    //                  -- contains the DER encoding of an ASN.1 value
    //                  -- corresponding to the extension type identified
    //                  -- by extnID
    //      }

    encode::sequence(
        (
            oid.encode(),
            critical.value(),
            OctetString::encode_into_der(content)
        )
    )
}


//------------ BasicCa -------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicCa {
    // RFC5280 section 4.2.1.9 MAY appear as critical or non-critical
    critical: bool,
    ca: bool,
}

/// # Creating
///
impl BasicCa {
    pub fn new(critical: bool, ca: bool) -> Self {
        Self { critical, ca }
    }
}

/// # Decoding
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
}


/// # Data Access
///
impl BasicCa {
    pub fn ca(&self) -> bool {
        self.ca
    }

    pub fn is_critical(&self) -> bool {
        self.critical
    }
}

/// # Encoding
///
impl BasicCa {
    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode_extension(
            &oid::CE_BASIC_CONSTRAINTS,
            &self.critical,
            encode::sequence(
                self.ca.value()
            )
        )
    }
}


//------------ KeyIdentifier -------------------------------------------------

#[derive(Clone, Debug)]
pub struct KeyIdentifier(OctetString);

impl KeyIdentifier {
    pub fn new(key_info: &SubjectPublicKeyInfo) -> Self {
        let ki = key_info.key_identifier();
        let b = Bytes::from(ki.as_ref());
        KeyIdentifier(OctetString::new(b))
    }

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        self.0.encode()
    }

    pub fn encode_as<'a>(&'a self, tag: Tag) -> impl encode::Values + 'a {
        self.0.encode_as(tag)
    }

    pub fn key_id(&self) -> &OctetString {
        &self.0
    }
}

impl From<OctetString> for KeyIdentifier {
    fn from(o: OctetString) -> Self {
        KeyIdentifier(o)
    }
}



//------------ SubjectKeyIdentifier ------------------------------------------

#[derive(Clone, Debug)]
pub struct SubjectKeyIdentifier {
    subject_key_id: KeyIdentifier
}

/// # Creating
///
impl SubjectKeyIdentifier {
    pub fn new(key_info: &SubjectPublicKeyInfo) -> Self {
        Self{subject_key_id: KeyIdentifier::new(key_info)}
    }
}

/// # Decoding
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
            if critical == true {
                // RFC5280: Conforming CAs MUST mark this extension as non-critical.
                xerr!(Err(decode::Malformed.into()))
            }
            else if subject_key_id.len() != 20 {
                xerr!(Err(decode::Malformed.into()))
            }
            else {
                Ok(Self{subject_key_id: subject_key_id.into()} )
            }
        })
    }
}

/// # Data Access
///
impl SubjectKeyIdentifier {
    pub fn subject_key_id(&self) -> &OctetString {
        self.subject_key_id.key_id()
    }
}

/// # Encoding
///
impl SubjectKeyIdentifier {
    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {

        encode_extension(
            &oid::CE_SUBJECT_KEY_IDENTIFIER,
            &false,
            self.subject_key_id.encode()
        )
    }
}


//------------ AuthorityKeyIdentifier ----------------------------------------

#[derive(Clone, Debug)]
pub struct AuthorityKeyIdentifier {
    authority_key_id: OctetString
}

/// # Creating
///
impl AuthorityKeyIdentifier {
    pub fn new(key_info: &SubjectPublicKeyInfo) -> Self {
        let ki = key_info.key_identifier();
        let b = Bytes::from(ki.as_ref());

        Self{authority_key_id: OctetString::new(b)}
    }
}

/// # Decoding
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
                cons.take_value_if(Tag::CTX_0, OctetString::take_content_from)
            })?;
            if critical == true {
                // RFC5280: Conforming CAs MUST mark this extension as non-critical.
                return Err(decode::Malformed.into())
            }
            else if authority_key_id.len() != 20 {
                return Err(decode::Malformed.into())
            }
            else {
                Ok(AuthorityKeyIdentifier{authority_key_id})
            }
        })
    }
}

/// # Encoding
///
impl AuthorityKeyIdentifier {
//    const OID: &'static Oid<&'static [u8]> = &oid::CE_AUTHORITY_KEY_IDENTIFIER;

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode_extension(
            &oid::CE_AUTHORITY_KEY_IDENTIFIER,
            &false,
            encode::sequence(
                 self.authority_key_id.encode_as(Tag::CTX_0)
            )
        )
    }

}


/// # Data Access
///
impl AuthorityKeyIdentifier {
    pub fn authority_key_id(&self) -> &OctetString {
        &self.authority_key_id
    }
}

//------------ SubjectInfoAccess ---------------------------------------------

#[derive(Clone, Debug)]
pub struct SubjectInfoAccess {
    content: Captured,
    ca: bool
}

/// # Decoding
///
impl SubjectInfoAccess {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            let mut ca = None;
            let content = cons.capture(|cons| {
                while let Some(()) = cons.take_opt_sequence(|cons| {
                    let oid = Oid::take_from(cons)?;
                    if oid == oid::AD_CA_REPOSITORY
                        || oid == oid::AD_RPKI_MANIFEST
                        {
                            match ca {
                                None => ca = Some(true),
                                Some(true) => { }
                                Some(false) => {
                                    xerr!(return Err(decode::Malformed.into()))
                                }
                            }
                        }
                        else if oid == oid::AD_SIGNED_OBJECT {
                            match ca {
                                None => ca = Some(false),
                                Some(false) => { }
                                Some(true) => {
                                    xerr!(return Err(decode::Malformed.into()))
                                }
                            }
                        }
                    let _ = UriGeneralName::take_from(cons)?;
                    Ok(())
                })? { }
                Ok(())
            })?;
            if let Some(ca) = ca {
                Ok(SubjectInfoAccess { content, ca })
            }
                else {
                    // The sequence was empty.
                    xerr!(Err(decode::Malformed.into()))
                }
        })
    }
}

/// # Data Access
///
impl SubjectInfoAccess {
    pub fn iter(&self) -> SiaIter {
        SiaIter { content: self.content.clone() }
    }

    pub fn ca(&self) -> bool {
        self.ca
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


//------------ CertificatePolicies -------------------------------------------

#[derive(Clone, Debug)]
pub struct CertificatePolicies(Captured);

/// # Decoding
///
impl CertificatePolicies {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        // XXX TODO Parse properly.
        cons.take_sequence(|c| c.capture_all()).map(CertificatePolicies)
    }
}


//------------ CrlNumber -----------------------------------------------------

/// This extension is used in CRLs.
#[derive(Clone, Debug)]
pub struct CrlNumber {
    number: Unsigned
}

/// # Create
impl CrlNumber {
    pub fn new(number: u32) -> Self { CrlNumber{ number: number.into() } }
}

/// # Decoding
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
}

/// # Encoding
impl CrlNumber {
    pub fn encode<'a>(& 'a self) -> impl encode::Values + 'a {
        encode::sequence(
            (
                crl::oid::CE_CRL_NUMBER.encode(),
                OctetString::encode_into_der(self.number.value())
            )
        )
    }
}


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
    /// Must be present and critical. RFC 6484 describes the policies for
    /// PKIX certificates. This value contains the content of the
    /// certificatePolicies sequence.
    certificate_policies: CertificatePolicies,

    /// IP Resources
    ip_resources: Option<IpResources>,

    /// AS Resources
    as_resources: Option<AsResources>,
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
            let mut certificate_policies = None;
            let mut ip_resources = None;
            let mut as_resources = None;
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
                            content, &mut certificate_policies
                        )
                    } else if id == oid::PE_IP_ADDR_BLOCK {
                        Self::take_ip_resources(content, &mut ip_resources)
                    } else if id == oid::PE_AUTONOMOUS_SYS_IDS {
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
                certificate_policies:
                certificate_policies.ok_or(decode::Malformed)?,
                ip_resources,
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
        certificate_policies: &mut Option<CertificatePolicies>,
    ) -> Result<(), S::Err> {
        update_once(certificate_policies, || {
            CertificatePolicies::take_from(cons)
        })
    }

    /// Parses the IP Resources extension.
    fn take_ip_resources<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        ip_resources: &mut Option<IpResources>
    ) -> Result<(), S::Err> {
        update_once(ip_resources, || {
            IpResources::take_from(cons)
        })
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

    pub fn ip_resources(&self) -> Option<&IpResources> {
        self.ip_resources.as_ref()
    }

    pub fn as_resources(&self) -> Option<&AsResources> {
        self.as_resources.as_ref()
    }

    pub fn key_usage_ca(&self) -> bool {
        self.key_usage_ca
    }

    pub fn subject_info_access(&self) -> &SubjectInfoAccess {
        &self.subject_info_access
    }

    pub fn manifest_uris(&self) -> impl Iterator<Item=UriGeneralName> {
        self.subject_info_access.iter().filter_oid(oid::AD_RPKI_MANIFEST)
    }

    pub fn repository_uri(&self) -> Option<uri::Rsync> {
        for uri in self.subject_info_access
            .iter().filter_oid(oid::AD_CA_REPOSITORY)
            {
                if let Some(mut uri) = uri.into_rsync_uri() {
                    return Some(uri)
                }
            }
        None
    }

    pub fn extended_key_usage(&self) -> Option<&Captured> {
        self.extended_key_usage.as_ref()
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
            if let None = UriGeneralName::skip_opt(cons)? {
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
        uri::Rsync::from_bytes(self.0.clone()).ok()
    }
}


//------------ OIDs ----------------------------------------------------------

#[allow(dead_code)] // XXX
pub mod oid {
    use ::ber::Oid;

    pub const AD_CA_ISSUERS: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 2]);
    pub const AD_CA_REPOSITORY: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 5]);
    pub const AD_RPKI_MANIFEST: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 10]);
    pub const AD_SIGNED_OBJECT: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 11]);

    pub const CE_SUBJECT_KEY_IDENTIFIER: Oid<&[u8]> = Oid(&[85, 29, 14]);

    pub const CE_KEY_USAGE: Oid<&[u8]> = Oid(&[85, 29, 15]);
    pub const CE_BASIC_CONSTRAINTS: Oid<&[u8]> = Oid(&[85, 29, 19]);
    pub const CE_CRL_DISTRIBUTION_POINTS: Oid<&[u8]> = Oid(&[85, 29, 31]);
    pub const CE_EXTENDED_KEY_USAGE: Oid<&[u8]> = Oid(&[85, 29, 37]);
    pub const CE_CERTIFICATE_POLICIES: Oid<&[u8]> = Oid(&[85, 29, 32]);
    pub const CE_AUTHORITY_KEY_IDENTIFIER: Oid<&[u8]> = Oid(&[85, 29, 35]);
    pub const PE_AUTHORITY_INFO_ACCESS: Oid<&[u8]>
        = Oid(&[43, 6, 1, 5, 5, 7, 1, 1]);
    pub const PE_IP_ADDR_BLOCK: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 1, 7]);
    pub const PE_AUTONOMOUS_SYS_IDS: Oid<&[u8]>
        = Oid(&[43, 6, 1, 5, 5, 7, 1, 8]);
    pub const PE_SUBJECT_INFO_ACCESS: Oid<&[u8]>
        = Oid(&[43, 6, 1, 5, 5, 7, 1, 11]);
}
