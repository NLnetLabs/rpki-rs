//! Resource Tagged Attestations.
//!
//! Resouce Tagged Attestations attaching signed attestations of ownership of 
//! resources referred to by a docuement. This is currently an IETF draft,
//! see [draft-michaelson-rpki-rta] for details.
//!
//! draft-michaelson-rpki-rta: https://tools.ietf.org/html/draft-michaelson-rpki-rta

use bcder::{decode, encode};
use bcder::{Captured, Mode, OctetString, Tag};
use bcder::encode::{PrimitiveContent, Values};
use bcder::string::OctetStringSource;
use bcder::xerr;
use bytes::Bytes;
use crate::oid;
use crate::cert::{Cert, ResourceCert};
use crate::crl::Crl;
use crate::crypto:: {
    DigestAlgorithm, KeyIdentifier, Signature, SignatureAlgorithm,
    Signer, SigningError
};
use crate::resources::{
    AddressFamily, AsBlock, AsBlocksBuilder, IpBlock, IpBlocksBuilder
};
use crate::sigobj::{MessageDigest, SignedAttrs};
use crate::x509::{Time, ValidationError};


//------------ Rta -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Rta {
    signed: MultiSignedObject,
    content: ResourceTaggedAttestation,
}

impl Rta {
    pub fn decode<S: decode::Source>(
        source: S,
        strict: bool
    ) -> Result<Self, S::Err> {
        let signed = MultiSignedObject::decode(source, strict)?;
        let content = signed.decode_content(|cons| {
            ResourceTaggedAttestation::take_from(cons)
        })?;
        Ok(Rta { signed, content })
    }

    pub fn validate<F: FnMut(Cert) -> Result<ResourceCert, ValidationError>>(
        self, _strict: bool, _validate_cert: F
    ) -> Result<ResourceTaggedAttestation, ValidationError> {
        unimplemented!()
    }

    /// Returns a value encoder for a reference to a ROA.
    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        self.signed.encode_ref()
    }

    /// Returns a DER encoded Captured for this ROA.
    pub fn to_captured(&self) -> Captured {
        self.encode_ref().to_captured(Mode::Der)
    }
}


//------------ ResourceTaggedAttestation -------------------------------------

#[derive(Clone, Debug)]
pub struct ResourceTaggedAttestation {
    subject_keys: SubjectKeySet,

    /// AS Resources
    as_resources: RtaAsBlocks,

    /// IP Resources for the IPv4 address family.
    v4_resources: RtaIpBlocks,

    /// IP Resources for the IPv6 address family.
    v6_resources: RtaIpBlocks,

    digest_algorithm: DigestAlgorithm,

    message_digest: MessageDigest,
}

impl ResourceTaggedAttestation {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.take_opt_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(0))?;
            let subject_keys = SubjectKeySet::take_from(cons)?;
            let (v4res, v6res, asres) = Self::take_resources_from(cons)?;
            let alg = DigestAlgorithm::take_from(cons)?;
            let digest = OctetString::take_from(cons)?;
            Ok(ResourceTaggedAttestation {
                subject_keys,
                v4_resources: v4res,
                v6_resources: v6res,
                as_resources: asres,
                digest_algorithm: alg,
                message_digest: digest.into(),
            })
        })
    }

    fn take_resources_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(RtaIpBlocks, RtaIpBlocks, RtaAsBlocks), S::Err> {
        cons.take_sequence(|cons| {
            let asres = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                RtaAsBlocks::take_from(cons)
            })?;

            let mut v4 = None;
            let mut v6 = None;
            cons.take_opt_constructed_if(Tag::CTX_1, |cons| {
                cons.take_sequence(|cons| {
                    while let Some(()) = cons.take_opt_sequence(|cons| {
                        match AddressFamily::take_from(cons)? {
                            AddressFamily::Ipv4 => {
                                if v4.is_some() {
                                    xerr!(return Err(decode::Malformed.into()));
                                }
                                v4 = Some(RtaIpBlocks::take_from(cons)?);
                            }
                            AddressFamily::Ipv6 => {
                                if v6.is_some() {
                                    xerr!(return Err(decode::Malformed.into()));
                                }
                                v6 = Some(RtaIpBlocks::take_from(cons)?);
                            }
                        }
                        Ok(())
                    })? { }
                    Ok(())
                })
            })?;

            if asres.is_none() && v4.is_none() && v6.is_none() {
                xerr!(return Err(decode::Malformed.into()));
            }
            Ok((
                v4.unwrap_or_default(),
                v6.unwrap_or_default(),
                asres.unwrap_or_default(),
            ))
        })
    }

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            // version is DEFAULT
            self.subject_keys.encode_ref(),
            encode::sequence((
                self.encode_as_resources(),
                self.encode_ip_resources(),
            )),
            self.digest_algorithm.encode(),
            self.message_digest.encode_ref()
        ))
    }

    fn encode_as_resources<'a>(&'a self) -> impl encode::Values + 'a {
        if self.as_resources.is_empty() {
            return None
        }
        Some(encode::sequence_as(Tag::CTX_0,
            self.as_resources.encode_ref()
        ))
    }

    fn encode_ip_resources<'a>(&'a self) -> impl encode::Values + 'a {
        if self.v4_resources.is_empty() && self.v6_resources.is_empty() {
            return None
        }
        Some(encode::sequence_as(Tag::CTX_1,
            encode::sequence((
                self.v4_resources.encode_ref_family([0x00, 0x01]),
                self.v6_resources.encode_ref_family([0x00, 0x02]),
            ))
        ))
    }

    fn to_bytes(&self) -> Bytes {
        self.encode_ref().to_captured(Mode::Der).into_bytes()
    }
}


//------------ SubjectKeySet -------------------------------------------------

// The captured content only contains the content of the set.
#[derive(Clone, Debug)]
pub struct SubjectKeySet(Captured);

impl SubjectKeySet {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_set(|cons| {
            cons.capture(|cons| {
                KeyIdentifier::skip_in(cons)
            }).map(SubjectKeySet)
        })
    }

    fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::set(
            &self.0
        )
    }
}

impl From<Vec<KeyIdentifier>> for SubjectKeySet {
    fn from(src: Vec<KeyIdentifier>) -> Self {
        SubjectKeySet(Captured::from_values(
            Mode::Der,
            encode::iter(src.iter().map(|item| item.encode_ref()))
        ))
    }
}


//------------ RtaAsBlocks ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct RtaAsBlocks(Captured);

impl RtaAsBlocks {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl RtaAsBlocks {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.capture(|cons| {
                while AsBlock::skip_opt_in(cons)?.is_some() { }
                Ok(())
            })
        }).map(RtaAsBlocks)
    }

    fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence(
            &self.0
        )
    }
}

impl Default for RtaAsBlocks {
    fn default() -> Self {
        RtaAsBlocks(Captured::empty(Mode::Der))
    }
}

impl From<AsBlocksBuilder> for RtaAsBlocks {
    fn from(src: AsBlocksBuilder) -> RtaAsBlocks {
        RtaAsBlocks(Captured::from_values(
            Mode::Der,
            src.finalize().encode()
        ))
    }
}


//------------ RtaIpBlocks ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct RtaIpBlocks(Captured);

impl RtaIpBlocks {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl RtaIpBlocks {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.capture(|cons| {
                while IpBlock::take_opt_from(cons)?.is_some() { }
                Ok(())
            })
        }).map(RtaIpBlocks)
    }

    fn encode_ref_family<'a>(
        &'a self,
        family: [u8; 2]
    ) -> impl encode::Values + 'a {
        if self.0.is_empty() {
            None
        }
        else {
            Some(encode::sequence((
                OctetString::encode_slice(family),
                &self.0
            )))
        }
    }
}

impl Default for RtaIpBlocks {
    fn default() -> Self {
        RtaIpBlocks(Captured::empty(Mode::Der))
    }
}

impl From<IpBlocksBuilder> for RtaIpBlocks {
    fn from(src: IpBlocksBuilder) -> RtaIpBlocks {
        RtaIpBlocks(Captured::from_values(
            Mode::Der,
            src.finalize().encode()
        ))
    }
}


//------------ MultiSignedObject ---------------------------------------------

/// The flavour of a signed object used for RTAs.
#[derive(Clone, Debug)]
pub struct MultiSignedObject {
    digest_algorithm: DigestAlgorithm,
    content: OctetString,
    certificates: CertificateSet,
    crls: CrlSet,
    signer_infos: SignerInfoSet,
}

impl MultiSignedObject {
    /// Returns a reference to the object’s content.
    pub fn content(&self) -> &OctetString {
        &self.content
    }

    /// Decodes the object’s content.
    pub fn decode_content<F, T>(&self, op: F) -> Result<T, decode::Error>
    where F: FnOnce(&mut decode::Constructed<OctetStringSource>)
                    -> Result<T, decode::Error> {
        Mode::Der.decode(self.content.to_source(), op)
    }
}

impl MultiSignedObject {
    pub fn decode<S: decode::Source>(
        source: S,
        _strict: bool
    ) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            oid::SIGNED_DATA.skip_if(cons)?; // contentType
            cons.take_constructed_if(Tag::CTX_0, |cons| { // content
                cons.take_sequence(|cons| { // SignedData
                    cons.skip_u8_if(3)?; // version -- must be 3
                    let digest_algorithm =
                        DigestAlgorithm::take_set_from(cons)?;
                    let content = cons.take_sequence(|cons| {
                        // encapContentInfo
                        oid::CT_RESOURCE_TAGGED_ATTESTATION.skip_if(cons)?;
                        cons.take_constructed_if(
                            Tag::CTX_0,
                            OctetString::take_from
                        )
                    })?;
                    let certificates = CertificateSet::take_if(
                        Tag::CTX_0, cons
                    )?;
                    let crls = CrlSet::take_opt_if(Tag::CTX_1, cons)?;
                    let signer_infos = SignerInfoSet::take_from(cons)?;

                    Ok(MultiSignedObject {
                        digest_algorithm,
                        content,
                        certificates,
                        crls,
                        signer_infos,
                    })
                })
            })
        })
    }

    pub fn validate<F: FnMut(Cert) -> Result<ResourceCert, ValidationError>>(
        self, _strict: bool, _validate_cert: F
    ) -> Result<ResourceTaggedAttestation, ValidationError> {
        unimplemented!()
    }

    /// Returns a value encoder for a reference to a signed object.
    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            oid::SIGNED_DATA.encode(), // contentType
            encode::sequence_as(Tag::CTX_0, // content
                encode::sequence((
                    3u8.encode(), // version
                    self.digest_algorithm.encode_set(), // digestAlgorithms
                    encode::sequence(( // encapContentInfo
                        oid::CT_RESOURCE_TAGGED_ATTESTATION.encode(),
                        encode::sequence_as(Tag::CTX_0,
                            self.content.encode_ref()
                        ),
                    )),
                    encode::sequence_as(Tag::CTX_0, // certificates
                        self.certificates.encode_ref(),
                    ),
                    self.crls.encode_ref_as(Tag::CTX_1),
                    encode::sequence(self.signer_infos.encode_ref()),
                )),
            )
        ))
    }
}


//------------ CertificateSet ------------------------------------------------

// The captured content is the content of the set. We only support a
// certificate choice of a certificate.
#[derive(Clone, Debug)]
pub struct CertificateSet(Captured);

impl From<Vec<Cert>> for CertificateSet {
    fn from(src: Vec<Cert>) -> CertificateSet {
        CertificateSet(Captured::from_values(
            Mode::Der,
            encode::iter(src.iter().map(|item| item.encode_ref()))
        ))
    }
}

impl CertificateSet {
    pub fn collect_certs(self) -> Vec<Cert> {
        self.0.decode(|cons| {
            let mut res = Vec::new();
            while let Some(cert) = Cert::take_opt_from(cons)? {
                res.push(cert)
            }
            Ok(res)
        }).unwrap()
    }
}

impl CertificateSet {
    pub fn take_if<S: decode::Source>(
        tag: Tag, cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_constructed_if(tag, |cons| {
            cons.capture(|cons| {
                while Cert::take_opt_from(cons)?.is_some() { }
                Ok(())
            })
        }).map(CertificateSet)
    }

    /// Returns a value encoder for a reference to a signed object.
    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        &self.0
    }
}


//------------ CrlSet --------------------------------------------------------

// The captured content is the content of the set. We only support a
// choice of a CRL.
#[derive(Clone, Debug)]
pub struct CrlSet(Captured);

impl From<Vec<Crl>> for CrlSet {
    fn from(src: Vec<Crl>) -> CrlSet {
        CrlSet(Captured::from_values(
            Mode::Der,
            encode::iter(src.iter().map(|item| item.encode_ref()))
        ))
    }
}

impl CrlSet {
    pub fn collect_crls(self) -> Vec<Crl> {
        self.0.decode(|cons| {
            let mut res = Vec::new();
            while let Some(crl) = Crl::take_opt_from(cons)? {
                res.push(crl)
            }
            Ok(res)
        }).unwrap()
    }
}

impl CrlSet {
    pub fn take_opt_if<S: decode::Source>(
        tag: Tag, cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let res = cons.take_opt_constructed_if(tag, |cons| {
            cons.capture(|cons| {
                while Crl::take_opt_from(cons)?.is_some() { }
                Ok(())
            })
        })?;
        Ok(CrlSet(res.unwrap_or_else(|| Captured::empty(Mode::Der))))
    }


    /// Returns a value encoder for a reference to a signed object.
    pub fn encode_ref_as<'a>(&'a self, tag: Tag) -> impl encode::Values + 'a {
        if self.0.is_empty() {
            None
        }
        else {
            Some(encode::sequence_as(tag, &self.0))
        }
    }
}


//------------ SignerInfoSet -------------------------------------------------

#[derive(Clone, Debug)]
pub struct SignerInfoSet(Captured);

impl From<Vec<SignerInfo>> for SignerInfoSet {
    fn from(src: Vec<SignerInfo>) -> SignerInfoSet {
        SignerInfoSet(Captured::from_values(
            Mode::Der,
            encode::iter(src.iter().map(|item| item.encode_ref()))
        ))
    }
}

impl SignerInfoSet {
    pub fn collect_signer_infos(
        self,
    ) -> Vec<SignerInfo> {
        self.0.decode(|cons| {
            let mut res = Vec::new();
            while let Some(crl) = SignerInfo::take_opt_from(
                cons
            )? {
                res.push(crl)
            }
            Ok(res)
        }).unwrap()
    }
}

impl SignerInfoSet {
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_set(|cons| {
            cons.capture(|cons| {
                while SignerInfo::take_opt_from(cons)?.is_some() { }
                Ok(())
            })
        }).map(SignerInfoSet)
    }

    /// Returns a value encoder for a reference to a signed object.
    pub fn encode_ref<'a>( &'a self) -> impl encode::Values + 'a {
        &self.0
    } 
}


//------------ SignerInfo ----------------------------------------------------

/// A single SignerInfo of a signed object.
#[derive(Clone, Debug)]
pub struct SignerInfo {
    sid: KeyIdentifier,
    digest_algorithm: DigestAlgorithm,
    signed_attrs: SignedAttrs,
    signature: Signature,

    //--- SignedAttributes
    //
    message_digest: MessageDigest,
    signing_time: Option<Time>,
    binary_signing_time: Option<u64>,
}

impl SignerInfo {
    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_sequence(|cons| {
            cons.skip_u8_if(3)?;
            let sid = cons.take_value_if(
                Tag::CTX_0, |content| {
                    KeyIdentifier::from_content(content)
                }
            )?;
            let alg = DigestAlgorithm::take_from(cons)?;
            let attrs = SignedAttrs::take_from(cons)?;
            if attrs.2 != oid::CT_RESOURCE_TAGGED_ATTESTATION {
                return Err(decode::Malformed.into())
            }
            let signature = Signature::new(
                SignatureAlgorithm::cms_take_from(cons)?,
                OctetString::take_from(cons)?.into_bytes()
            );
            // no unsignedAttributes
            Ok(SignerInfo {
                sid,
                digest_algorithm: alg,
                signed_attrs: attrs.0,
                signature,
                message_digest: attrs.1,
                signing_time: attrs.3,
                binary_signing_time: attrs.4
            })
        })
    }

    pub fn encode_ref<'a>( &'a self) -> impl encode::Values + 'a {
        encode::sequence((
            self.sid.encode_ref_as(Tag::CTX_0),
            self.digest_algorithm.encode(), // digestAlgorithm
            self.signed_attrs.encode_ref(), // signedAttrs
            self.signature.algorithm().cms_encode(),
                                        // signatureAlgorithm
            OctetString::encode_slice( // signature
                self.signature.value().as_ref()
            ),
            // unsignedAttrs omitted
        ))
    }
}


//------------ AttestationBuilder --------------------------------------------

pub struct AttestationBuilder {
    keys: Vec<KeyIdentifier>,
    as_resources: AsBlocksBuilder,
    v4_resources: IpBlocksBuilder,
    v6_resources: IpBlocksBuilder,
    digest_algorithm: DigestAlgorithm,
    message_digest: MessageDigest,
}

impl AttestationBuilder {
    pub fn new(
        digest_algorithm: DigestAlgorithm,
        message_digest: MessageDigest
    ) -> Self {
        AttestationBuilder {
            keys: Vec::new(),
            as_resources: AsBlocksBuilder::new(),
            v4_resources: IpBlocksBuilder::new(),
            v6_resources: IpBlocksBuilder::new(),
            digest_algorithm, message_digest
        }
    }

    pub fn push_key(&mut self, key: KeyIdentifier) {
        self.keys.push(key)
    }

    pub fn keys(&self) -> &[KeyIdentifier] {
        &self.keys
    }

    pub fn keys_mut(&mut self) -> &mut Vec<KeyIdentifier> {
        &mut self.keys
    }

    pub fn push_as(&mut self, block: impl Into<AsBlock>) {
        self.as_resources.push(block)
    }

    pub fn as_resources(&self) -> &AsBlocksBuilder {
        &self.as_resources
    }

    pub fn as_resources_mut(&mut self) -> &mut AsBlocksBuilder {
        &mut self.as_resources
    }

    pub fn push_v4(&mut self, block: impl Into<IpBlock>) {
        self.v4_resources.push(block)
    }

    pub fn v4_resources(&self) -> &IpBlocksBuilder {
        &self.v4_resources
    }

    pub fn v4_resources_mut(&mut self) ->&mut IpBlocksBuilder {
        &mut self.v4_resources
    }

    pub fn push_v6(&mut self, block: impl Into<IpBlock>) {
        self.v6_resources.push(block)
    }

    pub fn v6_resources(&self) -> &IpBlocksBuilder {
        &self.v6_resources
    }

    pub fn v6_resources_mut(&mut self) -> &mut IpBlocksBuilder {
        &mut self.v6_resources
    }

    pub fn into_attestation(self) -> ResourceTaggedAttestation {
        ResourceTaggedAttestation {
            subject_keys: self.keys.into(),
            as_resources: self.as_resources.into(),
            v4_resources: self.v4_resources.into(),
            v6_resources: self.v6_resources.into(),
            digest_algorithm: self.digest_algorithm,
            message_digest: self.message_digest,
        }
    }

    pub fn into_rta_builder(self) -> RtaBuilder {
        RtaBuilder::from_attestation(self.into_attestation())
    }
}


//------------ RtaBuilder ----------------------------------------------------

pub struct RtaBuilder {
    digest_algorithm: DigestAlgorithm,
    encoded_content: Bytes,
    content: ResourceTaggedAttestation,
    certificates: Vec<Cert>,
    crls: Vec<Crl>,
    signer_infos: Vec<SignerInfo>,
}

impl RtaBuilder {
    pub fn from_attestation(content: ResourceTaggedAttestation) -> Self {
        RtaBuilder {
            digest_algorithm: DigestAlgorithm::default(),
            encoded_content: content.to_bytes(),
            content,
            certificates: Vec::new(),
            crls: Vec::new(),
            signer_infos: Vec::new()
        }
    }

    pub fn from_rta(rta: Rta) -> Self {
        RtaBuilder {
            digest_algorithm: DigestAlgorithm::default(),
            encoded_content: rta.signed.content.to_bytes(),
            content: rta.content,
            certificates: rta.signed.certificates.collect_certs(),
            crls: rta.signed.crls.collect_crls(),
            signer_infos: rta.signed.signer_infos.collect_signer_infos(),
        }
    }

    pub fn content(&self) -> &ResourceTaggedAttestation {
        &self.content
    }

    pub fn push_cert(&mut self, cert: Cert) {
        self.certificates.push(cert)
    }

    pub fn certificates(&self) -> &[Cert] {
        &self.certificates
    }

    pub fn certificates_mut(&mut self) -> &mut Vec<Cert> {
        &mut self.certificates
    }

    pub fn push_crl(&mut self, crl: Crl) {
        self.crls.push(crl)
    }

    pub fn crls(&self) -> &[Crl] {
        &self.crls
    }

    pub fn crls_mut(&mut self) -> &mut Vec<Crl> {
        &mut self.crls
    }

    pub fn sign<S: Signer>(
        &mut self,
        signer: &S,
        key: &S::KeyId,
        signing_time: Option<Time>,
        binary_signing_time: Option<u64>,
    ) -> Result<(), SigningError<S::Error>> {
        // Produce the content digest
        let message_digest = self.digest_algorithm.digest(
            &self.encoded_content
        ).into();

        // Produce signed attributes.
        let signed_attrs = SignedAttrs::new(
            &oid::CT_RESOURCE_TAGGED_ATTESTATION,
            &message_digest,
            signing_time,
            binary_signing_time
        );

        // Sign those attributes
        let signature = signer.sign(
            key, SignatureAlgorithm::default(),
            &signed_attrs.encode_verify()
        )?;

        self.signer_infos.push(SignerInfo {
            sid: KeyIdentifier::from_public_key(&signer.get_key_info(key)?),
            digest_algorithm: self.digest_algorithm,
            signed_attrs,
            signature,
            message_digest,
            signing_time,
            binary_signing_time
        });
        Ok(())
    }

    pub fn signer_infos(&self) -> &[SignerInfo] {
        &self.signer_infos
    }

    pub fn signer_infos_mut(&mut self) -> &mut Vec<SignerInfo> {
        &mut self.signer_infos
    }

    pub fn finalize(self) -> Rta {
        Rta {
            signed: MultiSignedObject {
                digest_algorithm: self.digest_algorithm,
                content: OctetString::new(self.encoded_content),
                certificates: self.certificates.into(),
                crls: self.crls.into(),
                signer_infos: self.signer_infos.into(),
            },
            content: self.content,
        }
    }
}

