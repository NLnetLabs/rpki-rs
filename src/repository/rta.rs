//! Resource Tagged Attestations.
//!
//! Resource Tagged Attestations attaching signed attestations of ownership of 
//! resources referred to by a document. This is currently an IETF draft,
//! see [draft-michaelson-rpki-rta] for details.
//!
//! Current limitations:
//!
//! * Resources are read in a rather relaxed way: they can be unordered and
//!   overlapping. This happens even if the strict flag is set.
//!
//! [draft-michaelson-rpki-rta]: https://tools.ietf.org/html/draft-michaelson-rpki-rta

use std::ops;
use bcder::{decode, encode};
use bcder::{Captured, Mode, OctetString, Tag};
use bcder::encode::{PrimitiveContent, Values};
use bcder::string::OctetStringSource;
use bcder::xerr;
use bytes::Bytes;
use crate::oid;
use crate::crypto:: {
    Digest, DigestAlgorithm, KeyIdentifier, RpkiSignature,
    RpkiSignatureAlgorithm, Signer, SigningError
};
use super::cert::{Cert, Overclaim, ResourceCert};
use super::crl::Crl;
use super::resources::{
    AddressFamily, AsBlock, AsBlocks, AsBlocksBuilder, IpBlock, IpBlocks,
    IpBlocksBuilder,
};
use super::sigobj::{MessageDigest, SignedAttrs};
use super::tal::Tal;
use super::x509::{Time, ValidationError};


//------------ Rta -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Rta {
    signed: MultiSignedObject,
    content: ResourceTaggedAttestation,
}

impl Rta {
    pub fn content(&self) -> &ResourceTaggedAttestation {
        &self.content
    }

    pub fn decode<S: decode::Source>(
        source: S, strict: bool
    ) -> Result<Self, S::Err> {
        let signed = MultiSignedObject::decode(source, strict)?;
        let content = signed.decode_content(|cons| {
            ResourceTaggedAttestation::take_from(cons)
        })?;
        Ok(Rta { signed, content })
    }

    /// Returns a value encoder for a reference to a ROA.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        self.signed.encode_ref()
    }

    /// Returns a DER encoded Captured for this ROA.
    pub fn to_captured(&self) -> Captured {
        self.encode_ref().to_captured(Mode::Der)
    }
}


//--- Deref and AsRef

impl ops::Deref for Rta {
    type Target = ResourceTaggedAttestation;

    fn deref(&self) -> &Self::Target {
        self.content()
    }
}

impl AsRef<ResourceTaggedAttestation> for Rta {
    fn as_ref(&self) -> &ResourceTaggedAttestation {
        self.content()
    }
}


//------------ ResourceTaggedAttestation -------------------------------------

#[derive(Clone, Debug)]
pub struct ResourceTaggedAttestation {
    subject_keys: Vec<KeyIdentifier>,

    /// AS Resources
    as_resources: AsBlocks,

    /// IP Resources for the IPv4 address family.
    v4_resources: IpBlocks,

    /// IP Resources for the IPv6 address family.
    v6_resources: IpBlocks,

    digest_algorithm: DigestAlgorithm,

    message_digest: MessageDigest,
}

impl ResourceTaggedAttestation {
    pub fn subject_keys(&self) -> &[KeyIdentifier] {
        &self.subject_keys
    }

    pub fn as_resources(&self) -> &AsBlocks {
        &self.as_resources
    }

    pub fn v4_resources(&self) -> &IpBlocks {
        &self.v4_resources
    }

    pub fn v6_resources(&self) -> &IpBlocks {
        &self.v6_resources
    }

    pub fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    pub fn message_digest(&self) -> &MessageDigest {
        &self.message_digest
    }
}

impl ResourceTaggedAttestation {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.take_opt_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(0))?;
            let subject_keys = Self::take_subject_keys_from(cons)?;
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

    fn take_subject_keys_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Vec<KeyIdentifier>, S::Err> {
        cons.take_set(|cons| {
            let mut res = Vec::new();
            while let Some(id) = KeyIdentifier::take_opt_from(cons)? {
                res.push(id)
            }
            Ok(res)
        })
    }

    fn take_resources_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(IpBlocks, IpBlocks, AsBlocks), S::Err> {
        cons.take_sequence(|cons| {
            let asres = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                AsBlocks::take_from(cons)
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
                                v4 = Some(IpBlocks::take_from_with_family(
                                    cons, AddressFamily::Ipv4
                                )?);
                            }
                            AddressFamily::Ipv6 => {
                                if v6.is_some() {
                                    xerr!(return Err(decode::Malformed.into()));
                                }
                                v6 = Some(IpBlocks::take_from_with_family(
                                    cons, AddressFamily::Ipv6
                                )?);
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

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            // version is DEFAULT
            encode::set(
                encode::iter(self.subject_keys.iter().map(|item| {
                    item.encode_ref()
                }))
            ),
            encode::sequence((
                self.encode_as_resources(),
                self.encode_ip_resources(),
            )),
            self.digest_algorithm.encode(),
            self.message_digest.encode_ref()
        ))
    }

    fn encode_as_resources(&self) -> impl encode::Values + '_ {
        if self.as_resources.is_empty() {
            None
        }
        else {
            Some(encode::sequence_as(Tag::CTX_0,
                encode::sequence(
                    self.as_resources.encode_ref()
                )
            ))
        }
    }

    fn encode_ip_resources(&self) -> impl encode::Values + '_ {
        if self.v4_resources.is_empty() && self.v6_resources.is_empty() {
            return None
        }
        Some(encode::sequence_as(Tag::CTX_1,
            encode::sequence((
                self.v4_resources.encode_family(AddressFamily::Ipv4),
                self.v6_resources.encode_family(AddressFamily::Ipv6),
            ))
        ))
    }

    fn to_bytes(&self) -> Bytes {
        self.encode_ref().to_captured(Mode::Der).into_bytes()
    }
}


//------------ MultiSignedObject ---------------------------------------------

/// The flavour of a signed object used for RTAs.
#[derive(Clone, Debug)]
pub struct MultiSignedObject {
    digest_algorithm: DigestAlgorithm,
    content: OctetString,
    certificates: Vec<Cert>,
    crls: Vec<Crl>,
    signer_infos: Vec<SignerInfo>,
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
        source: S, strict: bool
    ) -> Result<Self, S::Err> {
        Mode::Der.decode(source, |cons| Self::take_from(cons, strict))
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>, strict: bool
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
                    let certificates = Self::take_certificates(cons, strict)?;
                    let crls = Self::take_crls(cons, strict)?;
                    let signer_infos = Self::take_signer_infos(cons, strict)?;

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

    fn take_certificates<S: decode::Source>(
        cons: &mut decode::Constructed<S>, _strict: bool
    ) -> Result<Vec<Cert>, S::Err> {
        cons.take_constructed_if(Tag::CTX_0, |cons| {
            let mut certificates = Vec::new();
            while let Some(cert) = Cert::take_opt_from(cons)? {
                certificates.push(cert);
            }
            Ok(certificates)
        })
    }

    fn take_crls<S: decode::Source>(
        cons: &mut decode::Constructed<S>, _strict: bool
    ) -> Result<Vec<Crl>, S::Err> {
        cons.take_opt_constructed_if(Tag::CTX_1, |cons| {
            let mut crls = Vec::new();
            while let Some(crl) = Crl::take_opt_from(cons)? {
                crls.push(crl);
            }
            Ok(crls)
        }).map(|item| item.unwrap_or_default())
    }

    fn take_signer_infos<S: decode::Source>(
        cons: &mut decode::Constructed<S>, _strict: bool
    ) -> Result<Vec<SignerInfo>, S::Err> {
        cons.take_set(|cons| {
            let mut infos = Vec::new();
            while let Some(info) = SignerInfo::take_opt_from(cons)? {
                infos.push(info);
            }
            Ok(infos)
        })
    }

    /// Returns a value encoder for a reference to a signed object.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
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
                        encode::iter(self.certificates.iter().map(|item| {
                            item.encode_ref()
                        }))
                    ),
                    if self.crls.is_empty() {
                        None
                    }
                    else {
                        Some(encode::sequence_as(Tag::CTX_1, // crls
                            encode::iter(self.crls.iter().map(|item| {
                                item.encode_ref()
                            }))
                        ))
                    },
                    encode::set(
                        encode::iter(self.signer_infos.iter().map(|item| {
                            item.encode_ref()
                        }))
                    )
                )),
            )
        ))
    }
}


//------------ SignerInfo ----------------------------------------------------

/// A single SignerInfo of a signed object.
#[derive(Clone, Debug)]
pub struct SignerInfo {
    sid: KeyIdentifier,
    digest_algorithm: DigestAlgorithm,
    signed_attrs: SignedAttrs,
    signature: RpkiSignature,

    //--- SignedAttributes
    //
    message_digest: MessageDigest,
    signing_time: Option<Time>,
    binary_signing_time: Option<u64>,
}

impl SignerInfo {
    /// Returns the signing time if available.
    pub fn signing_time(&self) -> Option<Time> {
        self.signing_time
    }

    /// Returns the binary signing time if available.
    pub fn binary_signing_time(&self) -> Option<u64> {
        self.binary_signing_time
    }

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
            let signature = RpkiSignature::new(
                RpkiSignatureAlgorithm::cms_take_from(cons)?,
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

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            3u8.encode(), // version
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


//------------ Validation ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct Validation<'a> {
    /// The RTA object we are validating.
    rta: &'a Rta,

    /// The validation chains we need to validate.
    chains: Vec<Chain<'a>>,

    /// Are we doing strict validation?
    strict: bool,

    /// What time is it, Geoff Peterson?
    now: Time,
}

impl<'a> Validation<'a> {
    pub fn new(
        rta: &'a Rta, strict: bool
    ) -> Result<Self, ValidationError> {
        Self::new_at(rta, strict, Time::now())
    }

    pub fn new_at(
        rta: &'a Rta, strict: bool, now: Time,
    ) -> Result<Self, ValidationError> {
        // Get a vec with options of refs to the CRLs. Whenever we used a CRL
        // in a CA, we take it out. Thus, at the end we need to have all
        // `None` in the vec.
        let mut crls: Vec<_> = rta.signed.crls.iter().map(Some).collect();

        // Ditto for the subject keys included with the content.
        let mut keys: Vec<_> = rta.content.subject_keys.iter().map(|key| {
            Some(*key)
        }).collect();

        // Calculate the digest of the content.
        let digest = {
            let mut context = rta.signed.digest_algorithm.start();
            rta.signed.content.iter().for_each(|x| context.update(x));
            context.finish()
        };

        // Process all certificates. CA certificates go into the CA vec and
        // EE certificates go into a temporary option-vec which we use when
        // creating chains from signer-infos later.
        let mut cas = Vec::new();
        let mut ees = Vec::new();
        for cert in &rta.signed.certificates {
            if cert.basic_ca().is_none() {
                cert.inspect_detached_ee_at(strict, now)?;
                ees.push(Some(cert));
            }
            else {
                cas.push(Ca::new(cert, &mut crls, strict, now)?);
            }
        }

        let mut chains = Vec::new();
        for info in &rta.signed.signer_infos {
            chains.push(
                Chain::new(info, &digest, &mut keys, &mut ees)?
            )
        }

        // All subject keys need to have been used.
        if keys.iter().any(|item| item.is_some()) {
            xerr!(return Err(ValidationError))
        }

        // All CRLs need to have been used.
        if crls.iter().any(|item| item.is_some()) {
            xerr!(return Err(ValidationError))
        }

        // All EE certificates have to have been used.
        if ees.iter().any(|item| item.is_some()) {
            xerr!(return Err(ValidationError))
        }

        // Create the object and advance the chains using the CA certificates
        // we have.
        let mut res = Validation { rta, chains, strict, now };
        res.advance_chains(&mut cas)?;

        // All the CA certificates have to have been used.
        if cas.iter().any(|item| !item.used) {
            xerr!(return Err(ValidationError))
        }

        // Hurray!
        Ok(res)
    }

    fn advance_chains(
        &mut self, cas: &mut [Ca<'a>]
    ) -> Result<(), ValidationError> {
        for chain in &mut self.chains {
            chain.advance(cas, self.strict)?;
        }
        Ok(())
    }

    pub fn supply_tal(&mut self, tal: &Tal) -> Result<bool, ValidationError> {
        let mut done = true;
        for chain in &mut self.chains {
            if !chain.supply_tal(tal, self.strict, self.now)? {
                done = false
            }
        }
        Ok(done)
    }

    pub fn supply_ca(
        &mut self, ca: &ResourceCert
    ) -> Result<bool, ValidationError> {
        let mut done = true;
        for chain in &mut self.chains {
            if !chain.supply_ca(ca, self.strict, self.now)? {
                done = false
            }
        }
        Ok(done)
    }

    pub fn finalize(
        self
    ) -> Result<&'a ResourceTaggedAttestation, ValidationError> {
        let mut asn = AsBlocksBuilder::new();
        let mut v4 = IpBlocksBuilder::new();
        let mut v6 = IpBlocksBuilder::new();

        for chain in &self.chains {
            chain.finalize(&mut asn, &mut v4, &mut v6)?;
        }

        let asn = asn.finalize();
        let v4 = v4.finalize();
        let v6 = v6.finalize();

        if asn != self.rta.content.as_resources
            || v4 != self.rta.content.v4_resources
            || v6 != self.rta.content.v6_resources
        {
            return Err(ValidationError)
        }

        Ok(self.rta)
    }
}


//------------ Ca ------------------------------------------------------------

#[derive(Clone, Debug)]
struct Ca<'a> {
    cert: &'a Cert,
    crl: &'a Crl,
    used: bool,
}

impl<'a> Ca<'a> {
    fn new(
        cert: &'a Cert,
        crls: &mut [Option<&'a Crl>],
        strict: bool, now: Time,
    ) -> Result<Self, ValidationError> {
        cert.inspect_ca_at(strict, now)?;
        Ok(Ca {
            cert,
            crl: Self::find_crl(cert, crls)?,
            used: false
        })
    }

    fn find_crl<'c>(
        cert: &Cert, crls: &mut [Option<&'c Crl>]
    ) -> Result<&'c Crl, ValidationError> {
        for crl in crls {
            match crl.as_ref() {
                Some(crl) => {
                    if *crl.authority_key_identifier()
                        != cert.subject_key_identifier()
                    {
                        continue
                    }
                    if crl.validate(cert.subject_public_key_info()).is_err() {
                        continue
                    }
                }
                None => continue
            }
            return Ok(crl.take().unwrap())
        }
        Err(ValidationError)
    }
}


//------------ Chain ---------------------------------------------------------

#[derive(Clone, Debug)]
struct Chain<'a> {
    /// The topmost certificate of the path.
    cert: &'a Cert,

    /// The resources of the topmost cert.
    cert_resources: CertResources,

    /// The resources of the entire path.
    chain_resources: CertResources,

    /// Has the chain been validated?
    validated: bool,
}

impl<'a> Chain<'a> {
    //--- new and helpers

    fn new(
        info: &SignerInfo,
        digest: &Digest,
        keys: &mut [Option<KeyIdentifier>],
        ees: &mut [Option<&'a Cert>],
    ) -> Result<Self, ValidationError> {
        // Find and removed sid in keys.
        match keys.iter_mut().find(|item| **item == Some(info.sid)) {
            Some(item) => *item = None,
            None => xerr!(return Err(ValidationError))
        }

        // Verify the message digest attribute
        if digest.as_ref() != info.message_digest.as_ref() {
            return xerr!(Err(ValidationError))
        }

        // Find th EE cert that signed this signer info.
        let ee = Self::find_cert(info, ees)?;

        let resources = CertResources::new(ee);
        Ok(Chain {
            cert: ee,
            cert_resources: resources.clone(),
            chain_resources: resources,
            validated: false
        })
    }

    fn find_cert(
        info: &SignerInfo,
        ees: &mut [Option<&'a Cert>]
    ) -> Result<&'a Cert, ValidationError> {
        let msg = info.signed_attrs.encode_verify();
        for item in ees {
            if let Some(cert) = *item {
                if cert.subject_key_identifier() != info.sid {
                    continue
                }
                if cert.subject_public_key_info().verify(
                    &msg,
                    &info.signature
                ).is_err() {
                    continue
                }
                *item = None;
                return Ok(cert)
            }

        }
        xerr!(Err(ValidationError))
    }

    //--- advance and helpers

    fn advance(
        &mut self,
        cas: &mut [Ca<'a>],
        strict: bool,
    ) -> Result<(), ValidationError> {
        while let Some(ca) = self.find_ca(cas, strict)? {
            self.apply_ca(ca)?;
            ca.used = true;
        }
        Ok(())
    }

    fn find_ca<'c>(
        &self,
        cas: &'c mut [Ca<'a>],
        strict: bool,
    ) -> Result<Option<&'c mut Ca<'a>>, ValidationError> {
        // If we don’t have an authority key identifier on the cert, it is
        // self-signed and we are done. If we do have one and it is the same
        // as the subject key identifier, it is self-signed, too.
        let aki = match self.cert.authority_key_identifier() {
            Some(aki) if aki == self.cert.subject_key_identifier() => {
                return Ok(None)
            }
            Some(aki) => aki,
            None => return Ok(None)
        };

        let mut found = false;
        for ca in cas {
            if ca.cert.subject_key_identifier() != aki {
                continue
            }
            found = true;
            if self.cert.verify_signature(ca.cert, strict).is_err() {
                continue
            }
            return Ok(Some(ca))
        }
        if found {
            xerr!(Err(ValidationError))
        }
        else {
            Ok(None)
        }
    }

    fn apply_ca(&mut self, ca: &Ca<'a>) -> Result<(), ValidationError> {
        // Check that our cert hasn’t been revoked.
        if ca.crl.contains(self.cert.serial_number()) {
            xerr!(return Err(ValidationError))
        }

        // Check if the CA allows us to have our resources.
        self.verify_resources(ca)?;

        // Now update self to reflect the new head of chain cert.
        self.update_head(ca);

        Ok(())
    }

    fn verify_resources(&self, ca: &Ca) -> Result<(), ValidationError> {
        // If our cert is of the resource trimming kind, we don’t actually
        // need to check but rather have to trim resources later on.
        if self.cert.overclaim() == Overclaim::Trim {
            return Ok(())
        }
        
        // If we have a certain resource, it needs to be covered by the CA.
        // If the CA has that resource as inherited, that qualifies as valid,
        // too.
        if let Some(blocks) = self.cert_resources.as_resources.as_ref() {
            blocks.verify_covered(ca.cert.as_resources())?
        }
        if let Some(blocks) = self.cert_resources.v4_resources.as_ref() {
            blocks.verify_covered(ca.cert.v4_resources())?
        }
        if let Some(blocks) = self.cert_resources.v6_resources.as_ref() {
            blocks.verify_covered(ca.cert.v6_resources())?
        }

        Ok(())
    }

    fn update_head(&mut self, ca: &Ca<'a>) {
        // Let’s get the CA’s resources so we can play with them.
        let ca_resources = CertResources::new(ca.cert);

        // If our current head has a resource trimming certificate, we first
        // need to trim back the chain resources to whatever the CA allows.
        if self.cert.overclaim() == Overclaim::Trim {
            self.chain_resources.trim_to(&ca_resources);
        }

        // Next we update remaining inherited chain resources to what the CA
        // has (unless it is inherited, too).
        self.chain_resources.replace_inherited(&ca_resources);

        // Now we can update the head resources and certificate, leaving
        // inherited resources in the CA untouched.
        self.cert_resources.update_head(ca_resources);
        self.cert = ca.cert;
    }


    //--- supply_tal and supply_ca

    fn supply_tal(
        &mut self, tal: &Tal, strict: bool, now: Time
    ) -> Result<bool, ValidationError> {
        if self.validated {
            return Ok(true)
        }

        // If we have a self-signed certificate, it is a TA certificate and
        // we don’t need to bother checking.
        if self.cert.is_self_signed() {
            return Ok(false)
        }

        // Let’s see if the key matches.
        if self.cert.subject_public_key_info() != tal.key_info() {
            return Ok(false)
        }

        // Finally, let’s see if we have a proper TA certificate. We only do
        // this now so we don’t check over and over again. We also will never
        // check a certificate that doesn’t have a matching TAL which will
        // safe a little extra time.
        self.cert.inspect_ta_at(strict, now)?;
        self.cert.verify_ta_ref(strict)?;

        self.validated = true;
        Ok(true)
    }

    fn supply_ca(
        &mut self, ca: &ResourceCert, strict: bool, now: Time
    ) -> Result<bool, ValidationError> {
        if self.validated {
            return Ok(true)
        }

        // Quick check first: If we don’t have an AKI, we are our own CA and
        // don’t need to continue here.
        if self.cert.authority_key_identifier().is_none() {
            return Ok(false)
        }

        // Now check properly if `ca` should be our CA and return if it isn’t.
        //
        // If it isn’t not all is lost. There may just be a key identifier
        // collision or something. Unlikely but hey.
        if self.cert.verify_issuer_claim(ca, strict).is_err()
            || self.cert.verify_signature(ca, strict).is_err()
        {
            return Ok(false)
        }

        // Now let’s see if our certificate is a proper CA or EE certificate.
        //
        // basic_ca must be present (and true) for CA certs and not present
        // for EE certs, so we can use that. If it has the wrong value, the
        // cert is broken, so the check will fail and all is good.
        //
        // We will error out here if the cert is broken because, well, the
        // cert is broken.
        if self.cert.basic_ca().is_some() {
            self.cert.inspect_ca_at(strict, now)?;
        }
        else {
            self.cert.inspect_detached_ee_at(strict, now)?;
        }

        // Finally, resources. If they don’t check out, we can error out ...
        // I think.
        //
        // Remember that our cert may be of the resource trimming kind,
        // though.
        if self.cert.overclaim() == Overclaim::Trim {
            self.chain_resources.trim_to_issuer(ca);
        }
        else {
            self.cert_resources.verify_issuer(ca)?;
        }

        // If we still have inherited resources left, replace them with the
        // CA cert.
        self.chain_resources.replace_inherited_from_issuer(ca);

        self.validated = true;
        Ok(true)
    }

    //--- finalize

    fn finalize(
        &self,
        asn: &mut AsBlocksBuilder,
        v4: &mut IpBlocksBuilder,
        v6: &mut IpBlocksBuilder
    ) -> Result<(), ValidationError> {
        if !self.validated {
            return Err(ValidationError)
        }

        // Add all our resources to the collection of resources.
        //
        // We can’t really have inherited resources left (if the top was a TA
        // certificate, we should have rejected it already in this case and
        // otherwise we checked it against a resource CA cert from outside
        // which always has all resources) resources left, so let’s unwrap
        // here to indicate a programming error.
        asn.extend(self.chain_resources.as_resources.as_ref().unwrap().iter());
        v4.extend(self.chain_resources.v4_resources.as_ref().unwrap().iter());
        v6.extend(self.chain_resources.v6_resources.as_ref().unwrap().iter());

        Ok(())
    }
}


//------------ CertResources -------------------------------------------------

#[derive(Clone, Debug)]
struct CertResources {
    /// The AS resources.
    ///
    /// A value of `None` means the resources are inherited from the CA.
    as_resources: Option<AsBlocks>,

    /// The IPv4 resources.
    ///
    /// A value of `None` means the resources are inherited from the CA.
    v4_resources: Option<IpBlocks>,

    /// The IPv6 resources.
    ///
    /// A value of `None` means the resources are inherited from the CA.
    v6_resources: Option<IpBlocks>,
}

impl CertResources {
    fn new(cert: &Cert) -> Self {
        CertResources {
            as_resources: cert.as_resources().to_blocks().ok(),
            v4_resources: cert.v4_resources().to_blocks().ok(),
            v6_resources: cert.v6_resources().to_blocks().ok(),
        }
    }

    fn trim_to(&mut self, ca: &CertResources) {
        if let (Some(my), Some(them)) = (
            self.as_resources.as_mut(), ca.as_resources.as_ref()
        ) {
            my.intersection_assign(them)
        }
        if let (Some(my), Some(them)) = (
            self.v4_resources.as_mut(), ca.v4_resources.as_ref()
        ) {
            my.intersection_assign(them)
        }
        if let (Some(my), Some(them)) = (
            self.v6_resources.as_mut(), ca.v6_resources.as_ref()
        ) {
            my.intersection_assign(them)
        }
    }

    fn trim_to_issuer(&mut self, issuer: &ResourceCert) {
        if let Some(res) = self.as_resources.as_mut() {
            res.intersection_assign(issuer.as_resources())
        }
        if let Some(res) = self.v4_resources.as_mut() {
            res.intersection_assign(issuer.v4_resources())
        }
        if let Some(res) = self.v6_resources.as_mut() {
            res.intersection_assign(issuer.v6_resources())
        }
    }

    fn verify_issuer(
        &self, issuer: &ResourceCert
    ) -> Result<(), ValidationError> {
        if let Some(res) = self.as_resources.as_ref() {
            if !issuer.as_resources().contains(res) {
                return Err(ValidationError)
            }
        }
        if let Some(res) = self.v4_resources.as_ref() {
            if !issuer.v4_resources().contains(res) {
                return Err(ValidationError)
            }
        }
        if let Some(res) = self.v6_resources.as_ref() {
            if !issuer.v6_resources().contains(res) {
                return Err(ValidationError)
            }
        }
        Ok(())
    }

    fn replace_inherited(&mut self, ca: &CertResources) {
        if self.as_resources.is_none() {
            self.as_resources = ca.as_resources.clone()
        }
        if self.v4_resources.is_none() {
            self.v4_resources = ca.v4_resources.clone()
        }
        if self.v6_resources.is_none() {
            self.v6_resources = ca.v6_resources.clone()
        }
    }

    fn replace_inherited_from_issuer(&mut self, ca: &ResourceCert) {
        if self.as_resources.is_none() {
            self.as_resources = Some(ca.as_resources().clone())
        }
        if self.v4_resources.is_none() {
            self.v4_resources = Some(ca.v4_resources().clone())
        }
        if self.v6_resources.is_none() {
            self.v6_resources = Some(ca.v6_resources().clone())
        }
    }

    fn update_head(&mut self, ca: CertResources) {
        if let Some(res) = ca.as_resources {
            self.as_resources = Some(res)
        }
        if let Some(res) = ca.v4_resources {
            self.v4_resources = Some(res)
        }
        if let Some(res) = ca.v6_resources {
            self.v6_resources = Some(res)
        }
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
            subject_keys: self.keys,
            as_resources: self.as_resources.finalize(),
            v4_resources: self.v4_resources.finalize(),
            v6_resources: self.v6_resources.finalize(),
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
            certificates: rta.signed.certificates,
            crls: rta.signed.crls,
            signer_infos: rta.signed.signer_infos,
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
            key, RpkiSignatureAlgorithm::default(),
            &signed_attrs.encode_verify()
        )?;

        self.signer_infos.push(SignerInfo {
            sid: signer.get_key_info(key)?.key_identifier(),
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
                certificates: self.certificates,
                crls: self.crls,
                signer_infos: self.signer_infos,
            },
            content: self.content,
        }
    }
}

