//! Autonomous System Provider Authorization
//!
//! This is still being discussed in the IETF. No RFC just yet.
//! See the following drafts:
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/

use std::collections::HashSet;
use bcder::{decode, encode};
use bcder::{Captured, Mode, Oid, Tag};
use bcder::encode::Values;
use super::oid;
use super::cert::{Cert, ResourceCert};
use super::crypto::{Signer, SigningError};
use super::resources::{AddressFamily, AsBlock, AsBlocks, AsBlocksBuilder, AsId, AsResources};
use super::sigobj::{SignedObject, SignedObjectBuilder};
use super::x509::ValidationError;


//------------ Aspa ----------------------------------------------------------
#[derive(Clone, Debug)]
pub struct Aspa {
    signed: SignedObject,
    content: AsProviderAttestation,
}

impl Aspa {
    pub fn decode<S: decode::Source>(
        source: S,
        strict: bool
    ) -> Result<Self, S::Err> {
        let signed = SignedObject::decode(source, strict)?;
        if signed.content_type().ne(&oid::AS_PROVIDER_AUTHZ) {
            return Err(decode::Malformed.into())
        }
        let content = signed.decode_content(|cons| {
            AsProviderAttestation::take_from(cons)
        })?;
        Ok(Aspa { signed, content })
    }

    pub fn process<F>(
        mut self,
        issuer: &ResourceCert,
        strict: bool,
        check_crl: F
    ) -> Result<(ResourceCert, AsProviderAttestation), ValidationError>
    where F: FnOnce(&Cert) -> Result<(), ValidationError> {
        let cert = self.signed.validate(issuer, strict)?;
        check_crl(cert.as_ref())?;
        self.content.validate(&cert)?;
        Ok((cert, self.content))
    }

    /// Returns a value encoder for a reference to an ASPA.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        self.signed.encode_ref()
    }

    /// Returns a DER encoded Captured for this ASPA.
    pub fn to_captured(&self) -> Captured {
        self.encode_ref().to_captured(Mode::Der)
    }

    /// Returns a reference to the EE certificate of this ROA.
    pub fn cert(&self) -> &Cert {
        self.signed.cert()
    }
}


//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for Aspa {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let bytes = self.to_captured().into_bytes();
        let b64 = base64::encode(&bytes);
        b64.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Aspa {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        let string = String::deserialize(deserializer)?;
        let decoded = base64::decode(&string).map_err(de::Error::custom)?;
        let bytes = bytes::Bytes::from(decoded);
        Aspa::decode(bytes, true).map_err(de::Error::custom)
    }
}


//------------ AsProviderAttestation -----------------------------------------
#[derive(Clone, Debug)]
pub struct AsProviderAttestation {
    family: AddressFamily,
    customer_as: AsId,
    provider_as_set: ProviderAsSet,
}

impl AsProviderAttestation {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        // version [0] EXPLICIT INTEGER DEFAULT 0
        cons.take_opt_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(0))?;
        eprintln!("AsProviderAttestation: got version");
        
        cons.take_sequence(|cons| {
            let family = AddressFamily::take_from(cons)?;
            eprintln!("AsProviderAttestation: got family");
            let customer_as = AsId::take_from(cons)?;
            eprintln!("AsProviderAttestation: got customer_as");
            let provider_as_set = ProviderAsSet::take_from(cons)?;

            Ok(AsProviderAttestation {
                family,
                customer_as,
                provider_as_set,
            })
        })
    }

    fn validate(
        &mut self,
        cert: &ResourceCert
    ) -> Result<(), ValidationError> {
        if !cert.as_resources().contains(&self.as_blocks()) {
            return Err(ValidationError);
        }
        Ok(())
    }

    fn as_blocks(&self) -> AsBlocks {
        let mut builder = AsBlocksBuilder::new();
        let block = AsBlock::Id(self.customer_as);
        builder.push(block);
    
        builder.finalize()
    }

    pub fn as_resources(&self) -> AsResources {
        AsResources::blocks(self.as_blocks())
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            // version is DEFAULT
            self.family.encode(),
            self.customer_as.encode(),
            &self.provider_as_set.0,
        ))
    }
}

//------------ ProviderAsSet -------------------------------------------------
#[derive(Clone, Debug)]
pub struct ProviderAsSet(Captured);

impl ProviderAsSet {
    pub fn iter(&self) -> ProviderAsIter {
        ProviderAsIter(self.0.as_ref())
    }

    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.capture(|cons| {
                while AsId::skip_opt_in(cons)?.is_some() {}
                Ok(())
            })
        }).map(ProviderAsSet)
    }
}

//------------ ProviderAsIter ------------------------------------------------
#[derive(Clone, Debug)]
pub struct ProviderAsIter<'a>(&'a [u8]);

impl<'a> Iterator for ProviderAsIter<'a> {
    type Item = AsId;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        } else {
            // If self.0 (Captured) is not empty then we know there will be at
            // least one more AsId we can take and unwrap safely. This is verified
            // when the ProviderAsSet is constructed during parsing.
            Mode::Der
                .decode(&mut self.0, |cons| AsId::take_from(cons).map(Some))
                .unwrap()
        }
    }
}

//------------ AspaBuilder ---------------------------------------------------

pub struct AspaBuilder {
    family: AddressFamily,
    customer_as: AsId,
    provider_as_set: HashSet<AsId>, // ensure there are no duplicates
}

impl AspaBuilder {
    pub fn new_v4(customer_as: AsId) -> Self {
        AspaBuilder {
            family: AddressFamily::Ipv4,
            customer_as,
            provider_as_set: HashSet::new(),
        }
    }

    pub fn new_v6(customer_as: AsId) -> Self {
        AspaBuilder {
            family: AddressFamily::Ipv6,
            customer_as,
            provider_as_set: HashSet::new(),
        }
    }

    pub fn add_provider(&mut self, provider: AsId) {
        self.provider_as_set.insert(provider);
    }

    pub fn into_attestation(self) -> AsProviderAttestation {
        let provider_as_set_captured = if self.provider_as_set.is_empty() {
            Captured::empty(Mode::Der)
        } else {
            let mut asns: Vec<AsId> = self.provider_as_set.into_iter().collect();
            asns.sort();

            Captured::from_values(Mode::Der, 
                encode::sequence(
                    encode::slice(asns.as_slice(), |as_id| as_id.encode())
                )
            )
        };
        let provider_as_set = ProviderAsSet(provider_as_set_captured);

        AsProviderAttestation {
            family: self.family,
            customer_as: self.customer_as,
            provider_as_set,
        }
    }

    /// Finalizes the builder into an ASPA.
    pub fn finalize<S: Signer>(
        self, 
        mut sigobj: SignedObjectBuilder,
        signer: &S,
        issuer_key: &S::KeyId,
    ) -> Result<Aspa, SigningError<S::Error>> {
        let content = self.into_attestation();
        sigobj.set_as_resources(content.as_resources());

        let signed = sigobj.finalize(
            Oid(oid::AS_PROVIDER_AUTHZ.0.into()),
            content.encode_ref().to_captured(Mode::Der).into_bytes(),
            signer,
            issuer_key,
        )?;
        Ok(Aspa { signed, content })
    }
}

#[cfg(all(test, feature = "softkeys"))]
mod signer_test {

    use std::str::FromStr;
    use crate::uri;
    use crate::repository::cert::{KeyUsage, Overclaim, TbsCert};
    use crate::repository::crypto::{PublicKeyFormat, Signer};
    use crate::repository::crypto::softsigner::OpenSslSigner;
    use crate::repository::resources::{AsId, Prefix};
    use crate::repository::tal::TalInfo;
    use crate::repository::x509::Validity;
    use super::*;


    fn make_aspa(afi: AddressFamily) -> Aspa {
        let mut signer = OpenSslSigner::new();

        let customer_as: AsId = 64496.into();
        let provider_asns: Vec<AsId> = vec![64497.into(), 64498.into(), 64499.into()];

        let issuer_key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
        let issuer_uri = uri::Rsync::from_str("rsync://example.com/parent/ca.cer").unwrap();
        let crl_uri = uri::Rsync::from_str("rsync://example.com/ca/ca.crl").unwrap();
        let asa_uri = uri::Rsync::from_str("rsync://example.com/ca/asa.asa").unwrap();
        
        let issuer_cert = {
            let repo_uri = uri::Rsync::from_str("rsync://example.com/ca/").unwrap();
            let mft_uri = uri::Rsync::from_str("rsync://example.com/ca/ca.mft").unwrap();

            let pubkey = signer.get_key_info(&issuer_key).unwrap();

            let mut cert = TbsCert::new(
                12u64.into(),
                pubkey.to_subject_name(),
                Validity::from_secs(86400),
                None,
                pubkey,
                KeyUsage::Ca,
                Overclaim::Refuse,
            );
            cert.set_basic_ca(Some(true));
            cert.set_ca_repository(Some(repo_uri));
            cert.set_rpki_manifest(Some(mft_uri));
            cert.build_v4_resource_blocks(|b| b.push(Prefix::new(0, 0)));
            cert.build_v6_resource_blocks(|b| b.push(Prefix::new(0, 0)));
            cert.build_as_resource_blocks(|b| b.push((AsId::MIN, AsId::MAX)));
            let cert = cert.into_cert(&signer, &issuer_key).unwrap();

            cert.validate_ta(
                TalInfo::from_name("foo".into()).into_arc(), true
            ).unwrap()

            
        };

        let mut aspa = match afi {
            AddressFamily::Ipv4 => AspaBuilder::new_v4(customer_as),
            AddressFamily::Ipv6 => AspaBuilder::new_v6(customer_as),
        };
        
        for provider in &provider_asns {
            aspa.add_provider(*provider);
        }
        let aspa = aspa.finalize(
            SignedObjectBuilder::new(
                123_u64.into(),
                Validity::from_secs(86400),
                crl_uri.clone(), 
                issuer_uri.clone(),
                asa_uri.clone()
            ),
            &signer,
            &issuer_key
        ).unwrap();

        let encoded = aspa.to_captured();
        let decoded = Aspa::decode(encoded.as_slice(), true).unwrap();
        
        assert_eq!(encoded.as_slice(), decoded.to_captured().as_slice());
        
        let (_, attestation) = decoded.process(&issuer_cert, true, |_| Ok(())).unwrap();
        
        assert_eq!(afi, attestation.family);
        assert_eq!(customer_as, attestation.customer_as);
        let decoded_provider_asns: Vec<AsId> = attestation.provider_as_set.iter().collect();
        assert_eq!(provider_asns, decoded_provider_asns.as_slice());

        aspa
    }

    #[test]
    fn encode_aspa() {
        make_aspa(AddressFamily::Ipv4);
        make_aspa(AddressFamily::Ipv6);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_aspa() {
        let aspa = make_aspa(AddressFamily::Ipv4);

        let serialized = serde_json::to_string(&aspa).unwrap();
        let deser_aspa: Aspa = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            aspa.to_captured().into_bytes(),
            deser_aspa.to_captured().into_bytes()
        )
    }
}

//============ Specification Documentation ===================================

/// ASPA Specification.
///
/// This is a documentation-only module. It summarizes the specification for
/// ASPAs, how they are parsed and constructed.
///
/// A Autonomous System Provider Authorization (ASPA) is a [signed object] that
/// provides a means of verifying that a Customer Autonomous System holder has
/// authorized members of Provider set to be its upstream providers and for the
/// Providers to send prefixes received from the Customer Autonomous System in
/// all directions including providers and peers.
///
/// which is defined as follows:
///
/// ```txt
/// ASProviderAttestation   ::= SEQUENCE {
///      version                [0] ASPAVersion DEFAULT v0,
///      aFI                    AddressFamilyIdentifier,
///      customerASID           ASID,
///      providerASSET          SEQUENCE (SIZE(1..MAX)) OF ASID }
///
/// ASPAVersion             ::= INTEGER  { v0(0) }
///
/// AddressFamilyIdentifier ::= OCTET STRING (SIZE (2))
///
/// ASID                    ::= INTEGER
/// ```
///
/// The _version_ must be 0. The _addressFamily_ is identical to the field
/// used in RPKI certificate IP resources, i.e, `"\0\x01"` for IPv4 and
/// `"\0\x02"` for IPv6.
///
/// [signed object]: ../../sigobj/spec/index.html
/// [ASPA Profile draft]:  https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
pub mod spec {}
