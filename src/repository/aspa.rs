//! Autonomous System Provider Authorization
//!
//! This is still being discussed in the IETF. No RFC just yet.
//! See the [draft-ietf-sidrops-aspa-profile] and
//! [draft-ietf-sidrops-aspa-verification].
//!
//! [draft-ietf-sidrops-aspa-profile]: https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
//! [draft-ietf-sidrops-aspa-verification]: https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/

use std::fmt;
use std::str::FromStr;
use bcder::{decode, encode};
use bcder::{Captured, Mode, Oid, Tag};
use bcder::decode::{DecodeError, IntoSource, SliceSource, Source};
use bcder::encode::Values;
use crate::oid;
use crate::crypto::{Signer, SigningError};
use super::cert::{Cert, ResourceCert};
use super::error::{ValidationError, VerificationError};
use super::resources::{
    AddressFamily, AsBlock, AsBlocks, AsBlocksBuilder, Asn, AsResources
};
use super::sigobj::{SignedObject, SignedObjectBuilder};


//------------ Aspa ----------------------------------------------------------
#[derive(Clone, Debug)]
pub struct Aspa {
    signed: SignedObject,
    content: AsProviderAttestation,
}

impl Aspa {
    pub fn decode<S: IntoSource>(
        source: S,
        strict: bool
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        let signed = SignedObject::decode_if_type(
            source, &oid::CT_ASPA, strict
        )?;
        let content = signed.decode_content(|cons| {
            AsProviderAttestation::take_from(cons)
        }).map_err(DecodeError::convert)?;
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
        let decoded = base64::decode(string).map_err(de::Error::custom)?;
        let bytes = bytes::Bytes::from(decoded);
        Aspa::decode(bytes, true).map_err(de::Error::custom)
    }
}


//------------ AsProviderAttestation -----------------------------------------

#[derive(Clone, Debug)]
pub struct AsProviderAttestation {
    customer_as: Asn,
    provider_as_set: ProviderAsSet,
}

impl AsProviderAttestation {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        // version [0] EXPLICIT INTEGER DEFAULT 0
        cons.take_opt_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(0))?;
                
        cons.take_sequence(|cons| {
            let customer_as = Asn::take_from(cons)?;
            let provider_as_set = ProviderAsSet::take_from(cons)?;

            Ok(AsProviderAttestation {
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
            return Err(VerificationError::new(
                "customer AS not covered by certificate"
            ).into());
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
            self.customer_as.encode(),
            &self.provider_as_set.0,
        ))
    }

    pub fn customer_as(&self) -> Asn {
        self.customer_as
    }

    pub fn provider_as_set(&self) -> &ProviderAsSet {
        &self.provider_as_set
    }
}


//------------ ProviderAsSet -------------------------------------------------

#[derive(Clone, Debug)]
pub struct ProviderAsSet(Captured);

impl ProviderAsSet {
    pub fn iter(&self) -> ProviderAsIter {
        ProviderAsIter(self.0.as_slice().into_source())
    }

    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            cons.capture(|cons| {
                let mut last: Option<Asn> = None;
                let mut entries = true;
                while entries {
                    if let Some(provider_as) = ProviderAs::take_opt_from(
                        cons
                    )? {
                        let current_as_id = provider_as.provider();
                        if let Some(last_as_id) = last {
                            if last_as_id >= current_as_id {
                                return Err(cons.content_err(
                                    "provider AS set is not ordered"
                                ));
                            }
                        }
                        last = Some(provider_as.provider());
                    } else {
                        entries = false;
                    }
                }
                
                Ok(())
            })
        }).map(ProviderAsSet)
    }
}


//------------ ProviderAsIter ------------------------------------------------

#[derive(Clone, Debug)]
pub struct ProviderAsIter<'a>(SliceSource<'a>);

impl<'a> Iterator for ProviderAsIter<'a> {
    type Item = ProviderAs;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        }
        else {
            Mode::Der.decode(&mut self.0, |cons| {
                ProviderAs::take_opt_from(cons)
            }).unwrap()
        }
    }
}


//------------ AspaProvider ----------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderAs {
    provider: Asn,
    afi_limit: Option<AddressFamily>,
}

impl ProviderAs {
    pub fn new(provider: Asn) -> Self {
        ProviderAs { provider, afi_limit: None }
    }

    pub fn new_v4(provider: Asn) -> Self {
        ProviderAs { provider, afi_limit: Some(AddressFamily::Ipv4) }
    }

    pub fn new_v6(provider: Asn) -> Self {
        ProviderAs { provider, afi_limit: Some(AddressFamily::Ipv6) }
    }

    pub fn provider(&self) -> Asn {
        self.provider
    }

    pub fn afi_limit(&self) -> Option<AddressFamily> {
        self.afi_limit
    }

}

impl ProviderAs {
    //
    //      providerAS     ::= SEQUENCE {
    //          providerASID ::= ASID,
    //          afiLimit     ::= OCTET STRING (SIZE (2)) OPTIONAL
    //      }
    //
    //      ASID           ::= INTEGER
        
    /// Takes an optional ProviderAS from the beginning of an encoded value.
    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons|{
            let provider = Asn::take_from(cons)?;
            let afi_limit = AddressFamily::take_opt_from(cons)?;
            Ok(ProviderAs { provider, afi_limit })
        })
    }

    /// Skips over a ProviderAs if it is present.
    pub fn skip_opt_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<()>, DecodeError<S::Error>> {
        Self::take_opt_from(cons).map(|opt| opt.map(|_| ()))
    }

    pub fn encode(self) -> impl encode::Values {
        encode::sequence((
            self.provider.encode(),
            self.afi_limit.map(|v| v.encode())
        ))
    }
}


//--- FromStr

impl FromStr for ProviderAs {
    type Err = <Asn as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Possible options:
        //  AS#
        //  AS#(v4)
        //  AS#(v6)
        if let Some(as_str) = s.strip_suffix("(v4)") {
            Ok(ProviderAs::new_v4(Asn::from_str(as_str)?))
        }
        else if let Some(as_str) = s.strip_suffix("(v6)") {
            Ok(ProviderAs::new_v6(Asn::from_str(as_str)?))
        }
        else {
            Ok(ProviderAs::new(Asn::from_str(s)?))
        }
    }
}


//--- Display

impl fmt::Display for ProviderAs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.afi_limit {
            None => write!(f, "{}", self.provider),
            Some(family) => {
                let fam_str = match &family {
                    AddressFamily::Ipv4 => "v4",
                    AddressFamily::Ipv6 => "v6",
                };
                write!(f, "{}({})", self.provider, fam_str)
            }
        }
    }
}


//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for ProviderAs {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ProviderAs {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        let string = String::deserialize(deserializer)?;
        ProviderAs::from_str(&string).map_err(de::Error::custom)
    }
}


//------------ AspaBuilder ---------------------------------------------------

pub struct AspaBuilder {
    customer_as: Asn,
    providers: Vec<ProviderAs>
}

impl AspaBuilder {
    pub fn new(
        customer_as: Asn,
        providers: Vec<ProviderAs>
    ) -> Result<Self, DuplicateProviderAs> {
        let mut builder = AspaBuilder {
            customer_as,
            providers,
        };
        builder.sort_and_verify_providers()?;
        Ok(builder)
    }

    pub fn empty(customer_as: Asn) -> Self {
        AspaBuilder {
            customer_as,
            providers: vec![],
        }
    }

    pub fn add_provider(
        &mut self, provider: ProviderAs
    ) -> Result<(), DuplicateProviderAs> {
        self.providers.push(provider);
        self.sort_and_verify_providers()
    }

    fn sort_and_verify_providers(
        &mut self
    ) -> Result<(), DuplicateProviderAs> {
        // sort and verify if there are any duplicates
        if self.providers.len() > 1 {
            self.providers.sort_by_key(|p| p.provider());
            let mut last = self.providers.first().unwrap().provider();
            for i in 1..self.providers.len() {
                let new = self.providers.get(i).unwrap().provider();
                if new == last {
                    return Err(DuplicateProviderAs);
                }
                last = new;
            }
        }
        Ok(())
    }

    fn into_attestation(self) -> AsProviderAttestation {
        let provider_as_set_captured = Captured::from_values(
            Mode::Der,
            encode::sequence(
                encode::slice(
                    self.providers.as_slice(),
                    |prov| prov.encode()
                )
            )
        );
        
        let provider_as_set = ProviderAsSet(provider_as_set_captured);

        AsProviderAttestation {
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
            Oid(oid::CT_ASPA.0.into()),
            content.encode_ref().to_captured(Mode::Der).into_bytes(),
            signer,
            issuer_key,
        )?;
        Ok(Aspa { signed, content })
    }
}


//------------ DuplicateProviderAs -------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DuplicateProviderAs;

impl fmt::Display for DuplicateProviderAs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("provider as set contains duplicate")
    }
}

impl std::error::Error for DuplicateProviderAs { }


//============ Test ==========================================================

#[cfg(all(test, feature = "softkeys"))]
mod signer_test {
    use std::str::FromStr;
    use crate::uri;
    use crate::repository::cert::{KeyUsage, Overclaim, TbsCert};
    use crate::crypto::{PublicKeyFormat, Signer};
    use crate::crypto::softsigner::OpenSslSigner;
    use crate::repository::resources::{Asn, Prefix};
    use crate::repository::tal::TalInfo;
    use crate::repository::x509::Validity;
    use super::*;


    fn make_aspa(
        customer_as: Asn,
        mut providers: Vec<ProviderAs>,
    ) -> Aspa {
        let signer = OpenSslSigner::new();

        let issuer_key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
        let issuer_uri = uri::Rsync::from_str(
            "rsync://example.com/parent/ca.cer"
        ).unwrap();
        let crl_uri = uri::Rsync::from_str(
            "rsync://example.com/ca/ca.crl"
        ).unwrap();
        let asa_uri = uri::Rsync::from_str(
            "rsync://example.com/ca/asa.asa"
        ).unwrap();
        
        let issuer_cert = {
            let repo_uri = uri::Rsync::from_str(
                "rsync://example.com/ca/"
            ).unwrap();
            let mft_uri = uri::Rsync::from_str(
                "rsync://example.com/ca/ca.mft"
            ).unwrap();

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
            cert.build_as_resource_blocks(|b| b.push((Asn::MIN, Asn::MAX)));
            let cert = cert.into_cert(&signer, &issuer_key).unwrap();

            cert.validate_ta(
                TalInfo::from_name("foo".into()).into_arc(), true
            ).unwrap()

            
        };

        let mut aspa = AspaBuilder::empty(customer_as);
        
        for provider in &providers {
            aspa.add_provider(*provider).unwrap();
        }

        let aspa = aspa.finalize(
            SignedObjectBuilder::new(
                123_u64.into(),
                Validity::from_secs(86400),
                crl_uri, 
                issuer_uri,
                asa_uri
            ),
            &signer,
            &issuer_key
        ).unwrap();

        let encoded = aspa.to_captured();
        let decoded = Aspa::decode(encoded.as_slice(), true).unwrap();
        
        assert_eq!(encoded.as_slice(), decoded.to_captured().as_slice());
        
        let (_, attestation) = decoded.process(
            &issuer_cert, true, |_| Ok(())
        ).unwrap();
        
        assert_eq!(customer_as, attestation.customer_as);
        let decoded_providers: Vec<_> =
            attestation.provider_as_set.iter().collect();
        
        providers.sort_by_key(|p| p.provider());
        assert_eq!(providers, decoded_providers.as_slice());
            // Sorted vecs should match

        aspa
    }

    #[test]
    fn encode_aspa() {
        let customer_as: Asn = 64496.into();
        let providers: Vec<ProviderAs> = vec![
            ProviderAs::new_v4(64498.into()),
            ProviderAs::new(64497.into()),
            ProviderAs::new_v6(64499.into())
        ];
        make_aspa(customer_as, providers);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_aspa() {
        let customer_as: Asn = 64496.into();
        let providers: Vec<ProviderAs> = vec![
            ProviderAs::new_v4(64498.into()),
            ProviderAs::new(64497.into()),
            ProviderAs::new_v6(64499.into())
        ];
        let aspa = make_aspa(customer_as, providers);
        
        let serialized = serde_json::to_string(&aspa).unwrap();
        let deserialized: Aspa = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            aspa.to_captured().into_bytes(),
            deserialized.to_captured().into_bytes()
        )
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_aspa_empty_providers() {
        let customer_as: Asn = 64496.into();
        let providers: Vec<ProviderAs> = vec![];
        let aspa = make_aspa(customer_as, providers);
        
        let serialized = serde_json::to_string(&aspa).unwrap();
        let deserialized: Aspa = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            aspa.to_captured().into_bytes(),
            deserialized.to_captured().into_bytes()
        )
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_provider_as() {
        let providers: Vec<ProviderAs> = vec![
            ProviderAs::new(64497.into()),
            ProviderAs::new_v4(64498.into()),
            ProviderAs::new_v6(64499.into())
        ];
        
        let serialized = serde_json::to_string(&providers).unwrap();
        let deserialized: Vec<_> = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            providers,
            deserialized
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
///      ct-ASPA CONTENT-TYPE ::=
///          { ASProviderAttestation IDENTIFIED BY id-ct-ASPA }
///
///      id-ct-ASPA OBJECT IDENTIFIER ::= { id-ct TBD }
///
///      ASProviderAttestation ::= SEQUENCE {
///          version [0]   ASPAVersion DEFAULT v0,
///          customerASID  ASID,
///          providers     ProviderASSet,
///      }
///
///      ASPAVersion    ::= INTEGER  { v0(0) }
///
///      ASID           ::= INTEGER
///
///      providerASSET  ::= SEQUENCE (SIZE(1..MAX)) OF ProviderAS }
///
///      providerAS     ::= SEQUENCE {
///          providerASID ::= ASID,
///          afiLimit     ::= OCTET STRING (SIZE (2)) OPTIONAL
///      }
/// ```
///
/// The _version_ must be 0. The _afiLimit, if present, MUST be
/// either `"\0\x01"` for IPv4 or `"\0\x02"` for IPv6.
///
/// [signed object]: ../../sigobj/spec/index.html
/// [ASPA Profile draft]:  https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
pub mod spec {}
