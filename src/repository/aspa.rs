//! Autonomous System Provider Authorization
//!
//! This is still being discussed in the IETF. No RFC just yet.
//! See the [draft-ietf-sidrops-aspa-profile] and
//! [draft-ietf-sidrops-aspa-verification].
//!
//! [draft-ietf-sidrops-aspa-profile]: https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
//! [draft-ietf-sidrops-aspa-verification]: https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/

use std::fmt;
use std::cmp::Ordering;
use bcder::{decode, encode};
use bcder::{Captured, Mode, Oid, Tag};
use bcder::decode::{DecodeError, IntoSource, SliceSource, Source};
use bcder::encode::{PrimitiveContent, Values};
use crate::oid;
use crate::crypto::{Signer, SigningError};
use crate::resources::asn::SmallAsnSet;
use crate::util::base64;
use super::cert::{Cert, ResourceCert};
use super::error::{ValidationError, VerificationError};
use super::resources::{AsBlock, AsBlocks, AsBlocksBuilder, Asn, AsResources};
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
        self.content.verify(&cert)?;
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

    /// Returns a reference to the content of the ASPA object
    pub fn content(&self) -> &AsProviderAttestation {
        &self.content
    }
}


//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for Aspa {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let bytes = self.to_captured().into_bytes();
        let b64 = base64::Serde.encode(&bytes);
        b64.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Aspa {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        let s = String::deserialize(deserializer)?;
        let decoded = base64::Serde.decode(&s).map_err(de::Error::custom)?;
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
        cons.take_sequence(|cons| {
            // version [0] EXPLICIT INTEGER DEFAULT 0
            // must be 1!
            cons.take_opt_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(1))?;
            let customer_as = Asn::take_from(cons)?;
            let provider_as_set = ProviderAsSet::take_from(
                cons, customer_as
            )?;

            Ok(AsProviderAttestation {
                customer_as,
                provider_as_set,
            })
        })
    }

    fn verify(
        &mut self,
        cert: &ResourceCert,
    ) -> Result<(), ValidationError> {
        // The three bullet points from draft-ietf-sidrops-aspa-profile-12,
        // section 4.
        if !cert.as_resources().contains_asn(self.customer_as) {
            return Err(VerificationError::new(
                "customer AS not covered by certificate"
            ).into());
        }
        if cert.as_cert().as_resources().is_inherited() {
            return Err(VerificationError::new(
                "certificate contains inherited AS resources"
            ).into());
        }
        if cert.as_cert().has_ip_resources() {
            return Err(VerificationError::new(
                "certificate contains IP resources"
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

    /// Returns the AS resources required by this provider attestation.
    ///
    /// The attestation requires resources covering the customer ASN, so
    /// the method constructs a value containing this ASN.
    pub fn as_resources(&self) -> AsResources {
        AsResources::blocks(self.as_blocks())
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            encode::sequence_as(Tag::CTX_0, 1u8.encode()),
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

/// The provider AS set of the ASPA object.
///
/// This type contains the provider AS set in encoded form. It guarantees that
/// the AS in this set are ordered, free of duplicates and there is at least
/// one AS.
#[derive(Clone, Debug)]
pub struct ProviderAsSet(Captured);

impl ProviderAsSet {
    pub fn to_set(&self) -> SmallAsnSet {
        unsafe {
            SmallAsnSet::from_vec_unchecked(
                self.iter().collect()
            )
        }
    }

    pub fn iter(&self) -> ProviderAsIter {
        ProviderAsIter(self.0.as_slice().into_source())
    }

    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        customer_as: Asn,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            cons.capture(|cons| {
                let mut last: Option<Asn> = None;
                while let Some(asn) = Asn::take_opt_from(
                    cons
                )? {
                    if asn == customer_as {
                        return Err(cons.content_err(
                            "customer AS in provider AS set"
                        ));
                    }
                    if let Some(last) = last {
                        match last.cmp(&asn) {
                            Ordering::Less => { }
                            Ordering::Equal => {
                                return Err(cons.content_err(
                                    "duplicate provider AS"
                                ));
                            }
                            Ordering::Greater => {
                                return Err(cons.content_err(
                                    "provider AS set is not ordered"
                                ));
                            }
                        }
                    }
                    last = Some(asn);
                }
                if last.is_none() {
                    return Err(cons.content_err(
                        "empty provider AS set"
                    ))
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
    type Item = Asn;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        }
        else {
            Mode::Der.decode(&mut self.0, |cons| {
                Asn::take_opt_from(cons)
            }).unwrap()
        }
    }
}


//------------ AspaBuilder ---------------------------------------------------

pub struct AspaBuilder {
    customer_as: Asn,
    providers: Vec<Asn>
}

impl AspaBuilder {
    pub fn new(
        customer_as: Asn,
        providers: impl Into<Vec<Asn>>
    ) -> Result<Self, DuplicateProviderAs> {
        let mut providers = providers.into();
        providers.sort_unstable();
        if providers.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DuplicateProviderAs)
        }
        Ok(AspaBuilder {
            customer_as,
            providers,
        })
    }

    pub fn empty(customer_as: Asn) -> Self {
        AspaBuilder {
            customer_as,
            providers: vec![],
        }
    }

    pub fn add_provider(
        &mut self, provider: Asn
    ) -> Result<(), DuplicateProviderAs> {
        match self.providers.binary_search(&provider) {
            Ok(_) => Err(DuplicateProviderAs),
            Err(idx) => {
                self.providers.insert(idx, provider);
                Ok(())
            }
        }
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn decode_content() {
        let content = Mode::Der.decode(
            include_bytes!(
                "../../test-data/repository/aspa-content.der"
            ).as_ref(),
            AsProviderAttestation::take_from
        ).unwrap();
        assert_eq!(content.customer_as(), 15562.into());
        assert_eq!(
            vec![2914, 8283, 51088, 206238],
            content.provider_as_set().iter().map(|asn| {
                asn.into_u32()
            }).collect::<Vec<_>>(),
        );
    }
}

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
        mut providers: Vec<Asn>,
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
        
        providers.sort();
        assert_eq!(providers, decoded_providers.as_slice());
            // Sorted vecs should match

        aspa
    }

    #[test]
    fn encode_aspa() {
        let customer_as = 64496.into();
        let providers = vec![
            64498.into(),
            64497.into(),
            64499.into(),
        ];
        make_aspa(customer_as, providers);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_aspa() {
        let customer_as = 64496.into();
        let providers = vec![
            64498.into(),
            64497.into(),
            64499.into(),
        ];
        let aspa = make_aspa(customer_as, providers);
        
        let serialized = serde_json::to_string(&aspa).unwrap();
        let deserialized: Aspa = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            aspa.to_captured().into_bytes(),
            deserialized.to_captured().into_bytes()
        )
    }
}


//============ Specification Documentation ===================================

/// ASPA Specification.
///
/// This is a documentation-only module. It summarizes the specification for
/// ASPAs, how they are parsed and constructed.
///
/// This implementation follows the ASPA profile as specificed in draft
/// version 15.
///
/// A Autonomous System Provider Authorization (ASPA) is a [signed object] that
/// provides a means of verifying that a Customer Autonomous System holder has
/// authorized members of Provider set to be its upstream providers and for the
/// Providers to send prefixes received from the Customer Autonomous System in
/// all directions including providers and peers.
///
/// It is defined as follows:
///
/// ```txt
/// id-ct-ASPA OBJECT IDENTIFIER ::= { id-ct aspa(49) }
///
/// ASProviderAttestation ::= SEQUENCE {
///     version       [0] EXPLICIT INTEGER DEFAULT 0,
///     customerASID  ASID,
///     providers     ProviderASSet
/// }
///
/// ProviderASSet ::= SEQUENCE (SIZE(1..MAX)) OF ASID
///
/// ASID           ::= INTEGER(0..4294967295)
/// ```
///
/// The _version_ must be 1. Yes, 1.
///
/// The the ASIDs in the provider AS set must be arranged in ascending order,
/// must not contain duplicates, and must not contain the customer ASID.
pub mod spec {}
