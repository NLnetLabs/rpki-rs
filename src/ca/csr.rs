//! Certificate Signing Requests (CSR) for RPKI.
//!
//! Certificate Signing Requests, also called Certification Requests, for the
//! RPKI use the PKCS#10 Certification Requests defined in RFC2986, while
//! limiting the allowed extensions in section 6 of RFC6487.
//!
//! They are used in the exchange defined in section 3.4.1 of RFC6492 where a
//! child Certificate Authority requests a new certificate to be signed by
//! its parent CA.
//!
//! The CSR includes:
//! - a suggested subject
//! - the public key
//! - extensions:
//!     - basic constraints
//!     - key usage
//!     - extended key usage
//!     - subject information access
//! - a signature (to prove possession of the public key)
//!

use std::borrow::Cow;
use std::fmt;
use bcder::{decode, encode, ConstOid};
use bcder::{BitString, Captured, Mode, OctetString, Oid, Tag};
use bcder::decode::{ContentError, DecodeError, IntoSource, Source};
use bcder::encode::{PrimitiveContent, Constructed};
use bytes::Bytes;
use crate::{oid, uri};
use crate::repository::cert::{
    ExtendedKeyUsage, InvalidExtension, KeyUsage, Sia, TbsCert
};
use crate::crypto::{
    BgpsecSignatureAlgorithm, RpkiSignatureAlgorithm, PublicKey,
    SignatureAlgorithm, SignatureVerificationError,
};
use crate::crypto::signer::{Signer, SigningError};
use crate::repository::x509::{Name, SignedData};
use crate::util::base64;


//------------ Csr -----------------------------------------------------------

/// An RPKI Certificate Sign Request.
#[derive(Clone, Debug)]
pub struct Csr<Alg, Attrs> {
    /// The outer structure of the CSR.
    signed_data: SignedData<Alg>,

    /// The content of the CSR.
    content: CsrContent<Attrs>
}

pub type RpkiCaCsr = Csr<RpkiSignatureAlgorithm, RpkiCaCsrAttributes>;
pub type BgpsecCsr = Csr<BgpsecSignatureAlgorithm, BgpsecCsrAttributes>;

/// # Data Access
///
impl<Alg, Attrs> Csr<Alg, Attrs> {
    /// The subject name included on the CSR.
    ///
    /// TLDR; This field is useless and will be ignored by the issuing CA.
    ///
    /// This field is required by RFC2986, but RFC6487 says that in the RPKI
    /// its value SHOULD be empty when requesting new certificates, and MAY
    /// be non-empty only on subsequent re-issuance requests and only if the
    /// issuing CA has adopted a policy that allows re-use of the name
    /// (implying, but not saying, that the request should then include the
    /// previously allocated name).
    ///
    /// Issuing CAs MUST generate a unique name in the issued certificate.
    pub fn subject(&self) -> &Name {
        &self.content.subject
    }

    /// Returns the public key for the requested certificate. Note that
    /// validate() should be called to ensure that the requester has possession
    /// of the private key for this public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.content.public_key
    }

    /// Returns a reference to the attributes of the CSR.
    pub fn attributes(&self) -> &Attrs {
        &self.content.attributes
    }
}

impl<Alg> Csr<Alg, RpkiCaCsrAttributes> {
    /// Returns the cA field of the basic constraints extension if present, or
    /// false.
    pub fn basic_ca(&self) -> bool {
        self.content.attributes.basic_ca
    }

    /// Returns the desired KeyUsage
    pub fn key_usage(&self) -> KeyUsage {
        self.content.attributes.key_usage
    }

    /// Returns the optional desired extended key usage.
    pub fn extended_key_usage(&self) -> Option<&ExtendedKeyUsage> {
       self.content.attributes.extended_key_usage.as_ref()
    }

    /// Returns the desired ca repository
    pub fn ca_repository(&self) -> Option<&uri::Rsync> {
        self.content.attributes.sia.ca_repository()
    }

    /// Returns the desired rpki manifest uri
    pub fn rpki_manifest(&self) -> Option<&uri::Rsync> {
        self.content.attributes.sia.rpki_manifest()
    }

    /// Returns the desired rpki notify uri (for RRDP)
    pub fn rpki_notify(&self) -> Option<&uri::Https> {
        self.content.attributes.sia.rpki_notify()
    }
}

/// # Decode, Encode, and Validate
///
impl<Alg: SignatureAlgorithm, Attrs: CsrAttributes> Csr<Alg, Attrs> {
    /// Parse as a source as a certificate signing request.
    pub fn decode<S: IntoSource>(
        source: S
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        Mode::Der.decode(source.into_source(), Self::take_from)
    }

    /// Takes an encoded CSR from the beginning of a constructed value.
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the content of a certificate signing request.
    fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        let signed_data = SignedData::from_constructed(cons)?;
        let content = signed_data.data().clone().decode(
            CsrContent::take_from
        ).map_err(DecodeError::convert)?;

        Ok(Self { signed_data, content })
    }

    /// Validates a CSR against its internal public key.
    pub fn verify_signature(&self) -> Result<(), SignatureVerificationError> {
        self.signed_data.verify_signature(self.public_key())
    }
}

impl<Alg: SignatureAlgorithm, Attrs> Csr<Alg, Attrs> {
    /// Returns a value encoder for a reference to the csr.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        self.signed_data.encode_ref()
    }

    /// Returns a captured encoding of the csr.
    pub fn to_captured(&self) -> Captured {
        Captured::from_values(Mode::Der, self.encode_ref())
    }
}

/// # Construct
///
impl Csr<(), ()> {
    /// Builds a new Csr for RPKI CA certificates.
    ///
    /// Other use cases are not required in RPKI, and for simplicity they are
    /// not supported here. That means that BasicConstraints, KeyUsage, and
    /// algorithm do not need to be specified. Only the values for the
    /// required SIA entries for 'id-ad-caRepository' and
    /// 'id-ad-rpkiManifest' (see RFC6487), and the optional entry for
    /// 'id-ad-rpkiNotify' (see RFC8182), need to be specified.
    pub fn construct_rpki_ca<S: Signer>(
        signer: &S,
        key: &S::KeyId,
        ca_repository: &uri::Rsync,
        rpki_manifest: &uri::Rsync,
        rpki_notify: Option<&uri::Https>
    ) -> Result<Captured, SigningError<S::Error>> {
        let pub_key = signer.get_key_info(key)?;

        let ca_repository = if ca_repository.path_is_dir() {
            Cow::Borrowed(ca_repository)
        } else {
            Cow::Owned(ca_repository.join(b"/").unwrap())
        };

        let content = Captured::from_values(Mode::Der, encode::sequence((
            0_u32.encode(),
            Name::from_pub_key(&pub_key).encode_ref(),
            pub_key.encode_ref(),

            Constructed::new(Tag::CTX_0, encode::sequence((
                oid::EXTENSION_REQUEST.encode_ref(),
                encode::set(encode::sequence((
                    Self::extension(
                        &oid::CE_BASIC_CONSTRAINTS, true,
                        encode::sequence(true.encode())
                    ),
                    Self::extension(
                        &oid::CE_KEY_USAGE, true,
                        KeyUsage::Ca.encode()
                    ),
                    Self::extension(
                        &oid::PE_SUBJECT_INFO_ACCESS, false,
                        encode::sequence((
                            encode::sequence((
                                oid::AD_CA_REPOSITORY.encode(),
                                ca_repository.encode_general_name()
                            )),
                            encode::sequence((
                                oid::AD_RPKI_MANIFEST.encode(),
                                rpki_manifest.encode_general_name()
                            )),
                            rpki_notify.map(|uri| {
                                encode::sequence((
                                    oid::AD_RPKI_NOTIFY.encode(),
                                    uri.encode_general_name()
                                ))
                            })
                        ))
                    )
                )))
            )))
        )));

        let (alg, signature) = signer.sign(
            key,
            RpkiSignatureAlgorithm::default(),
            &content
        )?.unwrap();

        Ok(Captured::from_values(Mode::Der,
            encode::sequence((
            content,
            alg.x509_encode(),
            BitString::new(0, signature).encode()
        ))))
    }

    fn extension<V: encode::Values>(
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


//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl<Alg: SignatureAlgorithm, Attrs> serde::Serialize for Csr<Alg, Attrs> {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let bytes = self.to_captured().into_bytes();
        let b64 = base64::Serde.encode(&bytes);
        b64.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, Alg, Attrs> serde::Deserialize<'de> for Csr<Alg, Attrs>
where
    Alg: SignatureAlgorithm,
    Attrs: CsrAttributes,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        let s = String::deserialize(deserializer)?;
        let decoded = base64::Serde.decode(&s).map_err(de::Error::custom)?;
        let bytes = bytes::Bytes::from(decoded);
        Csr::decode(bytes).map_err(de::Error::custom)
    }
}


//------------ CsrContent ----------------------------------------------------

#[derive(Clone, Debug)]
struct CsrContent<Attrs> {
    subject: Name,
    public_key: PublicKey,
    attributes: Attrs,
}

impl<Attrs: CsrAttributes> CsrContent<Attrs> {
    /// Takes a value from the beginning of an encoded constructed value.
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            cons.skip_u8_if(0)?; // version MUST be 0, cause v1
            let subject = Name::take_from(cons)?;
            let public_key = PublicKey::take_from(cons)?;
            let attributes = Attrs::take_from(cons)?;
            Ok(CsrContent { subject, public_key, attributes })
        })
    }
}


//------------ CsrAttributes -------------------------------------------------

pub trait CsrAttributes: Sized {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>>;
}


//------------ RpkiCaCsrAttributes -------------------------------------------

#[derive(Clone, Debug)]
pub struct RpkiCaCsrAttributes {
    basic_ca: bool,
    key_usage: KeyUsage,
    extended_key_usage: Option<ExtendedKeyUsage>,
    sia: Sia
}

impl CsrAttributes for RpkiCaCsrAttributes {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_constructed_if(Tag::CTX_0, |cons| {
            let mut basic_ca = None;
            let mut key_usage = None;
            let mut extended_key_usage = None;
            let mut sia = None;

            cons.take_sequence(|cons| {
                let id = Oid::take_from(cons)?;
                if id == oid::EXTENSION_REQUEST {
                    cons.take_set(|cons| { cons.take_sequence(|cons| {
                        while let Some(()) = cons.take_opt_sequence(|cons| {

                            let id = Oid::take_from(cons)?;
                            let _crit = cons.take_opt_bool()?;

                            let value = OctetString::take_from(cons)?;

                            Mode::Der.decode(value.into_source(), |content| {
                                if id == oid::CE_BASIC_CONSTRAINTS {
                                    TbsCert::take_basic_constraints(
                                        content, &mut basic_ca
                                    )
                                } else if id == oid::CE_KEY_USAGE {
                                    TbsCert::take_key_usage(
                                        content, &mut key_usage
                                    )
                                } else if id == oid::CE_EXTENDED_KEY_USAGE {
                                    TbsCert::take_extended_key_usage(
                                        content, &mut extended_key_usage
                                    )
                                } else if id == oid::PE_SUBJECT_INFO_ACCESS {
                                    TbsCert::take_subject_info_access(
                                        content, &mut sia
                                    )
                                } else {
                                    Err(content.content_err(
                                        InvalidExtension::new(id)
                                    ))
                                }
                            }).map_err(DecodeError::convert)?;


                            Ok(())
                        })? {};
                        Ok(())
                    })})
                } else {
                    Err(cons.content_err(InvalidAttribute::new(id)))
                }
            })?;

            let basic_ca = basic_ca.ok_or_else(|| {
                cons.content_err("missing Basic Constraints extension")
            })?;
            let key_usage = key_usage.ok_or_else(|| {
                cons.content_err("missing Key Usage extension")
            })?;
            let sia = sia.ok_or_else(|| {
                cons.content_err(
                    "missing Subject Information Access extension"
                )
            })?;

            Ok(RpkiCaCsrAttributes {
                    basic_ca, key_usage, extended_key_usage, sia
            })
        })
    }
}


//------------ BgpsecCsrAttributes -------------------------------------------

#[derive(Clone, Debug)]
pub struct BgpsecCsrAttributes {
    extended_key_usage: Option<ExtendedKeyUsage>,
}

impl BgpsecCsrAttributes {
    pub fn extended_key_usage(&self) -> Option<&ExtendedKeyUsage> {
        self.extended_key_usage.as_ref()
    }
}

impl CsrAttributes for BgpsecCsrAttributes {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_constructed_if(Tag::CTX_0, |cons| {
            let mut basic_ca = None;
            let mut key_usage = None;
            let mut extended_key_usage = None;
            let mut sia = None;

            cons.take_sequence(|cons| {
                let id = Oid::take_from(cons)?;
                if id == oid::EXTENSION_REQUEST {
                    cons.take_set(|cons| { cons.take_sequence(|cons| {
                        while let Some(()) = cons.take_opt_sequence(|cons| {

                            let id = Oid::take_from(cons)?;
                            let _crit = cons.take_opt_bool()?;

                            let value = OctetString::take_from(cons)?;

                            Mode::Der.decode(value.into_source(), |content| {
                                if id == oid::CE_BASIC_CONSTRAINTS {
                                    TbsCert::take_basic_constraints(
                                        content, &mut basic_ca
                                    )
                                } else if id == oid::CE_KEY_USAGE {
                                    TbsCert::take_key_usage(
                                        content, &mut key_usage
                                    )
                                } else if id == oid::CE_EXTENDED_KEY_USAGE {
                                    TbsCert::take_extended_key_usage(
                                        content, &mut extended_key_usage
                                    )
                                } else if id == oid::PE_SUBJECT_INFO_ACCESS {
                                    TbsCert::take_subject_info_access(
                                        content, &mut sia
                                    )
                                } else {
                                    Err(content.content_err(
                                        InvalidExtension::new(id)
                                    ))
                                }
                            }).map_err(DecodeError::convert)?;


                            Ok(())
                        })? {};
                        Ok(())
                    })})
                } else {
                    Err(cons.content_err(InvalidAttribute::new(id)))
                }
            })?;

            // Basic Constraints, Key Usage, and SIA are ignored (they are
            // allowed but MUST NOT be honored if wrong).

            // Extended Key Usage, if present, must include
            // id-kp-bgpsec-router.
            if let Some(eku) = extended_key_usage.as_ref() {
                eku.inspect_router().map_err(|err| cons.content_err(err))?;
            }

            Ok(BgpsecCsrAttributes { extended_key_usage })
        })
    }
}


//============ Error Types ===================================================

//------------ InvalidAttribute ----------------------------------------------

/// An invalid CSR attribute was encountered.
#[derive(Clone, Debug)]
pub struct InvalidAttribute {
    oid: Oid<Bytes>,
}

impl InvalidAttribute {
    pub(crate) fn new(oid: Oid<Bytes>) -> Self {
        InvalidAttribute { oid }
    }
}

impl From<InvalidAttribute> for ContentError {
    fn from(err: InvalidAttribute) -> Self {
        ContentError::from_boxed(Box::new(err))
    }
}

impl fmt::Display for InvalidAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid attribute {}", self.oid)
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use super::*;

    fn rsync(s: &str) -> uri::Rsync {
        uri::Rsync::from_str(s).unwrap()
    }

    #[allow(dead_code)]
    fn https(s: &str) -> uri::Https {
        uri::Https::from_str(s).unwrap()
    }

    #[test]
    fn parse_drl_csr() {
        let bytes = include_bytes!("../../test-data/ca/drl-csr.der");
        let csr = RpkiCaCsr::decode(bytes.as_ref()).unwrap();
        csr.verify_signature().unwrap();

        assert!(csr.basic_ca());

        assert_eq!(
            csr.ca_repository(),
            Some(&rsync("rsync://localhost:4404/rpki/Alice/Bob/Carol/3/"))
        );
        assert_eq!(
            csr.rpki_manifest(),
            Some(&rsync(
                "rsync://localhost:4404/rpki/Alice/Bob/Carol/3/\
                IozwkwjtGls63XR8W2lo1wc7UoU.mnf"
            ))
        );
        assert_eq!(csr.rpki_notify(), None);

        assert!(BgpsecCsr::decode(bytes.as_ref()).is_err());
    }

    #[test]
    fn parse_router_csr() {
        let bytes = include_bytes!("../../test-data/ca/router-csr.der");
        let csr = BgpsecCsr::decode(bytes.as_ref()).unwrap();
        csr.verify_signature().unwrap();

        assert!(RpkiCaCsr::decode(bytes.as_ref()).is_err());
    }

    #[test]
    #[cfg(all(test, feature="softkeys"))]
    fn build_csr() {

        use crate::crypto::softsigner::OpenSslSigner;
        use crate::crypto::PublicKeyFormat;

        let signer = OpenSslSigner::new();
        let key = signer.create_key(PublicKeyFormat::Rsa).unwrap();


        let ca_repo = rsync("rsync://localhost/repo/");
        let rpki_mft = rsync("rsync://localhost/repo/ca.mft");
        let rpki_not = https("https://localhost/repo/notify.xml");

        let enc = Csr::construct_rpki_ca(
            &signer,
            &key,
            &ca_repo,
            &rpki_mft,
            Some(&rpki_not)
        ).unwrap();

        let csr = RpkiCaCsr::decode(enc.as_slice()).unwrap();
        csr.verify_signature().unwrap();

        let pub_key = signer.get_key_info(&key).unwrap();

        assert!(csr.basic_ca());
        assert_eq!(&pub_key, csr.public_key());
        assert_eq!(Some(&ca_repo), csr.ca_repository());
        assert_eq!(Some(&rpki_mft), csr.rpki_manifest());
        assert_eq!(Some(&rpki_not), csr.rpki_notify());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_csr() {
        let bytes = include_bytes!("../../test-data/ca/drl-csr.der");
        let csr = RpkiCaCsr::decode(bytes.as_ref()).unwrap();

        let csr_ser = serde_json::to_string(&csr).unwrap();
        let csr_des: RpkiCaCsr = serde_json::from_str(&csr_ser).unwrap();

        assert_eq!(
            csr.to_captured().as_slice(),
            csr_des.to_captured().as_slice()
        );
    }
}

#[cfg(all(test, feature="softkeys"))]
mod signer_test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn router_cert_from_csr() {
        use crate::crypto::keys::PublicKeyFormat;
        use crate::crypto::softsigner::OpenSslSigner;
        use crate::repository::cert::{Cert, Overclaim};
        use crate::repository::resources::{Asn, Prefix};
        use crate::repository::x509::Validity;
        use crate::repository::tal::TalInfo;

        let bytes = include_bytes!("../../test-data/ca/router-csr.der");
        let csr = BgpsecCsr::decode(bytes.as_ref()).unwrap();
        csr.verify_signature().unwrap();

        let signer = OpenSslSigner::new();
        let ca_key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
        let ca_pubkey = signer.get_key_info(&ca_key).unwrap();
        let uri = uri::Rsync::from_str("rsync://example.com/m/p").unwrap();
        let mut cert = TbsCert::new(
            12u64.into(), ca_pubkey.to_subject_name(),
            Validity::from_secs(86400), None, ca_pubkey, KeyUsage::Ca,
            Overclaim::Trim
        );
        cert.set_basic_ca(Some(true));
        cert.set_ca_repository(Some(uri.clone()));
        cert.set_rpki_manifest(Some(uri.clone()));
        cert.build_v4_resource_blocks(|b| b.push(Prefix::new(0, 0)));
        cert.build_v6_resource_blocks(|b| b.push(Prefix::new(0, 0)));
        cert.build_as_resource_blocks(|b| b.push((Asn::MIN, Asn::MAX)));
        let cert = cert.into_cert(&signer, &ca_key).unwrap().to_captured();
        let cert = Cert::decode(cert.as_slice()).unwrap();
        let talinfo = TalInfo::from_name("foo".into()).into_arc();
        let ca_cert = cert.validate_ta(talinfo, true).unwrap();

        let mut router_cert = TbsCert::new(
            42_u128.into(),
            ca_cert.subject().clone(),
            Validity::from_secs(86400),
            None,
            csr.public_key().clone(),
            KeyUsage::Ee,
            Overclaim::Refuse
        );
        router_cert.set_authority_key_identifier(
            Some(ca_cert.subject_key_identifier())
        );
        router_cert.set_ca_issuer(
            Some(uri.clone())
        );
        router_cert.set_crl_uri(
            Some(uri)
        );
        router_cert.set_extended_key_usage(
            Some(ExtendedKeyUsage::create_router())
        );
        router_cert.build_as_resource_blocks(
            |b| b.push(Asn::from(12))
        );

        // test sign and encode
        let router_cert = router_cert.into_cert(&signer, &ca_key).unwrap();

        // decode again
        let router_cert = router_cert.to_captured();
        let router_cert = Cert::decode(router_cert.as_slice()).unwrap();
        router_cert.validate_router(&ca_cert, true).unwrap();
    }
}

