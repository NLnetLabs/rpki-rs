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

use bcder::{decode, encode, xerr};
use bcder::{BitString, Captured, Mode, OctetString, Oid, Tag};
use bcder::encode::{PrimitiveContent, Constructed};
use crate::{oid, uri};
use crate::cert::{KeyUsage, Sia, TbsCert};
use crate::cert::builder;
use crate::crypto::{SignatureAlgorithm, PublicKey};
use crate::crypto::signer::{Signer, SigningError};
use crate::x509::{Name, SignedData, ValidationError};


//------------ Csr -----------------------------------------------------------

/// An RPKI Certificate Sign Request.
#[derive(Clone, Debug)]
pub struct Csr {
    /// The outer structure of the CSR.
    signed_data: SignedData,

    /// The content of the CSR.
    content: CsrContent
}

/// # Data Access
///
impl Csr {
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
    pub fn extended_key_usage(&self) -> Option<&Captured> {
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

/// # Decode and Validate
///
impl Csr {
    /// Parse as a source as a certificate signing request.
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded CSR from the beginning of a constructed value.
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the content of a certificate signing request.
    fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::from_constructed(cons)?;
        let content = signed_data.data().clone().decode(CsrContent::take_from)?;

        Ok(Self { signed_data, content })
    }

    /// Validates the CSR against its internal public key
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.signed_data.verify_signature(self.public_key())
    }
}

/// # Construct
///
impl Csr {
    /// Builds a new Csr for RPKI CA certificates.
    ///
    /// Other use cases are not required in RPKI, and for simplicity they are
    /// not supported here. That means that BasicConstraints, KeyUsage, and
    /// algorithm do not need to be specified. Only the values for the
    /// required SIA entries for 'id-ad-caRepository' and
    /// 'id-ad-rpkiManifest' (see RFC6487), and the optional entry for
    /// 'id-ad-rpkiNotify' (see RFC8182), need to be specified.
    pub fn construct<S: Signer>(
        signer: &S,
        key: &S::KeyId,
        ca_repository: &uri::Rsync,
        rpki_manifest: &uri::Rsync,
        rpki_notify: Option<&uri::Https>
    ) -> Result<Captured, SigningError<S::Error>> {
        let pub_key = signer.get_key_info(key)?;

        let content = Captured::from_values(Mode::Der, encode::sequence((
            0_u32.encode(),
            Name::from_pub_key(&pub_key).encode_ref(),
            pub_key.encode_ref(),

            Constructed::new(Tag::CTX_0, encode::sequence((
                oid::EXTENSION_REQUEST.encode_ref(),
                encode::set(encode::sequence((
                    builder::extension(
                        &oid::CE_BASIC_CONSTRAINTS, true,
                        encode::sequence(true.encode())
                    ),
                    builder::extension(
                        &oid::CE_KEY_USAGE, true,
                        KeyUsage::Ca.encode()
                    ),
                    builder::extension(
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
            SignatureAlgorithm::default(),
            &content
        )?.unwrap();

        Ok(Captured::from_values(Mode::Der,
            encode::sequence((
            content,
            alg.x509_encode(),
            BitString::new(0, signature).encode()
        ))))
    }
}


//------------ CsrContent ----------------------------------------------------

#[derive(Clone, Debug)]
struct CsrContent {
    subject: Name,
    public_key: PublicKey,
    attributes: CsrAttributes
}

impl CsrContent {
    /// Takes a value from the beginning of an encoded constructed value.
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.skip_u8_if(0)?; // version MUST be 0, cause v1
            let subject = Name::take_from(cons)?;
            let public_key = PublicKey::take_from(cons)?;
            let attributes = CsrAttributes::take_from(cons)?;
            Ok(CsrContent { subject, public_key, attributes })
        })
    }
}


//------------ CsrAttributes -------------------------------------------------

#[derive(Clone, Debug)]
struct CsrAttributes {
    basic_ca: bool,
    key_usage: KeyUsage,
    extended_key_usage: Option<Captured>,
    sia: Sia
}

impl CsrAttributes {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_constructed_if(Tag::CTX_0, |cons| {

            let mut basic_ca: Option<bool> = None;
            let mut key_usage: Option<KeyUsage> = None;
            let mut extended_key_usage: Option<Captured> = None;
            let mut sia: Option<Sia> = None;

            cons.take_sequence(|cons| {
                let id = Oid::take_from(cons)?;
                if id == oid::EXTENSION_REQUEST {
                    cons.take_set(|cons| { cons.take_sequence(|cons| {
                        while let Some(()) = cons.take_opt_sequence(|cons| {

                            let id = Oid::take_from(cons)?;
                            let _crit = cons.take_opt_bool()?;

                            let value = OctetString::take_from(cons)?;

                            Mode::Der.decode(value.to_source(), |content| {
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
                                    Err(decode::Malformed)
                                }
                            })?;


                            Ok(())
                        })? {};
                        Ok(())
                    })})
                } else {
                    xerr!(Err(decode::Malformed).map_err(Into::into))
                }
            })?;

            let basic_ca = basic_ca.ok_or_else(|| decode::Malformed)?;
            let key_usage = key_usage.ok_or_else(|| decode::Malformed)?;
            let sia = sia.ok_or_else(|| decode::Malformed)?;

            Ok(CsrAttributes {
                    basic_ca, key_usage, extended_key_usage, sia
            })
        })
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
        let bytes = include_bytes!("../test-data/drl-csr.der");

        let csr = Csr::decode(bytes.as_ref()).unwrap();

        csr.validate().unwrap();

        assert!(csr.basic_ca());

        let ca_repo = rsync("rsync://localhost:4404/rpki/Alice/Bob/Carol/3/");
        assert_eq!(Some(&ca_repo), csr.ca_repository());

        let rpki_mft = rsync("rsync://localhost:4404/rpki/Alice/Bob/Carol/3/IozwkwjtGls63XR8W2lo1wc7UoU.mnf");
        assert_eq!(Some(&rpki_mft), csr.rpki_manifest());

        assert_eq!(None, csr.rpki_notify());
    }

    #[test]
    #[cfg(all(test, feature="softkeys"))]
    fn build_csr() {

        use crate::crypto::softsigner::OpenSslSigner;
        use crate::crypto::PublicKeyFormat;

        let mut signer = OpenSslSigner::new();
        let key = signer.create_key(PublicKeyFormat::default()).unwrap();


        let ca_repo = rsync("rsync://localhost/repo/");
        let rpki_mft = rsync("rsync://localhost/repo/ca.mft");
        let rpki_not = https("https://localhost/repo/notify.xml");

        let enc = Csr::construct(
            &signer,
            &key,
            &ca_repo,
            &rpki_mft,
            Some(&rpki_not)
        ).unwrap();

        let csr = Csr::decode(enc.as_slice()).unwrap();
        csr.validate().unwrap();

        let pub_key = signer.get_key_info(&key).unwrap();

        assert!(csr.basic_ca());
        assert_eq!(&pub_key, csr.public_key());
        assert_eq!(Some(&ca_repo), csr.ca_repository());
        assert_eq!(Some(&rpki_mft), csr.rpki_manifest());
        assert_eq!(Some(&rpki_not), csr.rpki_notify());
    }
}