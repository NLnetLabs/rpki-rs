//! Trust Anchor Key (TAK)
//! 
//! In full: RPKI Signed Object for Trust Anchor Key
//! 
//! These objects are designed to facilitate planned RPKI Trust Anchor
//! Key roll-overs. They serve to signal an updated TAL to Relying Parties.
//! The updated TAL is signed by the current (to become old) TA.
//! 
//! This is currently an IETF draft in WG last call:
//! See: https://datatracker.ietf.org/doc/draft-ietf-sidrops-signed-tal/

use std::convert::TryFrom;

use bcder::{Oid, Mode, encode, Utf8String, Captured, Tag};
use bcder::encode::Values;
use bcder::encode::PrimitiveContent;

use crate::{uri, crypto::{PublicKey, SigningError, Signer}, oid};

use super::{sigobj::{SignedObject, SignedObjectBuilder}, tal::TalUri, Tal};


//------------ Tak -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Tak {
    signed: SignedObject,
    _content: TakContent,
}

impl Tak {
    pub fn build<S: Signer>(
        content: TakContent,
        mut sigobj: SignedObjectBuilder,
        signer: &S,
        issuer_key: &S::KeyId,
    ) -> Result<Self, SigningError<S::Error>> {
        sigobj.set_as_resources_inherit();
        sigobj.set_v4_resources_inherit();
        sigobj.set_v6_resources_inherit();
        let signed = sigobj.finalize(
            Oid(oid::TRUST_ANCHOR_KEY.0.into()),
            content.encode_ref().to_captured(Mode::Der).into_bytes(),
            signer,
            issuer_key,
        )?;
        Ok(Tak { signed, _content: content })
    }

    /// Returns a DER encoded Captured for this Tak.
    pub fn to_captured(&self) -> Captured {
        self.signed.encode_ref().to_captured(Mode::Der)
    }
}


//------------ TakContent ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct TakContent {
    current: TaKey,
    predecessor: Option<TaKey>,
    successor: Option<TaKey>
}

impl TakContent {
    pub fn new(
        current: TaKey,
        predecessor: Option<TaKey>,
        successor: Option<TaKey>
    ) -> Self {
        TakContent { current, predecessor, successor }
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            // version is default
            self.current.encode_ref(),
            self.predecessor.as_ref().map(|k| k.encode_ref_as(Tag::CTX_0)),
            self.successor.as_ref().map(|k| k.encode_ref_as(Tag::CTX_1)),
        ))
    }
}

//------------ TaKey ---------------------------------------------------------

#[derive(Clone, Debug)]
pub struct TaKey {
    comments: Vec<Utf8String>,
    certificate_uris: Vec<TalUri>,
    subject_public_key_info: PublicKey,
}

impl TaKey {
    pub fn create(
        comment_strings: Vec<String>,
        certificate_uris: Vec<TalUri>,
        subject_public_key_info: PublicKey,
    ) -> Result<Self, TaKeyError> {
        
        let mut comments = vec![];
        for string in comment_strings {
            let comment = Utf8String::from_string(string)
                                .map_err(|_| TaKeyError::NonUtf8Comment)?;

            comments.push(comment);
        }
        
        Ok(TaKey { comments, certificate_uris, subject_public_key_info })
    }

    pub fn https_uris(&self) -> Vec<&uri::Https> {
        self.certificate_uris.iter().flat_map(|uri| uri.as_https_opt()).collect()
    }

    pub fn rsync_uris(&self) -> Vec<&uri::Rsync> {
        self.certificate_uris.iter().flat_map(|uri| uri.as_rsync_opt()).collect()
    }
    
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        self.encode_ref_as(Tag::SEQUENCE)
    }

    #[allow(clippy::clone_double_ref)]
    fn encode_ref_as(&self, tag: Tag) -> impl encode::Values + '_ {
        encode::sequence_as(
            tag,
            (
                encode::sequence(
                    encode::slice(
                        self.comments.as_slice(),
                        |c: &Utf8String| c.clone().encode()
                    )
                ),
                encode::sequence(
                    (
                        encode::slice(
                            self.https_uris(),
                            |uri| uri.clone().encode()
                        ),
                        encode::slice(
                            self.rsync_uris(),
                            |uri| uri.clone().encode()
                        ),
                    )
                ),
                self.subject_public_key_info.encode_ref()
            )
        )
    }
}

impl TryFrom<&Tal> for TaKey {
    type Error = TaKeyError;
    
    fn try_from(tal: &Tal) -> Result<Self, Self::Error> {
        TaKey::create(
            tal.comments().clone(),
            tal.uris().cloned().collect(),
            tal.key_info().clone()
        )
    }
}

//------------ TaKeyError ----------------------------------------------------

#[derive(Debug)]
pub enum TaKeyError {
    NonUtf8Comment,
}

//============ Tests =========================================================

#[cfg(test)]
mod test { }

#[cfg(all(test, feature="softkeys"))]
mod signer_test {
    use std::str::FromStr;
    
    use routecore::asn::Asn;
    
    use crate::crypto::PublicKeyFormat;
    use crate::crypto::signer::Signer;
    use crate::crypto::softsigner::OpenSslSigner;
    use crate::repository::cert::{TbsCert, KeyUsage, Overclaim};
    use crate::repository::resources::Prefix;
    use crate::repository::x509::Validity;

    use super::*;

    #[test]
    fn make_tak() {
        let signer = OpenSslSigner::new();
        let ta_signing_key = signer.create_key(PublicKeyFormat::Rsa).unwrap();

        let ta_https = uri::Https::from_str("https://example.com/ta.cer").unwrap();
        let ta_rsync = uri::Rsync::from_str("rsync://example.com/rsync/ta.cer").unwrap();

        let ta_repo = uri::Rsync::from_str("rsync://example.com/ta/").unwrap();
        let ta_mft = ta_repo.join(b"ta.mft").unwrap();
        let ta_crl = ta_repo.join(b"ta.crl").unwrap();
        let ta_tak = ta_repo.join(b"tak.tak").unwrap();

        let ta_cert = {
            let pubkey = signer.get_key_info(&ta_signing_key).unwrap();
    
            let mut cert = TbsCert::new(
                12u64.into(), pubkey.to_subject_name(),
                Validity::from_secs(86400), None, pubkey, KeyUsage::Ca,
                Overclaim::Refuse
            );
            cert.set_basic_ca(Some(true));
            cert.set_ca_repository(Some(ta_repo.clone()));
            cert.set_rpki_manifest(Some(ta_mft.clone()));
            cert.build_v4_resource_blocks(|b| b.push(Prefix::new(0, 0)));
            cert.build_v6_resource_blocks(|b| b.push(Prefix::new(0, 0)));
            cert.build_as_resource_blocks(|b| b.push((Asn::MIN, Asn::MAX)));
            cert.into_cert(&signer, &ta_signing_key).unwrap()
        };

        let tal_comments = vec!["My nice TA".to_string()];
        let tal_uris = vec![ 
            TalUri::Https(ta_https),
            TalUri::Rsync(ta_rsync.clone())
        ];
        let tal_key_info = ta_cert.subject_public_key_info().clone();
        let tal_name = "TAL".to_string();

        let tal = Tal::new(tal_comments, tal_uris, tal_key_info, tal_name);

        let ta_key = TaKey::try_from(&tal).unwrap();

        let current = ta_key.clone();
        let predecessor = Some(ta_key.clone());
        let successor = Some(ta_key.clone());

        let tak_content = TakContent::new(current, predecessor, successor);

        let tak_object_builder = SignedObjectBuilder::new(
            1_u64.into(),
            Validity::from_secs(86400),
            ta_crl,
            ta_rsync,
            ta_tak
        );

        let _tak = Tak::build(
            tak_content,
            tak_object_builder,
            &signer,
            &ta_signing_key
        ).unwrap();

        // let bytes = tak.to_captured().into_bytes();
        // panic!("{}", base64::encode(&bytes));
    }
}

//============ Specification Documentation ===================================

/// TAK Specification
/// 
/// This is a documentation-only module. It summarizes the specification for
/// TAKs, how they are parsed and constructed.
///
/// A TAK is a [signed object] that can be used by an RPKI TA to signal a
/// transition to new key, or new location(s) of its TA certificate to
/// Relying Parties.
/// See: https://datatracker.ietf.org/doc/draft-ietf-sidrops-signed-tal/
/// 
/// ```txt
/// TAK ::= SEQUENCE {
///     version     INTEGER DEFAULT 0,
///     current     TAKey,
///     predecessor [0] TAKey OPTIONAL,
///     successor   [1] TAKey OPTIONAL
/// }
/// 
/// TAKey ::= SEQUENCE {
///     comments  SEQUENCE SIZE (0..MAX) OF UTF8String,
///     certificateURIs  SEQUENCE SIZE (1..MAX) OF CertificateURI,
///     subjectPublicKeyInfo  SubjectPublicKeyInfo
/// }
/// 
/// CertificateURI ::= IA5String
/// ```
/// 
/// The _version_ MUST be 0. SubjectPublicKeyInfo is the same as used on
/// certificates.
pub mod spec { }