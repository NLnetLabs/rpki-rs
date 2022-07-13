//! RPKI Manifests.
//!
//! Manifests list all the files that are currently published by an RPKI CA.
//! They are defined in RFC 6486.
//!
//! This module defines the type [`Manifest`] that represents a decoded
//! manifest and the type [`ManifestContent`] for the content of a validated
//! manifest, as well as some helper types for accessing the content.
//!
//! [`Manifest`]: struct.Manifest.html
//! [`ManifestContent`]: struct.ManifestContent.html

use std::{borrow, fmt, ops};
use bcder::{decode, encode};
use bcder::{
    BitString, Captured, Ia5String, Mode, OctetString, Oid, Tag,
};
use bcder::decode::{DecodeError, IntoSource, Source};
use bcder::encode::{PrimitiveContent, Values};
use bytes::Bytes;
use crate::{oid, uri};
use crate::crypto::{DigestAlgorithm, Signer, SigningError};
use super::cert::{Cert, ResourceCert};
use super::error::{ValidationError, VerificationError};
use super::sigobj::{SignedObject, SignedObjectBuilder};
use super::x509::{Serial, Time};


//------------ Manifest ------------------------------------------------------

/// A decoded RPKI manifest.
///
/// This type represents a manifest decoded from a source. In order to get to
/// the manifest’s content, you need to validate it via the `validate`
/// method.
#[derive(Clone, Debug)]
pub struct Manifest {
    signed: SignedObject,
    content: ManifestContent,
}

impl Manifest {
    /// Decodes a manifest from a source.
    pub fn decode<S: IntoSource>(
        source: S,
        strict: bool
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        let signed = SignedObject::decode_if_type(
            source, &oid::CT_RPKI_MANIFEST, strict
        )?;
        let content = signed.decode_content(
            |cons| ManifestContent::take_from(cons)
        ).map_err(DecodeError::convert)?;
        Ok(Manifest { signed, content })
    }

    /// Validates the manifest.
    ///
    /// You need to pass in the certificate of the issuing CA. If validation
    /// succeeds, the result will be the EE certificate of the manifest and
    /// the manifest content.
    pub fn validate(
        self,
        cert: &ResourceCert,
        strict: bool,
    ) -> Result<(ResourceCert, ManifestContent), ValidationError> {
        self.validate_at(cert, strict, Time::now())
    }

    pub fn validate_at(
        self,
        cert: &ResourceCert,
        strict: bool,
        now: Time
    ) -> Result<(ResourceCert, ManifestContent), ValidationError> {
        let cert = self.signed.validate_at(cert, strict, now)?;
        Ok((cert, self.content))
    }

    /// Returns a value encoder for a reference to the manifest.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        self.signed.encode_ref()
    }

    /// Returns a DER encoded Captured for this.
    pub fn to_captured(&self) -> Captured {
        self.encode_ref().to_captured(Mode::Der)
    }

    /// Returns a reference to the EE certificate of this manifest.
    pub fn cert(&self) -> &Cert {
        self.signed.cert()
    }

    /// Returns a reference to the manifest content.
    pub fn content(&self) -> &ManifestContent {
        &self.content
    }
}


//--- Deref, AsRef, and Borrow

impl ops::Deref for Manifest {
    type Target = ManifestContent;

    fn deref(&self) -> &Self::Target {
        &self.content
    }
}

impl AsRef<Manifest> for Manifest {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<ManifestContent> for Manifest {
    fn as_ref(&self) -> &ManifestContent {
        &self.content
    }
}

impl borrow::Borrow<ManifestContent> for Manifest {
    fn borrow(&self) -> &ManifestContent {
        &self.content
    }
}


//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for Manifest {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error> {
        let bytes = self.to_captured().into_bytes();
        let b64 = base64::encode(&bytes);
        b64.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Manifest {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        let string = String::deserialize(deserializer)?;
        let decoded = base64::decode(&string).map_err(de::Error::custom)?;
        let bytes = Bytes::from(decoded);
        Manifest::decode(bytes, true).map_err(de::Error::custom)
    }
}


//------------ ManifestContent -----------------------------------------------

/// The content of an RPKI manifest.
#[derive(Clone, Debug)]
pub struct ManifestContent {
    /// The number of this manifest.
    manifest_number: Serial,

    /// The time this iteration of the manifest was created.
    this_update: Time,

    /// The time the next iteration of the manifest is likely to be created.
    next_update: Time,

    /// The digest algorithm used for the file hash.
    file_hash_alg: DigestAlgorithm,

    /// The list of files.
    ///
    /// This contains the content of the fileList sequence, i.e, not the
    /// outer sequence object.
    file_list: Captured,

    /// The length of the list.
    len: usize,
}


/// # Creation and Conversion
///
impl ManifestContent {
    pub fn new<I, FH, F, H>(
        manifest_number: Serial,
        this_update: Time,
        next_update: Time,
        file_hash_alg: DigestAlgorithm,
        iter: I,
    ) -> Self
    where
        I: IntoIterator<Item = FH>,
        FH: AsRef<FileAndHash<F, H>>,
        F: AsRef<[u8]>,
        H: AsRef<[u8]>,
    {
        let mut len = 0;
        let mut file_list = Captured::builder(Mode::Der);
        for item in iter.into_iter() {
            file_list.extend(item.as_ref().encode_ref());
            len += 1;
        }
        Self {
            manifest_number,
            this_update,
            next_update,
            file_hash_alg,
            file_list: file_list.freeze(),
            len
        }
    }

    pub fn into_manifest<S: Signer>(
        self,
        mut sigobj: SignedObjectBuilder,
        signer: &S,
        issuer_key: &S::KeyId,
    ) -> Result<Manifest, SigningError<S::Error>> {
        sigobj.set_v4_resources_inherit();
        sigobj.set_v6_resources_inherit();
        sigobj.set_as_resources_inherit();
        let signed = sigobj.finalize(
            Oid(oid::CT_RPKI_MANIFEST.0.into()),
            self.encode_ref().to_captured(Mode::Der).into_bytes(),
            signer,
            issuer_key,
        )?;
        Ok(Manifest { signed, content: self })
    }
}


/// # Data Access
///
impl ManifestContent {
    /// Returns the manifest number.
    pub fn manifest_number(&self) -> Serial {
        self.manifest_number
    }

    /// Returns the time when this manifest was created.
    pub fn this_update(&self) -> Time {
        self.this_update
    }

    /// Returns the time when the next update to the manifest should appear.
    pub fn next_update(&self) -> Time {
        self.next_update
    }

    /// Returns the hash algorithm for the file list entries.
    pub fn file_hash_alg(&self) -> DigestAlgorithm {
        self.file_hash_alg
    }

    /// Returns an iterator over the file list.
    pub fn iter(&self) -> FileListIter {
        FileListIter(self.file_list.clone())
    }

    /// Returns an iterator over URL and hash pairs.
    ///
    /// The iterator assumes that all files referred to in the manifest are
    /// relative to the given rsync URI.
    pub fn iter_uris<'a>(
        &'a self,
        base: &'a uri::Rsync
    ) -> impl Iterator<Item = (uri::Rsync, ManifestHash)> + 'a {
        let alg = self.file_hash_alg;
        self.iter().map(move |item| {
            let (file, hash) = item.into_pair();
            (
                base.join(file.as_ref()).unwrap(),
                ManifestHash::new(hash, alg)
            )
        })
    }

    /// Returns the length of the file list.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the file list is empty.
    pub fn is_empty(&self) -> bool {
        self.file_list.is_empty()
    }

    /// Returns whether the manifest is stale.
    ///
    /// A manifest is stale if it’s nextUpdate time has passed.
    pub fn is_stale(&self) -> bool {
        self.next_update < Time::now()
    }
}

/// # Decoding and Encoding
///
impl ManifestContent {
    /// Takes the content from the beginning of an encoded constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            cons.take_opt_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(0))?;
            let manifest_number = Serial::take_from(cons)?;
            let this_update = Time::take_from(cons)?;
            let next_update = Time::take_from(cons)?;
            let file_hash_alg = DigestAlgorithm::take_oid_from(cons)?;
            if this_update > next_update {
                return Err(cons.content_err(
                    "thisUpdate after nextUpdate"
                ));
            }

            let mut len = 0;
            let file_list = cons.take_sequence(|cons| {
                cons.capture(|cons| {
                    while let Some(()) = FileAndHash::skip_opt_in(cons)? {
                        len += 1;
                    }
                    Ok(())
                })
            })?;
 
            Ok(Self {
                manifest_number,
                this_update,
                next_update,
                file_hash_alg,
                file_list,
                len
            })
        })
    }


    /// Returns a value encoder for a reference to the content.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            self.manifest_number.encode(),
            self.this_update.encode_generalized_time(),
            self.next_update.encode_generalized_time(),
            self.file_hash_alg.encode_oid(),
            encode::sequence(
                &self.file_list
            )
        ))
    }
}


//------------ FileListIter --------------------------------------------------

/// An iterator over the content of a file list.
#[derive(Clone, Debug)]
pub struct FileListIter(Captured);

impl Iterator for FileListIter {
    type Item = FileAndHash<Bytes, Bytes>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.decode_partial(|cons| {
            FileAndHash::take_opt_from(cons)
        }).unwrap()
    }
}


//------------ FileAndHash ---------------------------------------------------

/// An entry in the manifest file list.
///
/// This type contains a file name and a hash over the file. Both are
/// expressed through generic types for superior flexibility.
#[derive(Clone, Debug)]
pub struct FileAndHash<F, H> {
    /// The name of a file.
    file: F,

    /// The hash over the file’s content.
    hash: H
}

/// # Data Access
impl<F, H> FileAndHash<F, H> {
    /// Creates a new value.
    pub fn new(file: F, hash: H) -> Self {
        FileAndHash { file, hash }
    }

    /// Returns a reference to the file name.
    pub fn file(&self) -> &F {
        &self.file
    }

    /// Returns a reference to the hash.
    pub fn hash(&self) -> &H {
        &self.hash
    }

    /// Returns a pair of the file and the hash.
    pub fn into_pair(self) -> (F, H) {
        (self.file, self.hash)
    }
}


/// # Decoding and Encoding
///
impl FileAndHash<Bytes, Bytes> {
    /// Skips over an optional value in a constructed value.
    fn skip_opt_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<()>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            cons.take_value_if(
                Tag::IA5_STRING,
                OctetString::from_content
            )?;
            BitString::skip_in(cons)?;
            Ok(())
        })
    }

    /// Takes an optional value from the beginning of a constructed value.
    fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            Ok(FileAndHash {
                file: Ia5String::take_from(cons)?.into_bytes(),
                hash: BitString::take_from(cons)?.octet_bytes(),
            })
        })
    }
}

impl<F: AsRef<[u8]>, H: AsRef<[u8]>> FileAndHash<F, H> {
    /// Returns a value encoder for a reference.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            OctetString::encode_slice_as(self.file.as_ref(), Tag::IA5_STRING),
            BitString::encode_slice(self.hash.as_ref(), 0),
        ))
    }
}


//--- AsRef

impl<F: AsRef<[u8]>, H: AsRef<[u8]>> AsRef<Self> for FileAndHash<F, H> {
    fn as_ref(&self) -> &Self {
        self
    }
}


//------------ ManifestHash --------------------------------------------------

/// A file hash value gained from a manifest.
///
/// This type knows the hash value itself plus the digest algorithm used for
/// this hash and thus can verify objects.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ManifestHash {
    hash: Bytes,
    algorithm: DigestAlgorithm,
}

impl ManifestHash {
    /// Creates a new manifest hash from the hash and algorithm.
    pub fn new(hash: Bytes, algorithm: DigestAlgorithm) -> Self {
        Self { hash, algorithm }
    }

    /// Verifies whether an octet sequence is matched by this hash.
    pub fn verify<T: AsRef<[u8]>>(
        &self,
        t: T
    ) -> Result<(), ManifestHashMismatch> {
        ring::constant_time::verify_slices_are_equal(
            self.hash.as_ref(),
            self.algorithm.digest(t.as_ref()).as_ref()
        ).map_err(|_| ManifestHashMismatch(()))
    }

    /// Returns the digest algorithm of the hash.
    pub fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// Returns the hash value as a bytes slice.
    pub fn as_slice(&self) -> &[u8] {
        self.hash.as_ref()
    }
}


//============ Errors ========================================================

/// A manifest hash didn’t match an object’s hash.
#[derive(Clone, Copy, Debug)]
pub struct ManifestHashMismatch(());

impl fmt::Display for ManifestHashMismatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("manifest hash mismatch")
    }
}

impl From<ManifestHashMismatch> for VerificationError {
    fn from(_: ManifestHashMismatch) -> VerificationError {
        VerificationError::new("manifest hash mismatch")
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use crate::repository::cert::Cert;
    use crate::repository::tal::TalInfo;
    use super::*;

    #[test]
    fn decode() {
        let talinfo = TalInfo::from_name("foo".into()).into_arc();
        let at = Time::utc(2019, 5, 1, 0, 0, 0);
        let issuer = Cert::decode(
            include_bytes!("../../test-data/ta.cer").as_ref()
        ).unwrap();
        let issuer = issuer.validate_ta_at(talinfo, false, at).unwrap();
        let obj = Manifest::decode(
            include_bytes!("../../test-data/ta.mft").as_ref(),
            false
        ).unwrap();
        obj.validate_at(&issuer, false, at).unwrap();
        let obj = Manifest::decode(
            include_bytes!("../../test-data/ca1.mft").as_ref(),
            false
        ).unwrap();
        assert!(obj.validate_at(&issuer, false, at).is_err());
    }
}

#[cfg(all(test, feature = "softkeys"))]
mod signer_test {
    use std::str::FromStr;
    use bcder::encode::Values;
    use crate::uri;
    use crate::repository::cert::{KeyUsage, Overclaim, TbsCert};
    use crate::crypto::{PublicKeyFormat, Signer};
    use crate::crypto::softsigner::OpenSslSigner;
    use crate::repository::resources::{Asn, Prefix};
    use crate::repository::tal::TalInfo;
    use crate::repository::x509::Validity;
    use super::*;

    fn make_test_manifest() -> Manifest {
        let signer = OpenSslSigner::new();
        let key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
        let pubkey = signer.get_key_info(&key).unwrap();
        let uri = uri::Rsync::from_str("rsync://example.com/m/p").unwrap();

        let mut cert = TbsCert::new(
            12u64.into(), pubkey.to_subject_name(),
            Validity::from_secs(86400), None, pubkey, KeyUsage::Ca,
            Overclaim::Trim
        );
        cert.set_basic_ca(Some(true));
        cert.set_ca_repository(Some(uri.clone()));
        cert.set_rpki_manifest(Some(uri.clone()));
        cert.build_v4_resource_blocks(|b| b.push(Prefix::new(0, 0)));
        cert.build_v6_resource_blocks(|b| b.push(Prefix::new(0, 0)));
        cert.build_as_resource_blocks(|b| b.push((Asn::MIN, Asn::MAX)));
        let cert = cert.into_cert(&signer, &key).unwrap();

        let content = ManifestContent::new(
            12u64.into(), Time::now(), Time::next_week(),
            DigestAlgorithm::default(),
            [
                FileAndHash::new(b"file".as_ref(), b"hash".as_ref()),
                FileAndHash::new(b"file".as_ref(), b"hash".as_ref()),
            ].iter()
        );

        let manifest = content.into_manifest(
            SignedObjectBuilder::new(
                12u64.into(), Validity::from_secs(86400), uri.clone(),
                uri.clone(), uri
            ),
            &signer, &key
        ).unwrap();
        let manifest = manifest.encode_ref().to_captured(Mode::Der);

        let manifest = Manifest::decode(manifest.as_slice(), true).unwrap();
        let cert = cert.validate_ta(
            TalInfo::from_name("foo".into()).into_arc(), true
        ).unwrap();
        manifest.clone().validate(&cert, true).unwrap();

        manifest
    }

    #[test]
    fn encode_manifest() {
        make_test_manifest();
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_manifest() {
        let mft = make_test_manifest();
        let serialized = serde_json::to_string(&mft).unwrap();
        let deser_mft: Manifest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            mft.to_captured().into_bytes(),
            deser_mft.to_captured().into_bytes()
        );
    }
}

