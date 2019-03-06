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

use std::ops;
use bcder::{decode, encode};
use bcder::{BitString, Captured, Mode, OctetString, Tag, Unsigned};
use bcder::encode::PrimitiveContent;
use super::uri;
use super::cert::{CertBuilder, ResourceCert};
use super::crypto::DigestAlgorithm;
use super::sigobj::{SignedObject, SignedObjectBuilder};
use super::x509::{Time, ValidationError};
use crate::oid;


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
    pub fn decode<S: decode::Source>(
        source: S,
        strict: bool
    ) -> Result<Self, S::Err> {
        let signed = SignedObject::decode(source, strict)?;
        if signed.content_type().ne(&oid::AD_RPKI_MANIFEST) {
            return Err(decode::Malformed.into())
        }
        let content = signed.decode_content(
            |cons| ManifestContent::decode(cons)
        )?;
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
}


//------------ ManifestBuilder -----------------------------------------------

pub struct ManifestBuilder(SignedObjectBuilder<ManifestContentBuilder>);

impl ManifestBuilder {
    pub fn new(
        manifest_number: u128,
        this_update: Time,
        next_update: Time,
        file_hash_alg: DigestAlgorithm,
        cert: CertBuilder,
    ) -> Self {
        ManifestBuilder(
            SignedObjectBuilder::new(
                oid::AD_RPKI_MANIFEST,
                ManifestContentBuilder::new(
                    manifest_number, this_update, next_update, file_hash_alg
                ),
                cert
            )
        )
    }

    pub fn encode(self) -> SignedObjectBuilder<impl encode::Values> {
        self.0.map(ManifestContentBuilder::encode)
    }
}


//--- Deref, DerefMut, AsRef, and AsMut

impl ops::Deref for ManifestBuilder {
    type Target = SignedObjectBuilder<ManifestContentBuilder>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ops::DerefMut for ManifestBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<SignedObjectBuilder<ManifestContentBuilder>> for ManifestBuilder {
    fn as_ref(&self) -> &SignedObjectBuilder<ManifestContentBuilder> {
        &self.0
    }
}

impl AsMut<SignedObjectBuilder<ManifestContentBuilder>> for ManifestBuilder {
    fn as_mut(&mut self) -> &mut SignedObjectBuilder<ManifestContentBuilder> {
        &mut self.0
    }
}

impl AsRef<ManifestContentBuilder> for ManifestBuilder {
    fn as_ref(&self) -> &ManifestContentBuilder {
        self.0.content()
    }
}

impl AsMut<ManifestContentBuilder> for ManifestBuilder {
    fn as_mut(&mut self) -> &mut ManifestContentBuilder {
        self.0.content_mut()
    }
}


//------------ ManifestContent -----------------------------------------------

/// The content of an RPKI manifest.
///
/// A manifests consists chiefly of a list of files and their hash value. You
/// can access this list via the `iter_uris` method.
#[derive(Clone, Debug)]
pub struct ManifestContent {
    /// The number of this manifest.
    ///
    /// These numbers are similar to the serial numbers of certificates.
    manifest_number: Unsigned,

    /// The time this iteration of the manifest was created.
    this_update: Time,

    /// The time the next iteration of the manifest is likely to be created.
    next_update: Time,

    /// The list of files in its encoded form.
    file_list: Captured,

    /// The number of entries in the file list.
    len: usize,
}

impl ManifestContent {
    /// Decodes the manifest content from its encoded form.
    fn decode<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.take_opt_primitive_if(Tag::CTX_0, |prim| {
                if prim.to_u8()? != 0 {
                    xerr!(Err(decode::Malformed.into()))
                }
                else {
                    Ok(())
                }
            })?;
            let manifest_number = Unsigned::take_from(cons)?;
            let this_update = Time::take_from(cons)?;
            let next_update = Time::take_from(cons)?;
            if this_update > next_update {
                xerr!(return Err(decode::Malformed.into()));
            }
            oid::SHA256.skip_if(cons)?;
            let mut len = 0;
            let file_list = cons.take_sequence(|cons| {
                cons.capture(|cons| {
                    while let Some(()) = FileAndHash::skip_opt_in(cons)? {
                        len += 1;
                    }
                    Ok(())
                })
            })?;
            Ok(ManifestContent {
                manifest_number, this_update, next_update, file_list, len
            })
        })
    }

    /// Returns an iterator over the files in the manifest.
    ///
    /// Since the manifest only contains file names, the iterator needs a base
    /// URI to produce complete URIs. It is taken from `base`.
    ///
    /// The returned iterator returns a pair of the file URI and the SHA256
    /// hash of the file.
    pub fn iter_uris(&self, base: uri::Rsync) -> ManifestIter {
        ManifestIter { base, file_list: self.file_list.clone() }
    }

    /// Returns the number of entries in the file list.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the file list is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns whether the manifest is stale.
    ///
    /// A manifest is stale if it’s nextUpdate time has passed.
    pub fn is_stale(&self) -> bool {
        self.next_update < Time::now()
    }
}


//------------ ManifestIter --------------------------------------------------

/// An iterator over the files in the manifest.
///
/// The iterator returns pairs of the absolute URIs of the files and their
/// SHA256 hash values.
#[derive(Clone, Debug)]
pub struct ManifestIter{
    base: uri::Rsync,
    file_list: Captured,
}

impl Iterator for ManifestIter {
    type Item = Result<(uri::Rsync, ManifestHash), ValidationError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.file_list.is_empty() {
            None
        }
        else {
            self.file_list.decode_partial(|cons| {
                FileAndHash::take_opt_from(cons)
            }).unwrap().map(|item| {
                item.into_uri_etc(&self.base)
            })
        }
    }
}


//------------ ManifestContentBuilder ----------------------------------------

#[derive(Clone, Debug)]
pub struct ManifestContentBuilder {
    manifest_number: u128,
    this_update: Time,
    next_update: Time,
    file_hash_alg: DigestAlgorithm,
    file_list: Captured,
}

impl ManifestContentBuilder {
    pub fn new(
        manifest_number: u128,
        this_update: Time,
        next_update: Time,
        file_hash_alg: DigestAlgorithm,
    ) -> Self {
        ManifestContentBuilder {
            manifest_number,
            this_update,
            next_update,
            file_hash_alg,
            file_list: Captured::empty(Mode::Der),
        }
    }

    pub fn push(&mut self, item: &FileAndHash) {
        self.file_list.extend(item.encode_ref())
    }

    pub fn push_pair<D: AsRef<[u8]>>(&mut self, file: &[u8], hash: &D) {
        self.file_list.extend(
            encode::sequence((
                OctetString::encode_slice_as(file, Tag::IA5_STRING),
                BitString::encode_slice(hash, 0),
            ))
        )
    }

    pub fn encode(self) -> impl encode::Values {
        encode::sequence((
            0u8.encode_as(Tag::CTX_0),
            self.manifest_number.encode(),
            self.this_update.encode(),
            self.next_update.encode(),
            self.file_hash_alg.encode_oid(),
            encode::sequence(
                self.file_list
            )
        ))
    }
}


//------------ FileAndHash ---------------------------------------------------

/// An entry in the list of a manifest.
#[derive(Clone, Debug)]
pub struct FileAndHash {
    /// The name of the file.
    file: OctetString,

    /// A SHA256 hash over the file’s content.
    hash: ManifestHash,
}

impl FileAndHash {
    /// Skips over an optional value in a constructed value.
    fn skip_opt_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<()>, S::Err> {
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
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_sequence(|cons| {
            Ok(FileAndHash {
                file: cons.take_value_if(
                    Tag::IA5_STRING,
                    OctetString::from_content
                )?,
                hash: ManifestHash(BitString::take_from(cons)?)
            })
        })
    }

    /// Converts a value into a pair of an absolute URI and its hash.
    fn into_uri_etc(
        self,
        base: &uri::Rsync
    ) -> Result<(uri::Rsync, ManifestHash), ValidationError> {
        let name = self.file.into_bytes();
        if !name.is_ascii() {
            return Err(ValidationError)
        }
        Ok((base.join(&name), self.hash))
    }

    fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            self.file.encode_ref_as(Tag::IA5_STRING),
            self.hash.0.encode_ref()
        ))
    }
}


//------------ ManifestHash --------------------------------------------------

/// A manifest hash.
///
/// This is a SHA256 hash.
#[derive(Clone, Debug)]
pub struct ManifestHash(BitString);

impl ManifestHash {
    /// Check that `bytes` has the same hash value as `this`.
    pub fn verify<B: AsRef<[u8]>>(
        &self,
        bytes: B
    ) -> Result<(), ValidationError> {
        ::ring::constant_time::verify_slices_are_equal(
            self.0.octet_slice().unwrap(),
            ::ring::digest::digest(
                &::ring::digest::SHA256,
                bytes.as_ref()
            ).as_ref()
        ).map_err(|_| ValidationError)
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
}

#[cfg(all(test, feature="softkeys"))]
mod signer_test {
    use std::str::FromStr;
    use bcder::encode::Values;
    use crate::cert::Validity;
    use crate::crypto::{
        DigestAlgorithm, PublicKeyFormat, SignatureAlgorithm, Signer
    };
    use crate::crypto::softsigner::OpenSslSigner;
    use crate::resources::{AsId, Prefix};
    use crate::uri;
    use super::*;

    #[test]
    fn encode_manifest() {
        let mut signer = OpenSslSigner::new();
        let key = signer.create_key(PublicKeyFormat).unwrap();
        let pubkey = signer.get_key_info(&key).unwrap();
        let uri = uri::Rsync::from_str("rsync://example.com/m/p").unwrap();

        let mut cert = CertBuilder::new(
            12, pubkey.to_subject_name(), Validity::from_secs(86400), true
        );
        cert.rpki_manifest(uri.clone())
            .v4_blocks(|blocks| blocks.push(Prefix::new(0, 0)))
            .as_blocks(|blocks| blocks.push((AsId::MIN, AsId::MAX)));

        let mut builder = ManifestBuilder::new(
            12, Time::now(), Time::now(), DigestAlgorithm, cert
        );
        builder.push_pair(b"file.name", b"123");
        builder.push_pair(b"file.name", b"123");
        let captured = builder.encode().encode(
            &signer, &key, SignatureAlgorithm, DigestAlgorithm,
            SignatureAlgorithm
        ).unwrap().to_captured(Mode::Der);

        let _roa = Manifest::decode(captured.as_slice(), true).unwrap();
    }
}


//============ Specification Documentation ===================================

/// Manifest Specification.
///
/// This is a documentation-only module. It summarizes the specification for
/// ROAs, how they are parsed and constructed.
///
/// A manifest is a [signed object] that lists all the objects published by
/// an RPKI certificate authority. It is specified in [RFC 6486].
///
/// The content of a manifest signed object is of type `Manifest` which is
/// defined as follows:
///
/// ```txt
/// Manifest            ::= SEQUENCE {
///     version             [0] INTEGER DEFAULT 0,
///     manifestNumber      INTEGER (0..MAX),
///     thisUpdate          GeneralizedTime,
///     nextUpdate          GeneralizedTime,
///     fileHashAlg         OBJECT IDENTIFIER,
///     fileList            SEQUENCE SIZE (0..MAX) OF FileAndHash
/// }
///
/// FileAndHash         ::= SEQUENCE {
///     file                IA5String,
///     hash                BIT STRING
/// }
/// ```
///
/// The _version_ must be 0. Both the time values must be UTC times as
/// specified for certificates.
///
/// [signed object]: ../../sigobj/spec/index.html
/// [RFC 6486]: https://tools.ietf.org/html/rfc6486
pub mod spec { }
