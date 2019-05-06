//! Digest algorithm and operations.

use std::io;
use ring::digest;
use bcder::{decode, encode};
use bcder::encode::PrimitiveContent;
use bcder::Tag;
use crate::oid;

// Re-export the things from ring for actual digest generation.
pub use ring::digest::Digest;


//------------ DigestAlgorithm -----------------------------------------------

/// The digest algorithms used by RPKI.
///
/// These are the algorithms used by the signature algorithms. For use in
/// RPKI, [RFC 7935] limits them to exactly one, SHA-256. Because of
/// that, this type is currently a zero-sized struct. If additional
/// algorithms are ever introduced in the future, it will change into an enum.
///
/// [RFC 7935]: https://tools.ietf.org/html/rfc7935
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct DigestAlgorithm(());


/// # Creating Digest Values
///
impl DigestAlgorithm {
    /// Returns the digest of `data` using this algorithm.
    pub fn digest(self, data: &[u8]) -> Digest {
        digest::digest(&digest::SHA256, data)
    }

    /// Returns a digest context for multi-step calculation of the digest.
    pub fn start(self) -> Context {
        Context(digest::Context::new(&digest::SHA256))
    }
}


/// # ASN.1 Values
///
/// Digest algorithms appear in CMS either alone or in sets with the following
/// syntax:
///
/// ```txt
/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
/// DigestAlgorithmIdentifier  ::= AlgorithmIdentifier
/// AlgorithmIdentifier        ::= SEQUENCE {
///      algorithm                 OBJECT IDENTIFIER,
///      parameters                ANY DEFINED BY algorithm OPTIONAL }
/// ```
///
/// In RPKI signed objects, a set is limited to exactly one identifer. The
/// allowed algorithms are limited, too. In particular, [RFC 7935] only
/// allows SHA-256. Its algorithm identifier is defined in [RFC 4055]. The
/// _parameters_ field may either be absent or `NULL`.
///
/// The functions and methods in this section allow decoding and encoding
/// such values.
///
/// [RFC 4055]: https://tools.ietf.org/html/rfc4055
/// [RFC 7935]: https://tools.ietf.org/html/rfc7935
impl DigestAlgorithm {
    /// Takes and returns a single digest algorithm identifier.
    ///
    /// Returns a malformed error if the algorithm isn’t one of the allowed
    /// algorithms or if the value isn’t correctly encoded.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Takes and returns an optional digest algorithm identifier.
    ///
    /// Returns `Ok(None)` if the next value isn’t a sequence.
    /// Returns a malformed error if the sequence isn’t a correctly encoded
    /// algorithm identifier or if algorithm isn’t one of the allowed
    /// algorithms.
    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_sequence(Self::from_constructed)
    }

    /// Takes and returns a set of digest algorithm identifiers.
    ///
    /// The set must contain exactly one identifier as required everywhere for
    /// RPKI. If it contains more than one or identifiers that are not
    /// allowed, a malformed error is returned.
    pub fn take_set_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_set(Self::take_from)
    }

    /// Parses the algorithm identifier from the contents of its sequence.
    fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        oid::SHA256.skip_if(cons)?;
        cons.take_opt_null()?;
        Ok(DigestAlgorithm::default())
    }

    /// Parses a SET OF DigestAlgorithmIdentifiers.
    ///
    /// This is used in the digestAlgorithms field of the SignedData
    /// container. It provides all the digest algorithms used later on, so
    /// that the data can be read over. We don’t really need this, so this
    /// function returns `()` on success.
    ///
    /// Section 2.1.2. of RFC 6488 requires there to be exactly one element
    /// chosen from the allowed values.
    pub fn skip_set<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(), S::Err> {
        cons.take_constructed_if(Tag::SET, |cons| {
            while let Some(_) = Self::take_opt_from(cons)? { }
            Ok(())
        })
    }

    /// Takes a single algorithm object identifier from a constructed value.
    pub fn take_oid_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
    ) -> Result<Self, S::Err> {
        oid::SHA256.skip_if(cons)?;
        Ok(Self::default())
    }

    /// Provides an encoder for a single algorithm identifier.
    pub fn encode(self) -> impl encode::Values {
        encode::sequence((
            oid::SHA256.encode(),
            ().encode(),
        ))
    }

    /// Provides an encoder for a indentifer as the sole value of a set.
    pub fn encode_set(self) -> impl encode::Values {
        encode::set(
            self.encode()
        )
    }

    /// Provides an encoder for just the object identifier of the algorithm.
    pub fn encode_oid(self) -> impl encode::Values {
        oid::SHA256.encode()
    }
}


//------------ Sha1 ----------------------------------------------------------

pub fn sha1_digest(data: &[u8]) -> Digest {
    digest::digest(&digest::SHA1, data)
}

pub fn start_sha1() -> Context {
    Context(digest::Context::new(&digest::SHA1))
}


//------------ Context -------------------------------------------------------

#[derive(Clone)]
pub struct Context(digest::Context);

impl Context {
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    pub fn finish(self) -> Digest {
        self.0.finish()
    }
}

impl io::Write for Context {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

