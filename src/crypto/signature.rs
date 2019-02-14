//! Signature algorithms and operations.

use bcder::{decode, encode};
use bcder::encode::PrimitiveContent;
use bcder::Oid;
use bytes::Bytes;
use crate::oid;
use super::keys::PublicKeyFormat;


//------------ SignatureAlgorithm --------------------------------------------

/// The signature algorihms used by RPKI.
///
/// These are the algorithms used for creating and verifying signatures. For
/// RPKI, [RFC 7935] allows only one algorithm, RSA PKCS #1 v1.5 with
/// SHA-256. Because of that, this type is currently a zero-sized struct.
/// Should additional algorithms ever be allowed, it will change into an
/// enum.
///
/// [RFC 7935]: https://tools.ietf.org/html/rfc7935
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SignatureAlgorithm;


impl SignatureAlgorithm {
    /// Returns the preferred public key format for this algorithm.
    pub fn public_key_format(self) -> PublicKeyFormat {
        PublicKeyFormat
    }
}


/// # ASN.1 Values
///
/// Signature algorithm identifiers appear in certificates and other objects
/// from [RFC 5280] (simply as algorithm identifiers) as well as in signed
/// objects.
///
/// ```txt
/// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
/// AlgorithmIdentifier          ::= SEQUENCE {
///      algorithm                   OBJECT IDENTIFIER,
///      parameters                  ANY DEFINED BY algorithm OPTIONAL }
/// ```
///
/// Currently, [RFC 7935] allows only one algorithm, but sadly it uses
/// different identifiers in different places. For X.509-related objects,
/// i.e., certificates, CRLs, and certification requests, this is
/// `sha256WithRSAEncryption` from [RFC 4055].  For signed objects, the
/// identifier must be `rsaEncryption` from [RFC 3370] for constructed
/// objects while both must be accepted when reading objects.
///
/// Because of these differences, you’ll find two sets of functions and
/// methods in this section. Those prefixed with `x509` deal with the
/// X.509-related identifiers while `cms_` is the prefix for signed objects.
///
/// The parameters field for the former identifier can be either NULL or
/// missing and must be NULL for the latter. We will, however, accept an
/// absent field for the latter as well. When constructing identifiers,
/// we will always include a parameters field and set it to NULL.
///
/// [RFC 3370]: https://tools.ietf.org/html/rfc3370
/// [RFC 4055]: https://tools.ietf.org/html/rfc4055
/// [RFC 7935]: https://tools.ietf.org/html/rfc7935
impl SignatureAlgorithm {
    /// Takes a signature algorithm identifier for X.509 objects.
    ///
    /// Returns a malformed error if the algorithm isn’t the allowed for RPKI
    /// or if it isn’t correctly encoded.
    pub fn x509_take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::x509_from_constructed)
    }

    /// Parses the algorithm identifier for X.509 objects.
    fn x509_from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        oid::SHA256_WITH_RSA_ENCRYPTION.skip_if(cons)?;
        cons.take_opt_null()?;
        Ok(SignatureAlgorithm)
    }

    /// Takes a signature algorithm identifier for CMS objects.
    ///
    /// Returns a malformed error if the algorithm isn’t the allowed for RPKI
    /// or if it isn’t correctly encoded.
    pub fn cms_take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::cms_from_constructed)
    }

    /// Parses the algorithm identifier for CMS objects.
    fn cms_from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let oid = Oid::take_from(cons)?;
        if oid != oid::RSA_ENCRYPTION && oid != oid::SHA256_WITH_RSA_ENCRYPTION
        {
            return Err(decode::Malformed.into())
        }
        cons.take_opt_null()?;
        Ok(SignatureAlgorithm)
    }

    /// Provides an encoder for X.509 objects.
    pub fn x509_encode(self) -> impl encode::Values {
        encode::sequence((
            oid::SHA256_WITH_RSA_ENCRYPTION.encode(),
            ().encode(),
        ))
    }

    /// Provides an encoder for CMS objects.
    pub fn cms_encode(self) -> impl encode::Values {
        encode::sequence((
            oid::RSA_ENCRYPTION.encode(),
            ().encode(),
        ))
    }
}


//------------ Signature -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct Signature {
    algorithm: SignatureAlgorithm,
    value: Bytes
}

impl Signature {
    pub fn new(algorithm: SignatureAlgorithm, value: Bytes) -> Self {
        Signature { algorithm, value }
    }

    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    pub fn value(&self) -> &Bytes {
        &self.value
    }

    pub fn unwrap(self) -> (SignatureAlgorithm, Bytes) {
        (self.algorithm, self.value)
    }
}

