//! Types and parameters of keys.

use bcder::{decode, encode};
use bcder::{BitString, Mode};
use bcder::encode::PrimitiveContent;
use ring::{digest, signature};
use ring::error::Unspecified;
use untrusted::Input;
use crate::oid;
use super::signature::Signature;


//------------ PublicKeyFormat -----------------------------------------------

/// The formats of public keys used by RPKI.
///
/// Currently, RPKI uses exactly one type of public keys, RSA keys with a size
/// of 2048 bits. However, as that might change in the future, we are not
/// hard-coding that format but rather use this type – which for the time
/// being is zero-sized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyFormat;

/// # ASN.1 Algorithm Identifiers
///
/// The format of the public key is identified in certificates through a
/// algorithm identifier defined with this ASN.1:
///
/// ```txt
/// AlgorithmIdentifier ::= SEQUENCE {
///      algorithm          OBJECT IDENTIFIER,
///      parameters         ANY DEFINED BY algorithm OPTIONAL }
/// ```
///
/// Right now, the object identifier needs to be that of `rsaEncryption`
/// defined by [RFC 4055] and the parameters must be present and NULL.
/// Then parsing, we generously also allow it to be absent altogether.
///
/// The functions and methods in this section allow decoding and encoding of
/// these identifiers.
///
/// [RFC 4055]: https://tools.ietf.org/html/rfc4055
impl PublicKeyFormat{
    /// Takes and returns a algorithm identifier.
    ///
    /// Returns a malformed error if the algorithm isn’t one of the allowed
    /// algorithms or if the value isn’t correctly encoded.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the algorithm identifier from the contents of its sequence.
    fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        oid::RSA_ENCRYPTION.skip_if(cons)?;
        cons.take_opt_null()?;
        Ok(PublicKeyFormat)
    }

    /// Provides an encoder for the algorihm identifier.
    pub fn encode(&self) -> impl encode::Values {
        encode::sequence((
            oid::RSA_ENCRYPTION.encode(),
            ().encode(),
        ))
    }
}


//------------ PublicKey -----------------------------------------------------

/// A public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    algorithm: PublicKeyFormat,
    bits: BitString,
}


impl PublicKey {
    pub fn algorithm(&self) -> &PublicKeyFormat {
        &self.algorithm
    }

    pub fn bits(&self) -> &[u8] {
        self.bits.octet_slice().unwrap()
    }

    pub fn key_identifier(&self) -> digest::Digest {
        digest::digest(
            &digest::SHA1,
            self.bits.octet_slice().unwrap()
        )
    }

    /// Verifies a signature using this public key.
    pub fn verify(
        &self, message: &[u8], signature: &Signature
    ) -> Result<(), VerificationError> {
        signature::verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            Input::from(self.bits()),
            Input::from(message),
            Input::from(signature.value().as_ref())
        ).map_err(Into::into)
    }
}


/// # As `SubjectPublicKeyInfo`
///
/// Public keys are included in X.509 certificates as `SubjectPublicKeyInfo`
/// structures. As these are contain the same information as `PublicKey`,
/// it can be decoded from and encoded to such sequences.
impl PublicKey {
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            Ok(PublicKey {
                algorithm: PublicKeyFormat::take_from(cons)?,
                bits: BitString::take_from(cons)?
            })
        })
    }

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            self.algorithm.encode(),
            self.bits.encode()
        ))
    }
}


//------------ VerificationError ---------------------------------------------

/// An error happened while verifying a signature.
///
/// No further information is provided. This is on purpose.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="signature verification failed")]
pub struct VerificationError;

impl From<Unspecified> for VerificationError {
    fn from(_: Unspecified) -> Self {
        VerificationError
    }
}

