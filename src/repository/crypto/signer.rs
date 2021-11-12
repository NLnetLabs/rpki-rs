//! A generic interface to a signer.

use std::fmt;
use super::keys::{PublicKey, PublicKeyFormat};
use super::signature::{Signature, SignatureAlgorithm};


//------------ Experimental Reversed Signer Traits ---------------------------
//
// These will make it possible to have async signers. Instead of implementing
// a signer, we define the logic for signing something. Each signer can then
// implement a method to sign with a key or one off.


/// A type that can be signed but needs to know about the signing key.
///
/// A type implementing this trait will have to be signed in two steps. First,
/// the key is presented to the object via [`SignWithKey::set_key`]. This
/// step returns a transitional value that knows about the signing key and
/// can now be signed via the [`Sign`] trait.
pub trait SignWithKey {
    /// The transitional type for actual signing.
    type Sign: Sign + Sized;

    fn set_key(
        self, public_key: &PublicKey
    ) -> Result<Self::Sign, AlgorithmError>;
}

/// A type that can be signed.
///
/// The type provides access to the data to be signed via
/// [`signed_data`][Self::signed_data]. Once the signer has finished its job,
/// it can provide the signature to the value through [`sign`][Self::sign],
/// which will apply the signature and return the final, signed value.
pub trait Sign {
    /// The type of a final, signed value.
    type Final: Sized;

    /// Returns a reference to the data to be signed.
    fn signed_data(&self) -> &[u8];

    /// Applies the signature and returns the final, signed value.
    fn sign(self, signature: Signature) -> Self::Final;
}

/// A key of the given algorithm cannot be used to sign this object.
#[derive(Clone, Copy, Debug)]
pub struct AlgorithmError;

impl fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid algorithm")
    }
}

impl std::error::Error for AlgorithmError { }


//------------ Signer --------------------------------------------------------

/// A type that allow creating signatures.
pub trait Signer {
    /// The type used for identifying keys.
    type KeyId;

    /// An operational error happened in the signer.
    type Error: fmt::Debug + fmt::Display;

    /// Creates a new key and returns an identifier.
    fn create_key(
        &self,
        algorithm: PublicKeyFormat
    ) -> Result<Self::KeyId, Self::Error>;

    /// Returns the public key information for the given key.
    ///
    /// If the key identified by `key` does not exist, returns `None`.
    fn get_key_info(
        &self,
        key: &Self::KeyId
    ) -> Result<PublicKey, KeyError<Self::Error>>;

    /// Destroys a key.
    ///
    /// Returns whether the key identified by `key` existed.
    fn destroy_key(
        &self,
        key: &Self::KeyId
    ) -> Result<(), KeyError<Self::Error>>;

    /// Signs data.
    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key: &Self::KeyId,
        algorithm: SignatureAlgorithm,
        data: &D
    ) -> Result<Signature, SigningError<Self::Error>>;

    /// Signs data using a one time use keypair.
    ///
    /// Returns both the signature and the public key of the key pair,
    /// but will not store this key pair.
    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D
    ) -> Result<(Signature, PublicKey), Self::Error>;

    /// Creates random data.
    ///
    /// The method fills the provide bytes slice with random data.
    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error>;
}


//------------ KeyError ------------------------------------------------------

#[derive(Clone, Debug)]
pub enum KeyError<S> {
    /// A key with the given key ID doesn’t exist.
    KeyNotFound,

    /// An error happened during signing.
    Signer(S)
}

impl<S> From<S> for KeyError<S> {
    fn from(err: S) -> Self {
        KeyError::Signer(err)
    }
}

impl<S: fmt::Display> fmt::Display for KeyError<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::KeyError::*;

        match *self {
            KeyNotFound => write!(f, "key not found"),
            Signer(ref s) => s.fmt(f)
        }
    }
}


//------------ SigningError --------------------------------------------------

#[derive(Clone, Debug)]
pub enum SigningError<S> {
    /// A key with the given key ID doesn’t exist.
    KeyNotFound,

    /// The key cannot be used with the algorithm.
    IncompatibleKey,

    /// An error happened during signing.
    Signer(S)
}

impl<S> From<S> for SigningError<S> {
    fn from(err: S) -> Self {
        SigningError::Signer(err)
    }
}

impl<S> From<KeyError<S>> for SigningError<S> {
    fn from(err: KeyError<S>) -> Self {
        match err {
            KeyError::KeyNotFound => SigningError::KeyNotFound,
            KeyError::Signer(err) => SigningError::Signer(err)
        }
    }
}

impl<S: fmt::Display> fmt::Display for SigningError<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SigningError::*;

        match *self {
            KeyNotFound => write!(f, "key not found"),
            IncompatibleKey => write!(f, "key not compatible with algorithm"),
            Signer(ref s) => s.fmt(f)
        }
    }
}

