//! A generic interface to a signer.

use std::fmt;
use super::keys::{PublicKey, PublicKeyFormat};
use super::signature::{Signature, SignatureAlgorithm};


//------------ Signer --------------------------------------------------------

/// A type that allow creating signatures.
pub trait Signer {
    /// The type used for identifying keys.
    type KeyId;

    /// An operational error happened in the signer.
    type Error: fmt::Debug + fmt::Display;

    /// Creates a new key and returns an identifier.
    fn create_key(
        &mut self,
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
        &mut self,
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

