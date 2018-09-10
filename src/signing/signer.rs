//! Support for generating keys, and using them to sign things

use cert::SubjectPublicKeyInfo;
use bytes::Bytes;
use failure::Fail;
use signing::PublicKeyAlgorithm;


//------------ Signer --------------------------------------------------------

pub trait Signer {

    /// Creates a new key and returns an identifier.
    fn create_key(
        &mut self,
        algorithm: &PublicKeyAlgorithm
    ) -> Result<KeyId, CreateKeyError>;

    /// Gets the key info for the identifier.
    fn get_key_info(
        &self,
        id: &KeyId
    ) -> Result<SubjectPublicKeyInfo, KeyUseError>;

    /// Destroys the key.
    fn destroy_key(
        &mut self,
        id: &KeyId
    ) -> Result<(), KeyUseError>;

    /// Signs data
    fn sign<D: AsRef<[u8]>>(
        &self,
        id: &KeyId,
        data: &D
    ) -> Result<Signature, KeyUseError>;
}


//------------ KeyId ---------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(s: String) -> Self { KeyId(s) }
}


//------------ SignResult ----------------------------------------------------

pub struct Signature(Bytes);

impl Signature {
    pub fn new(bytes: Bytes) -> Self {
        Signature(bytes)
    }

    pub fn to_bytes(self) -> Bytes {
        self.0
    }
}


//------------ CreateKeyError ------------------------------------------------

#[derive(Debug)]
pub enum CreateKeyError {
    UnsupportedAlgorithm,
    Signer(Box<Fail>)
}

impl<F: Fail> From<F> for CreateKeyError {
    fn from(f: F) -> Self {
        CreateKeyError::Signer(Box::new(f))
    }
}


//------------ KeyUseError ---------------------------------------------------

#[derive(Debug)]
pub enum KeyUseError {
    KeyNotFound,
    Signer(Box<Fail>)
}

impl<F: Fail> From<F> for KeyUseError {
    fn from(f: F) -> Self {
        KeyUseError::Signer(Box::new(f))
    }
}
