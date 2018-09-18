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
    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        id: &KeyId,
        data: &D
    ) -> Result<Signature, KeyUseError>;

    /// Signs data using a one time use keypair
    ///
    /// Returns both the signature and the public key of the key pair,
    /// but will not store this key pair.
    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        data: &D
    ) -> Result<OneOffSignature, KeyUseError>;


}


//------------ KeyId ---------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(s: String) -> Self { KeyId(s) }
}


//------------ OneOffSignature -----------------------------------------------

pub struct OneOffSignature {
    key: SubjectPublicKeyInfo,
    signature: Signature
}

impl OneOffSignature {
    pub fn new(key: SubjectPublicKeyInfo, signature: Signature) -> Self {
        OneOffSignature{key, signature }
    }

    pub fn get_key_info(&self) -> &SubjectPublicKeyInfo {
        &self.key
    }

    pub fn get_signature(&self) -> &Signature {
        &self.signature
    }

    // Consumes this and returns the composite values.
    pub fn into_parts(self) -> (SubjectPublicKeyInfo, Signature) {
        (self.key, self.signature)
    }
}


//------------ Signature -----------------------------------------------------

pub struct Signature(Bytes);

impl Signature {
    pub fn new(bytes: Bytes) -> Self {
        Signature(bytes)
    }

    pub fn into_bytes(self) -> Bytes {
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
