//! Support for generating keys, and using them to sign things

use cert::SubjectPublicKeyInfo;


//------------ Signer --------------------------------------------------------

pub trait Signer {

    type KeyId;

    /// Creates a new key and returns an identifier.
    fn create_key(&mut self) -> Result<Self::KeyId, SignerError>;

    /// Gets the key info for the identifier.
    fn get_key_info(&self, id: &Self::KeyId)
        -> Result<SubjectPublicKeyInfo, SignerError>;

    /// Destroys the key, and its identifier.
    fn destroy_key(&mut self, id: Self::KeyId)
        -> Result<(), SignerError>;
}


//------------ SignerError ---------------------------------------------------

#[derive(Debug, Fail)]
pub enum SignerError {
    #[fail(display = "Key does not exist")]
    KeyNotFound,
}

