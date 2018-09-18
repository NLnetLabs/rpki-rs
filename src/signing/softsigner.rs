//! Support using openssl to generate keys and sign things.
//!
//! Because this adds a dependency to openssl libs this is disabled by
//! default and should only be used by implementations that need to use
//! software keys to sign things, such as an RPKI Certificate Authority or
//! Publication Server. In particular, this is not required when validating.

// XXX TODO Check security of keys in memory

use std::collections::HashMap;
use ber::decode;
use bytes::Bytes;
use cert::SubjectPublicKeyInfo;
use hex;
use signing::KEY_SIZE;
use signing::PublicKeyAlgorithm;
use signing::signer::{
    CreateKeyError,
    KeyId,
    KeyUseError,
    Signature,
    Signer};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::pkey::PKeyRef;
use openssl::hash::MessageDigest;
use openssl::error::ErrorStack;
use openssl::pkey::Private;
use signing::signer::OneOffSignature;


//------------ OpenSslSigner -------------------------------------------------

/// An openssl based signer.
///
/// Keeps the keys in memory (for now).
pub struct OpenSslSigner {
    keys: HashMap<KeyId, OpenSslKeyPair>
}

impl OpenSslSigner {
    pub fn new() -> OpenSslSigner {
        OpenSslSigner {keys: HashMap::new()}
    }
}

impl OpenSslSigner {

    fn sign_with_key<D: AsRef<[u8]> + ?Sized>(
        pkey: &PKeyRef<Private>,
        data: &D
    ) -> Result<Signature, KeyUseError>
    {
        let mut signer = ::openssl::sign::Signer::new(
            MessageDigest::sha256(),
            pkey
        )?;
        signer.update(data.as_ref())?;

        Ok(Signature::new(Bytes::from(signer.sign_to_vec()?)))
    }

}

impl Signer for OpenSslSigner {

    fn create_key(
        &mut self,
        algorithm: &PublicKeyAlgorithm
    ) -> Result<KeyId, CreateKeyError> {

        if *algorithm != PublicKeyAlgorithm::RsaEncryption {
            return Err(CreateKeyError::UnsupportedAlgorithm)
        }

        let kp = OpenSslKeyPair::new()?;
        let info = kp.subject_public_key_info()?.key_identifier();

        let enc = hex::encode(&info);
        let ret = enc.clone();

        self.keys.entry(KeyId::new(enc)).or_insert(kp);
        Ok(KeyId::new(ret))
    }

    fn get_key_info(&self, id: &KeyId)
        -> Result<SubjectPublicKeyInfo, KeyUseError>
    {
        match self.keys.get(id) {
            Some(k) => Ok(k.subject_public_key_info()?),
            None => Err(KeyUseError::KeyNotFound)
        }
    }

    fn destroy_key(&mut self, id: &KeyId) -> Result<(), KeyUseError> {
        match &self.keys.remove(id) {
            Some(_) => Ok(()),
            None => Err(KeyUseError::KeyNotFound)
        }
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        id: &KeyId,
        data: &D
    ) -> Result<Signature, KeyUseError> {

        match self.keys.get(id) {
            None => Err(KeyUseError::KeyNotFound),
            Some(k) => {
                match self.get_key_info(id)?.algorithm() {
                    PublicKeyAlgorithm::RsaEncryption => {
                        Self::sign_with_key(k.pkey.as_ref(), data)
                    }
                }
            }
        }
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        data: &D
    ) -> Result<OneOffSignature, KeyUseError> {
        let kp = OpenSslKeyPair::new()?;

        let signature = Self::sign_with_key(
            kp.pkey.as_ref(),
            data
        )?;

        let key = kp.subject_public_key_info()?;

        Ok(OneOffSignature::new(key, signature))
    }
}


//------------ OpenSslKeyPair ------------------------------------------------

/// An openssl based RSA key pair
pub struct OpenSslKeyPair {
    pkey: PKey<Private>
}

impl OpenSslKeyPair {
    fn new() -> Result<OpenSslKeyPair, OpenSslKeyError> {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let rsa = Rsa::generate(KEY_SIZE)?;
        let pkey = PKey::from_rsa(rsa)?;
        Ok(OpenSslKeyPair{ pkey })
    }

    fn subject_public_key_info(&self)
        -> Result<SubjectPublicKeyInfo, OpenSslKeyError>
    {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let mut b = Bytes::from(self.pkey.rsa().unwrap().public_key_to_der()?);
        Ok(SubjectPublicKeyInfo::decode(&mut b)?)
    }
}


//------------ OpenSslKeyError -----------------------------------------------

#[derive(Debug, Fail)]
pub enum OpenSslKeyError {

    #[fail(display = "OpenSsl Error: {}", _0)]
    OpenSslError(ErrorStack),

    #[fail(display = "Could not decode public key info: {}", _0)]
    DecodeError(decode::Error)
}

impl From<ErrorStack> for OpenSslKeyError {
    fn from(e: ErrorStack) -> Self {
        OpenSslKeyError::OpenSslError(e)
    }
}

impl From<decode::Error> for OpenSslKeyError {
    fn from(e: decode::Error) -> Self {
        OpenSslKeyError::DecodeError(e)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn should_return_subject_public_key_info() {
        let mut s = OpenSslSigner::new();
        let ki = s.create_key(&PublicKeyAlgorithm::RsaEncryption).unwrap();
        s.get_key_info(&ki).unwrap();
        s.destroy_key(&ki).unwrap();
    }
}
