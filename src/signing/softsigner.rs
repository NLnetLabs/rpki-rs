//! Support using openssl to generate keys and sign things.
//!
//! Because this adds a dependency to openssl libs this is disabled by
//! default and should only be used by implementations that need to use
//! software keys to sign things, such as an RPKI Certificate Authority or
//! Publication Server. In particular, this is not required when validating.

use std::collections::HashMap;
use bytes::Bytes;
use cert::SubjectPublicKeyInfo;
use hex;
use super::KEY_SIZE;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use signing::signer::Signer;
use signing::signer::SignerError;


//------------ OpenSslSigner -------------------------------------------------

/// An openssl based signer.
///
/// Keeps the keys in memory (for now).
pub struct OpenSslSigner {
    keys: HashMap<String, OpenSslKeyPair>
}

impl OpenSslSigner {
    pub fn new() -> OpenSslSigner {
        OpenSslSigner {keys: HashMap::new()}
    }
}

impl Signer for OpenSslSigner {

    type KeyId = String;

    fn create_key(&mut self) -> Result<Self::KeyId, SignerError> {
        let kp = OpenSslKeyPair::new();
        let info = kp.subject_public_key_info().key_identifier();
        let enc = hex::encode(&info);
        let ret = enc.clone();

        self.keys.entry(enc).or_insert(kp);
        Ok(ret)
    }

    fn get_key_info(&self, id: &Self::KeyId)
        -> Result<SubjectPublicKeyInfo, SignerError>
    {
        match self.keys.get(id) {
            Some(k) => Ok(k.subject_public_key_info()),
            None => Err(SignerError::KeyNotFound)
        }
    }

    fn destroy_key(&mut self, id: Self::KeyId) -> Result<(), SignerError> {
        match &self.keys.remove(&id) {
            Some(_) => Ok(()),
            None => Err(SignerError::KeyNotFound)
        }
    }
}


//------------ OpenSslKeyPair ------------------------------------------------

/// An openssl based RSA key pair
pub struct OpenSslKeyPair {
    private: Rsa<Private>
}

impl OpenSslKeyPair {
    fn new() -> OpenSslKeyPair {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let private = Rsa::generate(KEY_SIZE).unwrap();
        OpenSslKeyPair{ private }
    }

    fn subject_public_key_info(&self) -> SubjectPublicKeyInfo {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let mut b = Bytes::from(self.private.public_key_to_der().unwrap());
        SubjectPublicKeyInfo::decode(&mut b).unwrap()
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn should_return_subject_public_key_info() {
        let mut s = OpenSslSigner::new();
        let ki = s.create_key().unwrap();
        s.get_key_info(&ki).unwrap();
        s.destroy_key(ki).unwrap();
    }
}
