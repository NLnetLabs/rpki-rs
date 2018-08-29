//! Support for generating keys, and using them to sign things

use cert::SubjectPublicKeyInfo;
use openssl::rsa::Rsa;
use openssl::pkey::Private;
use super::KEY_SIZE;
use bytes::Bytes;


//------------ SigningKeyPair ------------------------------------------------

pub trait SigningKeyPair {
    fn subject_public_key_info(&self) -> SubjectPublicKeyInfo;
}


//------------ OpenSslKeyPair ------------------------------------------------

/// An openssl based RSA key pair
pub struct OpenSslKeyPair {
    private: Rsa<Private>
}

impl SigningKeyPair for OpenSslKeyPair {

    fn subject_public_key_info(&self) -> SubjectPublicKeyInfo {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let mut b = Bytes::from(self.private.public_key_to_der().unwrap());
        SubjectPublicKeyInfo::decode(&mut b).unwrap()
    }

}

impl OpenSslKeyPair {

    pub fn new() -> OpenSslKeyPair {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let private = Rsa::generate(KEY_SIZE).unwrap();
        OpenSslKeyPair{ private }
    }

}

//------------ Tests ---------------------------------------------------------

// is pub so that we can use a parsed test IdCert for now for testing
#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn should_return_subject_public_key_info() {
        let kp = OpenSslKeyPair::new();
        kp.subject_public_key_info();
    }
}
