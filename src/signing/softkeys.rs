//! Support using openssl to generate keys and sign things.
//!
//! Because this adds a dependency to openssl libs this is disabled by
//! default and should only be used by implementations that need to use
//! software keys to sign things, such as an RPKI Certificate Authority or
//! Publication Server. In particular, this is not required when validating.

use bytes::Bytes;
use cert::SubjectPublicKeyInfo;
use super::KEY_SIZE;
use super::keys::SigningKeyPair;
use openssl::pkey::Private;
use openssl::rsa::Rsa;

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

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn should_return_subject_public_key_info() {
        let kp = OpenSslKeyPair::new();
        kp.subject_public_key_info();
    }
}
