//! Support for generating keys, and using them to sign things

use cert::SubjectPublicKeyInfo;


//------------ SigningKeyPair ------------------------------------------------

pub trait SigningKeyPair {
    fn subject_public_key_info(&self) -> SubjectPublicKeyInfo;
}
