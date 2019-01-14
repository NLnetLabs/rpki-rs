//! A signer atop the OpenSSL library.
//!
//! Because this adds a dependency to openssl libs this is disabled by
//! default and should only be used by implementations that need to use
//! software keys to sign things, such as an RPKI Certificate Authority or
//! Publication Server. In particular, this is not required when validating.

use openssl::rsa::Rsa;
use openssl::pkey::{PKey, Private};
use openssl::hash::MessageDigest;
use openssl::error::ErrorStack;
use slab::Slab;
use super::keys::{PublicKey, PublicKeyFormat};
use super::signature::{Signature, SignatureAlgorithm};
use super::signer::{Signer, SigningError};



//------------ OpenSslSigner -------------------------------------------------

/// An OpenSSL based signer.
///
/// Keeps the keys in memory (for now).
pub struct OpenSslSigner {
    keys: Slab<KeyPair>,
}

impl OpenSslSigner {
    pub fn new() -> OpenSslSigner {
        OpenSslSigner {
            keys: Slab::new()
        }
    }
}

impl Signer for OpenSslSigner {
    type KeyId = KeyId;
    type Error = ErrorStack;

    fn create_key(
        &mut self, algorithm: PublicKeyFormat
    ) -> Result<Self::KeyId, Self::Error> {
        Ok(KeyId(self.keys.insert(KeyPair::new(algorithm)?)))
    }

    fn get_key_info(
        &self,
        id: &Self::KeyId
    ) -> Result<Option<PublicKey>, Self::Error> {
        match self.keys.get(id.0) {
            Some(key) => Ok(Some(key.get_key_info()?)),
            None => Ok(None)
        }
    }

    fn destroy_key(
        &mut self, key: &Self::KeyId
    ) -> Result<bool, Self::Error> {
        if self.keys.contains(key.0) {
            self.keys.remove(key.0);
            Ok(true)
        }
        else {
            Ok(false)
        }
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key: &Self::KeyId,
        algorithm: SignatureAlgorithm,
        data: &D
    ) -> Result<Signature, SigningError<Self::Error>> {
        match self.keys.get(key.0) {
            Some(key) => key.sign(algorithm, data.as_ref()),
            None => Err(SigningError::KeyNotFound)
        }
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D
    ) -> Result<(Signature, PublicKey), Self::Error> {
        let key = KeyPair::new(algorithm.public_key_format())?;
        let info = key.get_key_info()?;
        let sig = key.sign(algorithm, data.as_ref()).map_err(|err| {
            match err {
                SigningError::Signer(err) => err,
                _ => unreachable!()
            }
        })?;
        Ok((sig, info))
    }
}


//------------ KeyId ---------------------------------------------------------

/// This signer’s key identifier.
//
//  We wrap this in a newtype so that people won’t start mucking about with
//  the integers.
#[derive(Clone, Copy, Debug)]
pub struct KeyId(usize);


//------------ KeyPair -------------------------------------------------------

/// A key pair kept by the signer.
struct KeyPair(PKey<Private>);

impl KeyPair {
    fn new(_algorithm: PublicKeyFormat) -> Result<Self, ErrorStack> {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        Ok(KeyPair(pkey))
    }

    fn get_key_info(&self) -> Result<PublicKey, ErrorStack>
    {
        // Issues unwrapping this indicate a bug in the openssl
        // library. So, there is no way to recover.
        let der = self.0.rsa().unwrap().public_key_to_der()?;
        Ok(PublicKey::decode(der.as_ref()).unwrap())
    }

    fn sign(
        &self,
        _algorithm: SignatureAlgorithm,
        data: &[u8]
    ) -> Result<Signature, SigningError<ErrorStack>> {
        let mut signer = ::openssl::sign::Signer::new(
            MessageDigest::sha256(), &self.0
        )?;
        signer.update(data.as_ref())?;
        Ok(Signature::new(
            SignatureAlgorithm,
            signer.sign_to_vec()?.into()
        ))
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn info_sign_delete() {
        let mut s = OpenSslSigner::new();
        let ki = s.create_key(PublicKeyFormat).unwrap();
        let data = b"foobar";
        let info = s.get_key_info(&ki).unwrap();
        let sig = s.sign(&ki, SignatureAlgorithm, data).unwrap();
        s.destroy_key(&ki).unwrap();
    }
    
    #[test]
    fn one_off() {
        let s = OpenSslSigner::new();
        s.sign_one_off(SignatureAlgorithm, b"foobar").unwrap();
    }
}

