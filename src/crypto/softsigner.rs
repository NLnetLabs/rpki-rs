//! A signer storing private keys in memory.

use std::io;
use std::sync::{Arc, RwLock};
use bcder::decode::IntoSource;
use aws_lc_rs::{rand, rsa, signature};
use aws_lc_rs::rand::SecureRandom;
use aws_lc_rs::signature::KeyPair as _;
use super::keys::{PublicKey, PublicKeyFormat};
use super::signer::{KeyError, Signer, SigningAlgorithm, SigningError};
use super::signature::{SignatureAlgorithm, Signature};


//------------ SoftSigner -------------------------------------------------

/// A signer keeping keys in memory.
pub struct SoftSigner {
    keys: RwLock<Vec<Option<Arc<KeyPair>>>>,
    rng: rand::SystemRandom,
}

impl SoftSigner {
    pub fn new() -> SoftSigner {
        SoftSigner {
            keys: Default::default(),
            rng: rand::SystemRandom::new(),
        }
    }

    pub fn key_from_der(&self, der: &[u8]) -> Result<KeyId, io::Error> {
        Ok(self.insert_key(KeyPair::from_der(der)?))
    }

    pub fn key_from_pem(&self, pem: &[u8]) -> Result<KeyId, io::Error> {
        Ok(self.insert_key(KeyPair::from_pem(pem)?))
    }

    fn insert_key(&self, key: KeyPair) -> KeyId {
        let mut keys = self.keys.write().unwrap();
        let res = keys.len();
        keys.push(Some(key.into()));
        KeyId(res)
    }

    fn get_key(&self, id: KeyId) -> Result<Arc<KeyPair>, KeyError<io::Error>> {
        self.keys.read().unwrap().get(id.0).and_then(|key| {
            key.as_ref().cloned()
        }).ok_or(KeyError::KeyNotFound)
    }

    fn delete_key(&self, key: KeyId) -> Result<(), KeyError<io::Error>> {
        let mut keys = self.keys.write().unwrap();
        let key = keys.get_mut(key.0);
        match key {
            Some(key) => {
                if key.is_some() {
                    *key = None;
                    Ok(())
                }
                else {
                    Err(KeyError::KeyNotFound)
                }
            }
            None => Err(KeyError::KeyNotFound)
        }
    }
}

impl Signer for SoftSigner {
    type KeyId = KeyId;
    type Error = io::Error;

    fn create_key(
        &self, algorithm: PublicKeyFormat
    ) -> Result<Self::KeyId, Self::Error> {
        Ok(self.insert_key(KeyPair::new(algorithm)?))
    }

    fn get_key_info(
        &self,
        id: &Self::KeyId
    ) -> Result<PublicKey, KeyError<Self::Error>> {
        self.get_key(*id)?.get_key_info().map_err(KeyError::Signer)
    }

    fn destroy_key(
        &self, key: &Self::KeyId
    ) -> Result<(), KeyError<Self::Error>> {
        self.delete_key(*key)
    }

    fn sign<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        &self,
        key: &Self::KeyId,
        algorithm: Alg,
        data: &D
    ) -> Result<Signature<Alg>, SigningError<Self::Error>> {
        self.get_key(*key)?.sign(
            algorithm, data.as_ref(), &self.rng,
        ).map_err(Into::into)
    }

    fn sign_one_off<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: Alg,
        data: &D
    ) -> Result<(Signature<Alg>, PublicKey), Self::Error> {
        let key = KeyPair::new(algorithm.public_key_format())?;
        let info = key.get_key_info()?;
        let sig = key.sign(algorithm, data.as_ref(), &self.rng)?;
        Ok((sig, info))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        self.rng.fill(target).map_err(|_|
            io::Error::other("rng error")
        )
    }
}


impl Default for SoftSigner {
    fn default() -> Self {
        Self::new()
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
struct KeyPair(rsa::KeyPair);

impl KeyPair {
    fn new(algorithm: PublicKeyFormat) -> Result<Self, io::Error> {
        if algorithm != PublicKeyFormat::Rsa {
            return Err(io::Error::other("invalid algorithm"));
        }

        rsa::KeyPair::generate(
            rsa::KeySize::Rsa2048
        ).map(Self).map_err(io::Error::other)
    }

    fn from_der(der: &[u8]) -> Result<Self, io::Error> {
        let res = rsa::KeyPair::from_der(der).map_err(io::Error::other)?;
        if res.public_modulus_len() != 2048 / 8 {
            return Err(io::Error::other(
                format!(
                    "invalid key length {}", res.public_modulus_len() * 8
                )
            ))
        }
        Ok(KeyPair(res))
    }

    fn from_pem(pem: &[u8]) -> Result<Self, io::Error> {
        let res = rsa::KeyPair::from_pkcs8(pem).map_err(io::Error::other)?;
        if res.public_modulus_len() != 2048 / 8 {
            return Err(io::Error::other(
                format!(
                    "invalid key length {}", res.public_modulus_len() * 8
                )
            ))
        }
        Ok(KeyPair(res))
    }

    fn get_key_info(&self) -> Result<PublicKey, io::Error> {
        PublicKey::decode(
            self.0.public_key().as_ref().into_source()
        ).map_err(io::Error::other)
    }

    fn sign<Alg: SignatureAlgorithm>(
        &self,
        algorithm: Alg,
        data: &[u8],
        rng: &dyn rand::SecureRandom,
    ) -> Result<Signature<Alg>, io::Error> {
        if !matches!(
            algorithm.signing_algorithm(), SigningAlgorithm::RsaSha256
        ) {
            return Err(io::Error::other(
                "invalid algorithm"
            ));
        }

        let mut signature = vec![0; self.0.public_modulus_len()];
        self.0.sign(
            &signature::RSA_PKCS1_SHA256, rng, data, &mut signature
        ).map_err(io::Error::other)?;
        Ok(Signature::new(algorithm, signature.into()))
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::crypto::signature::RpkiSignatureAlgorithm;

    #[test]
    fn info_sign_delete() {
        let s = SoftSigner::new();
        let ki = s.create_key(PublicKeyFormat::Rsa).unwrap();
        let data = b"foobar";
        let _ = s.get_key_info(&ki).unwrap();
        let _ = s.sign(&ki, RpkiSignatureAlgorithm::default(), data).unwrap();
        s.destroy_key(&ki).unwrap();
    }
    
    #[test]
    fn one_off() {
        let s = SoftSigner::new();
        s.sign_one_off(RpkiSignatureAlgorithm::default(), b"foobar").unwrap();
    }
}

