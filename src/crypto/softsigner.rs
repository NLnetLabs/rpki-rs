//! A signer atop the OpenSSL library.
//!
//! Because this adds a dependency to openssl libs this is disabled by
//! default and should only be used by implementations that need to use
//! software keys to sign things, such as an RPKI Certificate Authority or
//! Publication Server. In particular, this is not required when validating.

use std::io;
use std::sync::{Arc, RwLock};
use bcder::decode::IntoSource;
use openssl::rsa::Rsa;
use openssl::pkey::{PKey, Private};
use openssl::hash::MessageDigest;
use ring::rand;
use ring::rand::SecureRandom;
use super::keys::{PublicKey, PublicKeyFormat};
use super::signer::{KeyError, Signer, SigningAlgorithm, SigningError};
use super::signature::{SignatureAlgorithm, Signature};



//------------ OpenSslSigner -------------------------------------------------

/// An OpenSSL based signer.
///
/// Keeps the keys in memory (for now).
pub struct OpenSslSigner {
    keys: RwLock<Vec<Option<Arc<KeyPair>>>>,
    rng: rand::SystemRandom,
}

impl OpenSslSigner {
    pub fn new() -> OpenSslSigner {
        OpenSslSigner {
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

#[async_trait::async_trait]
impl Signer for OpenSslSigner {
    type KeyId = KeyId;
    type Error = io::Error;

    async fn create_key(
        &self, algorithm: PublicKeyFormat
    ) -> Result<Self::KeyId, Self::Error> {
        Ok(self.insert_key(KeyPair::new(algorithm)?))
    }

    async fn get_key_info(
        &self,
        id: &Self::KeyId
    ) -> Result<PublicKey, KeyError<Self::Error>> {
        self.get_key(*id)?.get_key_info().map_err(KeyError::Signer)
    }

    async fn destroy_key(
        &self, key: &Self::KeyId
    ) -> Result<(), KeyError<Self::Error>> {
        self.delete_key(*key)
    }

    async fn sign<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized + Sync>(
        &self,
        key: &Self::KeyId,
        algorithm: Alg,
        data: &D
    ) -> Result<Signature<Alg>, SigningError<Self::Error>> {
        self.get_key(*key)?.sign(algorithm, data.as_ref()).map_err(Into::into)
    }

    async fn sign_one_off<
        Alg: SignatureAlgorithm,
        D: AsRef<[u8]> + ?Sized + Sync
        >(
        &self,
        algorithm: Alg,
        data: &D
    ) -> Result<(Signature<Alg>, PublicKey), Self::Error> {
        let key = KeyPair::new(algorithm.public_key_format())?;
        let info = key.get_key_info()?;
        let sig = key.sign(algorithm, data.as_ref())?;
        Ok((sig, info))
    }

    async fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        self.rng.fill(target).map_err(|_|
            io::Error::new(io::ErrorKind::Other, "rng error")
        )
    }
}


impl Default for OpenSslSigner {
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
struct KeyPair(PKey<Private>);

impl KeyPair {
    fn new(algorithm: PublicKeyFormat) -> Result<Self, io::Error> {
        if algorithm != PublicKeyFormat::Rsa {
            return Err(io::Error::new(
                io::ErrorKind::Other, "invalid algorithm"
            ));
        }
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        Ok(KeyPair(pkey))
    }

    fn from_der(der: &[u8]) -> Result<Self, io::Error> {
        let res = PKey::private_key_from_der(der)?;
        if res.bits() != 2048 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("invalid key length {}", res.bits())
            ))
        }
        Ok(KeyPair(res))
    }

    fn from_pem(pem: &[u8]) -> Result<Self, io::Error> {
        let res = PKey::private_key_from_pem(pem)?;
        if res.bits() != 2048 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("invalid key length {}", res.bits())
            ))
        }
        Ok(KeyPair(res))
    }

    fn get_key_info(&self) -> Result<PublicKey, io::Error>
    {
        // Issues unwrapping this indicate a bug in the openssl
        // library. So, there is no way to recover.
        let der = self.0.rsa().unwrap().public_key_to_der()?;
        Ok(PublicKey::decode(der.as_slice().into_source()).unwrap())
    }

    fn sign<Alg: SignatureAlgorithm>(
        &self,
        algorithm: Alg,
        data: &[u8]
    ) -> Result<Signature<Alg>, io::Error> {
        if !matches!(
            algorithm.signing_algorithm(), SigningAlgorithm::RsaSha256
        ) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "invalid algorithm"
            ));
        }
        let mut signer = ::openssl::sign::Signer::new(
            MessageDigest::sha256(), &self.0
        )?;
        signer.update(data)?;
        Ok(Signature::new(algorithm, signer.sign_to_vec()?.into()))
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::crypto::signature::RpkiSignatureAlgorithm;

    #[tokio::test]
    async fn info_sign_delete() {
        let s = OpenSslSigner::new();
        let ki = s.create_key(PublicKeyFormat::Rsa).await.unwrap();
        let data = b"foobar";
        s.get_key_info(&ki).await.unwrap();
        s.sign(&ki, RpkiSignatureAlgorithm::default(), data).await.unwrap();
        s.destroy_key(&ki).await.unwrap();
    }
    
    #[tokio::test]
    async fn one_off() {
        let s = OpenSslSigner::new();
        s.sign_one_off(
            RpkiSignatureAlgorithm::default(),
            b"foobar"
        ).await.unwrap();
    }
}

