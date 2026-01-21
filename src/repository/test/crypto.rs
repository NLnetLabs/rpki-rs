//! Crypto infrastructure for testing.
//!
//! This module provides self-contained keys so you don’t have to pass
//! around both a signer and a key id.

use std::sync::Arc;
use crate::crypto::keys::{PublicKey, PublicKeyFormat};
use crate::crypto::signature::{RpkiSignature, RpkiSignatureAlgorithm};
use crate::crypto::signer::Signer;
use crate::crypto::softsigner::{KeyId, OpenSslSigner};


//------------ KeyRing ------------------------------------------------------

pub struct KeyRing {
    signer: Arc<OpenSslSigner>,
}

impl Default for KeyRing {
    fn default() -> Self {
        KeyRing {
            signer: Arc::new(OpenSslSigner::new())
        }
    }
}

impl KeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_rpki_key(&self) -> RpkiKey {
        RpkiKey {
            signer: self.signer.clone(),
            key_id: self.signer.create_key(PublicKeyFormat::Rsa).unwrap()
        }
    }
}


//----------- RsaKey --------------------------------------------------------

pub struct RpkiKey {
    signer: Arc<OpenSslSigner>,
    key_id: KeyId,
}

impl RpkiKey {
    pub fn key_info(&self) -> PublicKey {
        self.signer.get_key_info(&self.key_id).unwrap()
    }

    pub fn sign(
        &self, data: &impl AsRef<[u8]>) -> RpkiSignature {
        self.signer.sign(
            &self.key_id, RpkiSignatureAlgorithm::default(), data
        ).unwrap()
    }
}

