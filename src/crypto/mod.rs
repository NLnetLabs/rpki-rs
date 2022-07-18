//! Signing related implementations.
//!

#![cfg(feature = "crypto")]


pub use self::digest::{Digest, DigestAlgorithm};
pub use self::keys::{
    KeyIdentifier, PublicKey, PublicKeyFormat, SignatureVerificationError,
};
pub use self::signer::{Signer, SigningError};
pub use self::signature::{
    BgpsecSignatureAlgorithm, Signature, SignatureAlgorithm, RpkiSignature,
    RpkiSignatureAlgorithm,
};

pub mod digest;
pub mod keys;
pub mod signer;
pub mod signature;
#[cfg(feature = "softkeys")] pub mod softsigner;

