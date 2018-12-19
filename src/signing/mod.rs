//! Signing related implementations.
//!

use bcder::{encode, decode};
use bcder::{Oid, Tag};


//------------ RPKI Key Size -------------------------------------------------

pub const KEY_SIZE: u32 = 2048;


//------------ SignatureAlgorithm --------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    Sha256WithRsaEncryption
}

impl SignatureAlgorithm {
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let oid = Oid::take_from(cons)?;
        if oid != oid::RSA_ENCRYPTION &&
            oid != oid::SHA256_WITH_RSA_ENCRYPTION
            {
                return Err(decode::Malformed.into())
            }
        cons.take_opt_null()?;
        Ok(SignatureAlgorithm::Sha256WithRsaEncryption)
    }

    pub fn encode(&self) -> impl encode::Values {
        encode::sequence((
            oid::SHA256_WITH_RSA_ENCRYPTION.encode(),
            encode::PrimitiveContent::encode(&()),
        ))
    }
}


//------------ PublicKeyAlgorithm --------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicKeyAlgorithm {
    RsaEncryption,
}

impl PublicKeyAlgorithm {
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        oid::RSA_ENCRYPTION.skip_if(cons)?;
        cons.take_opt_null()?;
        Ok(PublicKeyAlgorithm::RsaEncryption)
    }

    pub fn encode(&self) -> impl encode::Values {
        encode::sequence((
            oid::RSA_ENCRYPTION.encode(),
            encode::PrimitiveContent::encode(&())
        ))
    }
}


//------------ DigestAlgorithm -----------------------------------------------

#[derive(Clone, Debug)]
pub enum DigestAlgorithm {
    Sha256,
}


impl DigestAlgorithm {
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_sequence(Self::from_constructed)
    }

    fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        oid::SHA256.skip_if(cons)?;
        cons.take_opt_null()?;
        Ok(DigestAlgorithm::Sha256)
    }

    /// Parses a SET OF DigestAlgorithmIdentifiers.
    ///
    /// This is used in the digestAlgorithms field of the SignedData
    /// container. It provides all the digest algorithms used later on, so
    /// that the data can be read over. We don’t really need this, so this
    /// function returns `()` on success.
    ///
    /// Section 2.1.2. of RFC 6488 requires there to be exactly one element
    /// chosen from the allowed values.
    pub fn skip_set<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(), S::Err> {
        cons.take_constructed_if(Tag::SET, |cons| {
            while let Some(_) = Self::take_opt_from(cons)? { }
            Ok(())
        })
    }
}


//------------ OIDs ----------------------------------------------------------

pub mod oid {
    use bcder::Oid;

    pub const SHA256: Oid<&[u8]>
        = Oid(&[96, 134, 72, 1, 101, 3, 4, 2, 1]);
    pub const RSA_ENCRYPTION: Oid<&[u8]>
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]);
    pub const SHA256_WITH_RSA_ENCRYPTION: Oid<&[u8]>
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 11]);
}

pub mod signer;

#[cfg(feature = "softkeys")]
pub mod softsigner;
