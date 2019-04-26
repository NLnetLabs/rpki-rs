//! Types and parameters of keys.

use std::io;
use bcder::{decode, encode};
use bcder::{BitString, Mode, Tag};
use bcder::encode::{PrimitiveContent, Values};
use ring::{digest, signature};
use ring::error::Unspecified;
use untrusted::Input;
use crate::oid;
use crate::x509::Name;
use super::signature::Signature;


//------------ PublicKeyFormat -----------------------------------------------

/// The formats of public keys used by RPKI.
///
/// Currently, RPKI uses exactly one type of public keys, RSA keys with a size
/// of 2048 bits. However, as that might change in the future, we are not
/// hard-coding that format but rather use this type – which for the time
/// being is zero-sized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKeyFormat;

/// # ASN.1 Algorithm Identifiers
///
/// The format of the public key is identified in certificates through a
/// algorithm identifier defined with this ASN.1:
///
/// ```txt
/// AlgorithmIdentifier ::= SEQUENCE {
///      algorithm          OBJECT IDENTIFIER,
///      parameters         ANY DEFINED BY algorithm OPTIONAL }
/// ```
///
/// Right now, the object identifier needs to be that of `rsaEncryption`
/// defined by [RFC 4055] and the parameters must be present and NULL.
/// Then parsing, we generously also allow it to be absent altogether.
///
/// The functions and methods in this section allow decoding and encoding of
/// these identifiers.
///
/// [RFC 4055]: https://tools.ietf.org/html/rfc4055
impl PublicKeyFormat{
    /// Takes and returns a algorithm identifier.
    ///
    /// Returns a malformed error if the algorithm isn’t one of the allowed
    /// algorithms or if the value isn’t correctly encoded.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the algorithm identifier from the contents of its sequence.
    fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        oid::RSA_ENCRYPTION.skip_if(cons)?;
        cons.take_opt_null()?;
        Ok(PublicKeyFormat)
    }

    /// Provides an encoder for the algorihm identifier.
    pub fn encode(self) -> impl encode::Values {
        encode::sequence((
            oid::RSA_ENCRYPTION.encode(),
            ().encode(),
        ))
    }
}


//------------ PublicKey -----------------------------------------------------

/// A public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    algorithm: PublicKeyFormat,
    bits: BitString,
}


impl PublicKey {
    pub fn algorithm(&self) -> &PublicKeyFormat {
        &self.algorithm
    }

    pub fn bits(&self) -> &[u8] {
        self.bits.octet_slice().unwrap()
    }

    pub fn key_identifier(&self) -> digest::Digest {
        digest::digest(
            &digest::SHA1,
            self.bits.octet_slice().unwrap()
        )
    }

    /// Verifies a signature using this public key.
    pub fn verify(
        &self, message: &[u8], signature: &Signature
    ) -> Result<(), VerificationError> {
        signature::verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            Input::from(self.bits()),
            Input::from(message),
            Input::from(signature.value().as_ref())
        ).map_err(Into::into)
    }
}


/// # As `SubjectPublicKeyInfo`
///
/// Public keys are included in X.509 certificates as `SubjectPublicKeyInfo`
/// structures. As these are contain the same information as `PublicKey`,
/// it can be decoded from and encoded to such sequences.
impl PublicKey {
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            Ok(PublicKey {
                algorithm: PublicKeyFormat::take_from(cons)?,
                bits: BitString::take_from(cons)?
            })
        })
    }

    pub fn encode(self) -> impl encode::Values {
        encode::sequence((
            self.algorithm.encode(),
            self.bits.encode()
        ))
    }

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            self.algorithm.encode(),
            self.bits.encode_ref()
        ))
    }

    pub fn encode_subject_name<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence(
            encode::set(
                encode::sequence((
                    oid::AT_COMMON_NAME.encode(),
                    PublicKeyCn(&self).encode(),
                ))
            )
        )
    }

    pub fn to_subject_name(&self) -> Name {
        Name::from_captured(self.encode_subject_name().to_captured(Mode::Der))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bits()
    }
}


//------------ PublicKeyCn ---------------------------------------------------

/// Value encoder for a public key as a common name.
///
/// This type encodes the bits of a public key in a printable string as a
/// sequence of hex digits as suggested as one option for subject names in
/// RPKI certificates by section 8 of [RFC 6487].
///
/// [RFC 6487]: https://tools.ietf.org/html/rfc6487
#[derive(Clone, Debug)]
pub struct PublicKeyCn<'a>(&'a PublicKey);

impl<'a> PrimitiveContent for PublicKeyCn<'a> {
    const TAG: Tag = Tag::PRINTABLE_STRING;

    fn encoded_len(&self, _mode: Mode) -> usize {
        self.0.bits.octet_len() * 2
    }

    fn write_encoded<W: io::Write>(
        &self, 
        _mode: Mode, 
        target: &mut W
    ) -> Result<(), io::Error> {
        fn hexdig(ch: u8) -> u8 {
            if ch < 0xa { ch + b'0' }
            else { ch + b'a' }
        }

        for ch in self.0.bits.octets() {
            target.write_all(&[
                hexdig(ch & 0x0F),
                hexdig(ch >> 4)
            ])?
        }
        Ok(())
    }
}


//------------ VerificationError ---------------------------------------------

/// An error happened while verifying a signature.
///
/// No further information is provided. This is on purpose.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[display(fmt="signature verification failed")]
pub struct VerificationError;

impl From<Unspecified> for VerificationError {
    fn from(_: Unspecified) -> Self {
        VerificationError
    }
}

