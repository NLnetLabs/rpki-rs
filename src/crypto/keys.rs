//! Types and parameters of keys.

use std::{fmt, io, str};
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use bcder::{decode, encode};
use bcder::{BitString, Mode, OctetString, Tag};
use bcder::encode::{PrimitiveContent, Values};
use bytes::Bytes;
use derive_more::Display;
use ring::{digest, signature};
use ring::error::Unspecified;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use untrusted::Input;
use unwrap::unwrap;
use crate::oid;
use crate::util::hex;
use crate::x509::{Name, RepresentationError};
use super::signature::Signature;


//------------ PublicKeyFormat -----------------------------------------------

/// The formats of public keys used by RPKI.
///
/// Currently, RPKI uses exactly one type of public keys, RSA keys with a size
/// of 2048 bits. However, as that might change in the future, we are not
/// hard-coding that format but rather use this type – which for the time
/// being is zero-sized.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PublicKeyFormat(());

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
        Ok(PublicKeyFormat::default())
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

    pub fn key_identifier(&self) -> KeyIdentifier {
        unwrap!(KeyIdentifier::try_from(
            digest::digest(
                &digest::SHA1, self.bits.octet_slice().unwrap()
            ).as_ref()
        ))
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

    /// Returns a bytes values of the encoded the *subjectPublicKeyInfo*.
    pub fn to_info_bytes(&self) -> Bytes {
        self.encode_ref().to_captured(Mode::Der).into_bytes()
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
        for ch in self.0.bits.octets() {
            target.write_all(&hex::encode_u8(ch))?
        }
        Ok(())
    }
}


//------------ KeyIdentifier -------------------------------------------------

/// A key identifier.
///
/// This is the SHA-1 hash over the public key’s bits.
#[derive(Clone, Copy, Eq, Hash)]
pub struct KeyIdentifier([u8; 20]);

impl KeyIdentifier {
    /// Creates a new identifier for the given key.
    pub fn from_public_key(key: &PublicKey) -> Self {
        Self(unwrap!(key.key_identifier().as_ref().try_into()))
    }

    /// Returns an octet slice of the key identifer’s value.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Returns a octet array with the hex representation of the identifier.
    pub fn into_hex(self) -> [u8; 40] {
        let mut res = [0u8; 40];
        hex::encode(self.as_slice(), &mut res);
        res
    }

    /// Takes an encoded key identifier from a constructed value.
    ///
    /// ```text
    /// KeyIdentifier ::= OCTET STRING
    /// ```
    ///
    /// The content of the octet string needs to be a SHA-1 hash, so it must
    /// be exactly 20 octets long.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_value_if(Tag::OCTET_STRING, Self::from_content)
    }

    /// Parses an encoded key identifer from a encoded content.
    pub fn from_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, S::Err> {
        let content = OctetString::from_content(content)?;
        if let Some(slice) = content.as_slice() {
            Self::try_from(slice).map_err(|_| decode::Malformed.into())
        }
        else if content.len() != 20 {
            Err(decode::Malformed.into())
        }
        else {
            let mut res = KeyIdentifier(Default::default());
            let mut pos = 0;
            for slice in &content {
                let end = pos + slice.len();
                res.0[pos .. end].copy_from_slice(slice);
                pos = end;
            }
            Ok(res)
        }
    }
}


//--- TryFrom and FromStr

impl<'a> TryFrom<&'a [u8]> for KeyIdentifier {
    type Error = RepresentationError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        value.try_into().map(KeyIdentifier).map_err(|_| RepresentationError)
    }
}

impl FromStr for KeyIdentifier {
    type Err = RepresentationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 40 || !value.is_ascii() {
            return Err(RepresentationError)
        }
        let mut res = KeyIdentifier(Default::default());
        let mut pos = 0;
        for ch in value.as_bytes().chunks(2) {
            let ch = unsafe { str::from_utf8_unchecked(ch) };
            res.0[pos] = u8::from_str_radix(ch, 16)
                            .map_err(|_| RepresentationError)?;
            pos += 1;
        }
        Ok(res)
    }
}


//--- AsRef

impl AsRef<[u8]> for KeyIdentifier {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: AsRef<[u8]>> PartialEq<T> for KeyIdentifier {
    fn eq(&self, other: &T) -> bool {
        self.0.as_ref().eq(other.as_ref())
    }
}


//--- Display and Debug

impl fmt::Display for KeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = [0u8; 40];
        write!(f, "{}", hex::encode(self.as_slice(), &mut buf))
    }
}

impl fmt::Debug for KeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyIdentifier({})", self)
    }
}


//--- PrimitiveContent

impl PrimitiveContent for KeyIdentifier {
    const TAG: Tag = Tag::OCTET_STRING;

    fn encoded_len(&self, _mode: Mode) -> usize {
        20
    }

    fn write_encoded<W: io::Write>(
        &self,
        _mode: Mode,
        target: &mut W
    ) -> Result<(), io::Error> {
        target.write_all(&self.0)
    }
}


//--- Deserialize and Serialize

impl Serialize for KeyIdentifier {
    fn serialize<S: Serializer>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; 40];
        hex::encode(self.as_slice(), &mut buf).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeyIdentifier {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        deserializer.deserialize_str(KeyIdentifierVisitor)
    }
}


//------------ KeyIdentifierVisitor -----------------------------------------

/// Private helper type for implementing deserialization of KeyIdentifier.
struct KeyIdentifierVisitor;

impl<'de> de::Visitor<'de> for KeyIdentifierVisitor {
    type Value = KeyIdentifier;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a string containing a key identifier as hex digits")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where E: de::Error {
        KeyIdentifier::from_str(s).map_err(de::Error::custom)
    }

    fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
    where E: de::Error {
        KeyIdentifier::from_str(&s).map_err(de::Error::custom)
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

