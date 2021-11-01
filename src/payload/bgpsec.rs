//! Payload types related to BGPsec.

use std::{error, fmt, str};
#[cfg(feature = "repository")] use std::io;
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use crate::util::hex;
#[cfg(feature = "repository")] use bcder::decode;
#[cfg(feature = "repository")] use bcder::{Mode, OctetString, Tag};
#[cfg(feature = "repository")] use bcder::encode::PrimitiveContent;
#[cfg(feature = "repository")] use crate::repository::crypto::keys::{
    PublicKey,
};


//------------ KeyIdentifier -------------------------------------------------

/// A key identifier.
///
/// This is the SHA-1 hash over the public key’s bits.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd)]
pub struct KeyIdentifier([u8; 20]);

impl KeyIdentifier {
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
}

#[cfg(feature = "repository")]
impl KeyIdentifier {
    /// Creates a new identifier for the given key.
    pub fn from_public_key(key: &PublicKey) -> Self {
        Self(key.key_identifier().as_ref().try_into().unwrap())
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

    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_value_if(Tag::OCTET_STRING, Self::from_content)
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

    /// Skips over an encoded key indentifier.
    pub fn skip_opt_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        cons.take_opt_value_if(Tag::OCTET_STRING, |cons| {
            Self::from_content(cons)?;
            Ok(())
        })
    }
}


//--- From, TryFrom and FromStr

impl From<[u8; 20]> for KeyIdentifier {
    fn from(src: [u8; 20]) -> Self {
        KeyIdentifier(src)
    }
}

impl From<KeyIdentifier> for [u8; 20] {
    fn from(src: KeyIdentifier) -> Self {
        src.0
    }
}

impl<'a> TryFrom<&'a [u8]> for KeyIdentifier {
    type Error = KeyIdentifierSliceError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        value.try_into()
            .map(KeyIdentifier)
            .map_err(|_| KeyIdentifierSliceError)
    }
}

impl FromStr for KeyIdentifier {
    type Err = ParseKeyIdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 40 || !value.is_ascii() {
            return Err(ParseKeyIdentifierError)
        }
        let mut res = KeyIdentifier(Default::default());
        for (pos, ch) in value.as_bytes().chunks(2).enumerate() {
            let ch = unsafe { str::from_utf8_unchecked(ch) };
            res.0[pos] = u8::from_str_radix(ch, 16)
                            .map_err(|_| ParseKeyIdentifierError)?;
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


//--- PartialEq

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

#[cfg(feature = "repository")]
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

#[cfg(feature = "serde")]
impl serde::Serialize for KeyIdentifier {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; 40];
        hex::encode(self.as_slice(), &mut buf).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for KeyIdentifier {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct KeyIdentifierVisitor;

        impl<'de> serde::de::Visitor<'de> for KeyIdentifierVisitor {
            type Value = KeyIdentifier;

            fn expecting(
                &self, formatter: &mut fmt::Formatter
            ) -> fmt::Result {
                write!(formatter,
                    "a string containing a key identifier as hex digits"
                )
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where E: serde::de::Error {
                KeyIdentifier::from_str(s).map_err(serde::de::Error::custom)
            }

            fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
            where E: serde::de::Error {
                KeyIdentifier::from_str(&s).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(KeyIdentifierVisitor)
    }
}


//============ Errors ========================================================

//------------ ParseKeyIdentifierError ---------------------------------------

/// Creating a prefix has failed.
#[derive(Clone, Debug)]
pub struct ParseKeyIdentifierError;

impl fmt::Display for ParseKeyIdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid key identifier")
    }
}

impl error::Error for ParseKeyIdentifierError { }


//------------ KeyIdentifierSliceError ----------------------------------

/// Creating a prefix has failed.
#[derive(Clone, Debug)]
pub struct KeyIdentifierSliceError;

impl fmt::Display for KeyIdentifierSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid slice for key identifier")
    }
}

impl error::Error for KeyIdentifierSliceError { }


