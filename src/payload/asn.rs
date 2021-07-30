
use std::{error, fmt, ops};
use std::str::FromStr;
#[cfg(feature = "repository")] use bcder::{decode, encode};

//------------ AsId ----------------------------------------------------------

/// An AS number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AsId(u32);

impl AsId {
    pub const MIN: AsId = AsId(std::u32::MIN);
    pub const MAX: AsId = AsId(std::u32::MAX);

    /// Creates an AS number from a `u32`.
    pub fn from_u32(value: u32) -> Self {
        AsId(value)
    }

    /// Converts an AS number into a `u32`.
    pub fn into_u32(self) -> u32 {
        self.0
    }
}

#[cfg(feature = "repository")] impl AsId {
    /// Takes an AS number from the beginning of an encoded value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_u32().map(AsId)
    }

    /// Skips over the AS number at the beginning of an encoded value.
    pub fn skip_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(), S::Err> {
        cons.take_u32().map(|_| ())
    }

    /// Parses the content of an AS number value.
    pub fn parse_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, S::Err> {
        content.to_u32().map(AsId)
    }

    /// Skips the content of an AS number value.
    pub fn skip_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<(), S::Err> {
        content.to_u32().map(|_| ())
    }

    pub fn encode(self) -> impl encode::Values {
        encode::PrimitiveContent::encode(self.0)
    }
}


//--- From

impl From<u32> for AsId {
    fn from(id: u32) -> Self {
        AsId(id)
    }
}

impl From<AsId> for u32 {
    fn from(id: AsId) -> Self {
        id.0
    }
}


//--- FromStr

impl FromStr for AsId {
    type Err = ParseAsIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = if s.len() > 2 && s[..2].eq_ignore_ascii_case("as") {
            &s[2..]
        } else {
            s
        };

        u32::from_str(s).map(AsId).map_err(|_| ParseAsIdError)
    }
}

//--- Deserialize
//
// There is no standard serialization because there is no commonly agreed
// upon serialization format. Options are: serialize as u32, serialize as a
// string, serialize as string with a prefix "AS".

#[cfg(feature = "serde")]
impl<'de> serde::de::Deserialize<'de> for AsId {
    /// Deserialize an AS number.
    ///
    /// This implementation is extremely flexible with regards to how the AS
    /// number can be encoded. It allows integers as well as string with and
    /// without the `AS` prefix.
    fn deserialize<D: serde::de::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = AsId;

            fn expecting(
                &self, formatter: &mut fmt::Formatter
            ) -> fmt::Result {
                write!(formatter, "an AS number")
            }

            fn visit_str<E: serde::de::Error>(
                self, v: &str
            ) -> Result<Self::Value, E> {
                AsId::from_str(v).map_err(E::custom)
            }

            fn visit_u32<E: serde::de::Error>(
                self, v: u32
            ) -> Result<Self::Value, E> {
                Ok(v.into())
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}


//--- Add

impl ops::Add<u32> for AsId {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        AsId(self.0.checked_add(rhs).unwrap())
    }
}


//--- Display

impl fmt::Display for AsId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}


//------------ ParseAsIdError ------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseAsIdError;

impl fmt::Display for ParseAsIdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid AS number")
    }
}

impl error::Error for ParseAsIdError { }

