//! Types for Autonomous Systems Numbers (ASN) and ASN collections

use std::{error, fmt, iter, ops, slice};
use std::cmp::Ordering;
use std::str::FromStr;
use std::iter::Peekable;

#[cfg(feature = "bcder")]
use bcder::decode::{self, DecodeError, Source};


//------------ Asn -----------------------------------------------------------

/// An AS number (ASN).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Asn(u32);

impl Asn {
    pub const MIN: Asn = Asn(u32::MIN);
    pub const MAX: Asn = Asn(u32::MAX);

    /// Creates an AS number from a `u32`.
    pub fn from_u32(value: u32) -> Self {
        Asn(value)
    }

    /// Converts an AS number into a `u32`.
    pub fn into_u32(self) -> u32 {
        self.0
    }

    /// Converts an AS number into a network-order byte array.
    pub fn to_raw(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

#[cfg(feature = "bcder")]
impl Asn {
    /// Takes an AS number from the beginning of an encoded value.
    pub fn take_from<S: Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_u32().map(Asn)
    }

    /// Takes an optional AS number from the beginning of an encoded value.
    pub fn take_opt_from<S: Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_u32().map(|val| val.map(Asn))
    }

    /// Skips over an AS number at the beginning of an encoded value.
    pub fn skip_in<S: Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(), DecodeError<S::Error>> {
        cons.take_u32().map(|_| ())
    }

    /// Parses the content of an AS number value.
    pub fn parse_content<S: Source>(
        content: &mut decode::Content<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        content.to_u32().map(Asn)
    }

    /// Skips the content of an AS number value.
    pub fn skip_content<S: Source>(
        content: &mut decode::Content<S>
    ) -> Result<(), DecodeError<S::Error>> {
        content.to_u32().map(|_| ())
    }

    pub fn encode(self) -> impl bcder::encode::Values {
        bcder::encode::PrimitiveContent::encode(self.0)
    }
}

//--- From

impl From<u32> for Asn {
    fn from(id: u32) -> Self {
        Asn(id)
    }
}

impl From<Asn> for u32 {
    fn from(id: Asn) -> Self {
        id.0
    }
}

//--- FromStr

impl FromStr for Asn {
    type Err = ParseAsnError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = if s.len() > 2 && s[..2].eq_ignore_ascii_case("as") {
            &s[2..]
        } else {
            s
        };

        u32::from_str(s).map(Asn).map_err(|_| ParseAsnError)
    }
}


//--- Serialize and Deserialize

/// # Serialization
///
/// With the `"serde"` feature enabled, `Asn` implements the `Serialize` and
/// `Deserialize` traits via _serde-derive_ as a newtype wrapping a `u32`.
///
/// However, ASNs are often serialized as a string prefix with `AS`. In order
/// to allow this, a number of methods are provided that can be used with
/// Serde’s field attributes to choose how to serialize an ASN as part of a
/// struct.
#[cfg(feature = "serde")]
impl Asn {
    /// Serializes an AS number as a simple `u32`.
    ///
    /// Normally, you wouldn’t need to use this method, as the default
    /// implementation serializes the ASN as a newtype struct with a `u32`
    /// inside which most serialization formats will turn into a sole `u32`.
    /// However, in case your format doesn’t, you can use this method.
    pub fn serialize_as_u32<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.0)
    }

    /// Serializes an AS number as a string without prefix.
    pub fn serialize_as_bare_str<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{}", self.0))
    }

    /// Seriaizes an AS number as a string with a `AS` prefix.
    pub fn serialize_as_str<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("AS{}", self.0))
    }

    /// Deserializes an AS number from a simple `u32`.
    ///
    /// Normally, you wouldn’t need to use this method, as the default
    /// implementation deserializes the ASN from a newtype struct with a
    /// `u32` inside for which most serialization formats will use a sole
    /// `u32`. However, in case your format doesn’t, you can use this method.
    pub fn deserialize_from_u32<'de, D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        <u32 as serde::Deserialize>::deserialize(deserializer).map(Into::into)
    }

    /// Deserializes an AS number from a string.
    ///
    /// The string may or may not have a case-insensitive `"AS"` prefix.
    pub fn deserialize_from_str<'de, D: serde::de::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Asn;

            fn expecting(
                &self, formatter: &mut fmt::Formatter
            ) -> fmt::Result {
                write!(formatter, "an AS number")
            }

            fn visit_str<E: serde::de::Error>(
                self, v: &str
            ) -> Result<Self::Value, E> {
                Asn::from_str(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(Visitor)
    }

    /// Deserializes an AS number as either a string or `u32`.
    ///
    /// This function can only be used with self-describing serialization
    /// formats as it uses `Deserializer::deserialize_any`. It accepts an
    /// AS number as any kind of integer as well as a string with or without
    /// a case-insensitive `"AS"` prefix.
    pub fn deserialize_from_any<'de, D: serde::de::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Asn;

            fn expecting(
                &self, formatter: &mut fmt::Formatter
            ) -> fmt::Result {
                write!(formatter, "an AS number")
            }

            fn visit_u8<E: serde::de::Error>(
                self, v: u8
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.into()))
            }

            fn visit_u16<E: serde::de::Error>(
                self, v: u16
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.into()))
            }

            fn visit_u32<E: serde::de::Error>(
                self, v: u32
            ) -> Result<Self::Value, E> {
                Ok(Asn(v))
            }

            fn visit_u64<E: serde::de::Error>(
                self, v: u64
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.try_into().map_err(E::custom)?))
            }

            fn visit_i8<E: serde::de::Error>(
                self, v: i8
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.try_into().map_err(E::custom)?))
            }

            fn visit_i16<E: serde::de::Error>(
                self, v: i16
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.try_into().map_err(E::custom)?))
            }

            fn visit_i32<E: serde::de::Error>(
                self, v: i32
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.try_into().map_err(E::custom)?))
            }

            fn visit_i64<E: serde::de::Error>(
                self, v: i64
            ) -> Result<Self::Value, E> {
                Ok(Asn(v.try_into().map_err(E::custom)?))
            }

            fn visit_str<E: serde::de::Error>(
                self, v: &str
            ) -> Result<Self::Value, E> {
                Asn::from_str(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

//--- Add

impl ops::Add<u32> for Asn {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        Asn(self.0.checked_add(rhs).unwrap())
    }
}

//--- Display

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}


//------------ SmallAsnSet --------------------------------------------------

/// A relatively small set of ASNs.
///
/// This type is only efficient if the amount of ASNs in it is relatively
/// small as it is represented internally by an ordered vec of ASNs to avoid
/// memory overhead.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SmallAsnSet(Vec<Asn>);

impl SmallAsnSet {
    /// Creates a new ASN set from an order vec of unique ASNs.
    ///
    /// # Safety
    ///
    /// The caller must make sure that the vec passed is sorted and does not
    /// contain any duplicates.
    pub unsafe fn from_vec_unchecked(vec: Vec<Asn>) -> Self {
        Self(vec)
    }

    pub fn iter(&self) -> SmallSetIter {
        self.0.iter().cloned()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn difference<'a>(
        &'a self, other: &'a Self
    ) -> SmallSetDifference<'a> {
        SmallSetDifference {
            left: self.iter().peekable(),
            right: other.iter().peekable(),
        }
    }

    pub fn symmetric_difference<'a>(
        &'a self, other: &'a Self
    ) -> SmallSetSymmetricDifference<'a> {
        SmallSetSymmetricDifference {
            left: self.iter().peekable(),
            right: other.iter().peekable(),
        }
    }

    pub fn intersection<'a>(
        &'a self, other: &'a Self
    ) -> SmallSetIntersection<'a> {
        SmallSetIntersection {
            left: self.iter().peekable(),
            right: other.iter().peekable(),
        }
    }

    pub fn union<'a>(&'a self, other: &'a Self) -> SmallSetUnion<'a> {
        SmallSetUnion {
            left: self.iter().peekable(),
            right: other.iter().peekable(),
        }
    }

    pub fn contains(&self, asn: Asn) -> bool {
        self.0.binary_search(&asn).is_ok()
    }

    // Missing: is_disjoint, is_subset, is_superset, insert, remove,
}


impl iter::FromIterator<Asn> for SmallAsnSet {
    fn from_iter<T: IntoIterator<Item = Asn>>(iter: T) -> Self {
        let mut res = Self(iter.into_iter().collect());
        res.0.sort();
        res
    }
}

impl<'a> IntoIterator for &'a SmallAsnSet {
    type Item = Asn;
    type IntoIter = SmallSetIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().cloned()
    }
}


//------------ SmallSetIter --------------------------------------------------

pub type SmallSetIter<'a> = iter::Cloned<slice::Iter<'a, Asn>>;


//------------ SmallSetDifference --------------------------------------------

pub struct SmallSetDifference<'a> {
    left: Peekable<SmallSetIter<'a>>,
    right: Peekable<SmallSetIter<'a>>,
}

impl<'a> Iterator for SmallSetDifference<'a> {
    type Item = Asn;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match (self.left.peek(), self.right.peek()) {
                (None, _) => return None,
                (Some(_), None) => return self.left.next(),
                (Some(left), Some(right)) => {
                    match left.cmp(right) {
                        Ordering::Less => return self.left.next(),
                        Ordering::Equal => {
                            let _ = self.left.next();
                            let _ = self.right.next();
                        }
                        Ordering::Greater => {
                            let _ = self.right.next();
                        }
                    }
                }
            }
        }
    }
}


//------------ SmallSetSymmetricDifference -----------------------------------

pub struct SmallSetSymmetricDifference<'a> {
    left: Peekable<SmallSetIter<'a>>,
    right: Peekable<SmallSetIter<'a>>,
}

impl<'a> Iterator for SmallSetSymmetricDifference<'a> {
    type Item = Asn;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match (self.left.peek(),self. right.peek()) {
                (None, None) => return None,
                (Some(_), None) => return self.left.next(),
                (None, Some(_)) => return self.right.next(),
                (Some(left), Some(right)) => {
                    match left.cmp(right) {
                        Ordering::Equal => {
                            let _ = self.left.next();
                            let _ = self.right.next();
                        }
                        Ordering::Less => return self.left.next(),
                        Ordering::Greater => return self.right.next(),
                    }
                }
            }
        }
    }
}


//------------ SmallSetIntersection ------------------------------------------

pub struct SmallSetIntersection<'a> {
    left: Peekable<SmallSetIter<'a>>,
    right: Peekable<SmallSetIter<'a>>,
}

impl<'a> Iterator for SmallSetIntersection<'a> {
    type Item = Asn;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match (self.left.peek(),self. right.peek()) {
                (None, _) | (_, None) => return None,
                (Some(left), Some(right)) => {
                    match left.cmp(right) {
                        Ordering::Equal => {
                            let _ = self.left.next();
                            return self.right.next()
                        }
                        Ordering::Less => {
                            let _ = self.left.next();
                        }
                        Ordering::Greater => {
                            let _ = self.right.next();
                        }
                    }
                }
            }
        }
    }
}


//------------ SmallSetUnion -------------------------------------------------

pub struct SmallSetUnion<'a> {
    left: Peekable<SmallSetIter<'a>>,
    right: Peekable<SmallSetIter<'a>>,
}

impl<'a> Iterator for SmallSetUnion<'a> {
    type Item = Asn;

    fn next(&mut self) -> Option<Self::Item> {
        match (self.left.peek(),self. right.peek()) {
            (None, None) => None,
            (Some(_), None) => self.left.next(),
            (None, Some(_)) => self.right.next(),
            (Some(left), Some(right)) => {
                match left.cmp(right) {
                    Ordering::Less => self.left.next(),
                    Ordering::Equal => {
                        let _ = self.left.next();
                        self.right.next()
                    }
                    Ordering::Greater => {
                        self.right.next()
                    }
                }
            }
        }
    }
}


//============ Error Types ===================================================

//------------ ParseAsnError ------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseAsnError;

impl fmt::Display for ParseAsnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid AS number")
    }
}

impl error::Error for ParseAsnError {}


//============ Tests =========================================================

#[cfg(all(test, feature = "serde"))]
mod test_serde {
    use super::*;
    use serde_test::{Token, assert_de_tokens, assert_tokens};
    
    #[test]
    fn asn() {
        #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
        struct AsnTest(
            Asn,

            #[serde(
                deserialize_with = "Asn::deserialize_from_u32",
                serialize_with = "Asn::serialize_as_u32",
            )]
            Asn,

            #[serde(
                deserialize_with = "Asn::deserialize_from_str",
                serialize_with = "Asn::serialize_as_str",
            )]
            Asn,
        );

        assert_tokens(
            &AsnTest ( Asn(0), Asn(0), Asn(0) ),
            &[
                Token::TupleStruct { name: "AsnTest", len: 3 },
                Token::NewtypeStruct { name: "Asn" }, Token::U32(0),
                Token::U32(0),
                Token::Str("AS0"),
                Token::TupleStructEnd,
            ]
        );
    }

    #[test]
    fn asn_any() {
        #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
        struct AsnTest(
            #[serde(deserialize_with = "Asn::deserialize_from_any")]
            Asn,
            #[serde(deserialize_with = "Asn::deserialize_from_any")]
            Asn,
            #[serde(deserialize_with = "Asn::deserialize_from_any")]
            Asn,
            #[serde(deserialize_with = "Asn::deserialize_from_any")]
            Asn,
            #[serde(deserialize_with = "Asn::deserialize_from_any")]
            Asn,
            #[serde(deserialize_with = "Asn::deserialize_from_any")]
            Asn,
        );

        assert_de_tokens(
            &AsnTest(Asn(0), Asn(0), Asn(0), Asn(0), Asn(0), Asn(0)),
            &[
                Token::TupleStruct { name: "AsnTest", len: 5 },
                Token::U32(0),
                Token::U64(0),
                Token::I64(0),
                Token::Str("0"),
                Token::Str("AS0"),
                Token::Str("As0"),
                Token::TupleStructEnd,
            ]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn asn() {
        assert_eq!(Asn::from_u32(1234), Asn(1234));
        assert_eq!(Asn(1234).into_u32(), 1234);

        assert_eq!(Asn::from(1234_u32), Asn(1234));
        assert_eq!(u32::from(Asn(1234)), 1234_u32);

        assert_eq!(format!("{}", Asn(1234)).as_str(), "AS1234");

        assert_eq!("0".parse::<Asn>(), Ok(Asn(0)));
        assert_eq!("AS1234".parse::<Asn>(), Ok(Asn(1234)));
        assert_eq!("as1234".parse::<Asn>(), Ok(Asn(1234)));
        assert_eq!("As1234".parse::<Asn>(), Ok(Asn(1234)));
        assert_eq!("aS1234".parse::<Asn>(), Ok(Asn(1234)));
        assert_eq!("1234".parse::<Asn>(), Ok(Asn(1234)));

        assert_eq!("".parse::<Asn>(), Err(ParseAsnError));
        assert_eq!("-1234".parse::<Asn>(), Err(ParseAsnError));
        assert_eq!("4294967296".parse::<Asn>(), Err(ParseAsnError));
    }


    //--- SmallAsnSet

    // Checks that our set operation does the same as the same on
    // HashSet<Asn>.
    macro_rules! check_set_fn {
        ( $fn:ident, $left:expr, $right:expr $(,)? ) => {{
            let left = Vec::from_iter($left.into_iter().map(Asn::from_u32));
            let right = Vec::from_iter($right.into_iter().map(Asn::from_u32));

            let set_fn = {
                let left = SmallAsnSet::from_iter(
                    left.clone().into_iter()
                );
                let right = SmallAsnSet::from_iter(
                    right.clone().into_iter()
                );
                left.$fn(&right).collect::<HashSet<Asn>>()
            };
            let hash_fn: HashSet<Asn> = {
                let left: HashSet<Asn> = HashSet::from_iter(
                    left.clone().into_iter()
                );
                let right: HashSet<Asn> = HashSet::from_iter(
                    right.clone().into_iter()
                );
                left.$fn(&right).cloned().collect()
            };
            assert_eq!(set_fn, hash_fn);
        }}
    }

    macro_rules! check_all_set_fns {
        ( $left:expr, $right:expr $(,)? ) => {{
            check_set_fn!(difference, $left, $right);
            check_set_fn!(symmetric_difference, $left, $right);
            check_set_fn!(intersection, $left, $right);
            check_set_fn!(union, $left, $right);
        }}
    }

    #[test]
    fn small_set_operations() {
        check_all_set_fns!([0, 1, 2, 3], [0, 1, 2, 3]);
        check_all_set_fns!([0, 1, 2], [0, 1, 2, 3]);
        check_all_set_fns!([0, 1, 2, 3], [0, 1, 2]);
        check_all_set_fns!([0, 1, 2, 3], [0, 1, 2]);
        check_all_set_fns!([], []);
        check_all_set_fns!([1, 2, 3], []);
        check_all_set_fns!([], [1, 2, 3]);
    }
}
