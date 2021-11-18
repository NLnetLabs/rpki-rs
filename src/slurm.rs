//! Local exceptions for RPKI payload data.
//!
//! This module contains the types representing the content SLURM files as
//! defined in [RFC 8416]. They support serialization and deserialization
//! to JSON files as required by the RFC via _serde._
//!
//! [RFC 8416]: https://tools.ietf.org/html/rfc8416

#![cfg(feature = "slurm")]

use std::{borrow, fmt, io, ops};
use std::convert::TryFrom;
use std::str::FromStr;
use bytes::Bytes;
use routecore::addr::{MaxLenPrefix, Prefix};
use routecore::bgpsec::KeyIdentifier;
use routecore::asn::Asn;
use serde::{Deserialize, Serialize};
use crate::rtr::payload as rtr;


//------------ SlurmFile -----------------------------------------------------

/// The content of a SLURM file.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlurmFile {
    #[serde(rename = "slurmVersion")]
    version: SlurmVersion,

    #[serde(rename = "validationOutputFilters")]
    pub filters: ValidationOutputFilters,

    #[serde(rename = "locallyAddedAssertions")]
    pub assertions: LocallyAddedAssertions,
}

impl SlurmFile {
    /// Creates a new slurm file from filters and assertions.
    pub fn new(
        filters: ValidationOutputFilters,
        assertions: LocallyAddedAssertions,
    ) -> Self {
        SlurmFile {
            version: Default::default(),
            filters, assertions,
        }
    }

    /// Parses a SLURM file from a reader.
    pub fn from_reader(
        reader: impl io::Read
    ) -> Result<Self, serde_json::Error> {
        serde_json::from_reader(reader)
    }

    /// Returns a string with the compact JSON representation.
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        serde_json::to_string(self).expect("serialization failed")
    }

    /// Returns a string with the pretty-printed JSON representation.
    pub fn to_string_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("serialization failed")
    }

    /// Writes the JSON representation to a writer.
    pub fn to_writer(&self, writer: impl io::Write) -> Result<(), io::Error> {
        serde_json::to_writer(writer, self).map_err(Into::into)
    }

    /// Writes the pretty-printed JSON representation to a writer.
    pub fn to_writer_pretty(
        &self, writer: impl io::Write
    ) -> Result<(), io::Error> {
        serde_json::to_writer_pretty(writer, self).map_err(Into::into)
    }

    /// Returns whether the given payload item should be dropped.
    pub fn drop_payload(&self, payload: &rtr::Payload) -> bool {
        self.filters.drop_payload(payload)
    }
}

impl FromStr for SlurmFile {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}


//------------ SlurmVersion --------------------------------------------------

/// The SLURM version of the file.
///
/// This is currently required to be 1, so this type is a unit struct (de-)
/// serializing accordingly.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(try_from = "u8")]
struct SlurmVersion;

impl Default for SlurmVersion {
    fn default() -> SlurmVersion {
        SlurmVersion
    }
}

impl TryFrom<u8> for SlurmVersion {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value == 1 {
            Ok(Self)
        }
        else {
            Err("slurmVersion must be 1")
        }
    }
}

impl Serialize for SlurmVersion {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(1)
    }
}


//------------ ValidationOutputFilters ---------------------------------------

/// The set of description of entries to be removed from the data set.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationOutputFilters {
    /// The list of descriptions of route origin assertions to remove.
    #[serde(rename = "prefixFilters")]
    pub prefix: Vec<PrefixFilter>,

    /// The list of descriptions of BGPsec router keys to remove.
    #[serde(rename = "bgpsecFilters")]
    pub bgpsec: Vec<BgpsecFilter>,
}

impl ValidationOutputFilters {
    /// Creates a new value from the components.
    pub fn new(
        prefix: impl Into<Vec<PrefixFilter>>,
        bgpsec: impl Into<Vec<BgpsecFilter>>,
    ) -> Self {
        ValidationOutputFilters {
            prefix: prefix.into(),
            bgpsec: bgpsec.into(),
        }
    }

    /// Returns whether the given payload item should be dropped.
    pub fn drop_payload(&self, payload: &rtr::Payload) -> bool {
        for prefix in &self.prefix {
            if prefix.drop_payload(payload) {
                return true
            }
        }
        false
    }
}


//------------ PrefixFilter --------------------------------------------------

// serde doesn’t allow enums to be flattened. So we will have to allow empty
// filters unless we want to do our own Deserialize impl. Which we don’t.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixFilter {
    /// The prefix for which assertions should be filtered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<Prefix>,

    /// The AS number of the autonomous system to filter assertions for.
    #[serde(with = "self::serde_opt_asn")]
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<Asn>,

    /// An optional cpmment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl PrefixFilter {
    /// Creates a new prefix filter.
    pub fn new(
        prefix: Option<Prefix>, asn: Option<Asn>, comment: Option<String>
    ) -> Self {
        PrefixFilter { prefix, asn, comment }
    }

    /// Returns whether the given payload item should be dropped.
    pub fn drop_payload(&self, payload: &rtr::Payload) -> bool {
        let drop_prefix = self.prefix.and_then(|self_prefix| {
            payload.to_origin().map(|origin| {
                self_prefix.covers(origin.prefix.prefix())
            })
        });
        let drop_asn = self.asn.and_then(|self_asn| {
            payload.to_origin().map(|origin| {
                self_asn == origin.asn
            })
        });

        match (drop_prefix, drop_asn) {
            (Some(prefix), Some(asn)) => prefix && asn,
            (Some(prefix), None) => prefix,
            (None, Some(asn)) => asn,
            (None, None) => false
        }
    }
}


//------------ BgpsecFilter --------------------------------------------------

/// Description for a set of BGPsec router key to be removed.
// serde doesn’t allow enums to be flattened. So we will have to allow empty
// filters unless we want to do our own Deserialize impl. Which we don’t.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BgpsecFilter {
    /// The Subject Key Identifier of the certificate to be removed.
    #[serde(rename = "SKI")]
    #[serde(with = "self::serde_opt_key_identifier")]
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ski: Option<KeyIdentifier>,

    /// The AS number of the autonomous system whose key is to be removed.
    #[serde(with = "self::serde_opt_asn")]
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<Asn>,

    /// An optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl BgpsecFilter {
    /// Creates a new BGPsec filter.
    pub fn new(
        ski: Option<KeyIdentifier>, asn: Option<Asn>, comment: Option<String>,
    ) -> Self {
        BgpsecFilter { ski, asn, comment }
    }
}


//------------ LocallyAddedAssertions ----------------------------------------

/// The set of elements added to the data set.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocallyAddedAssertions {
    /// The list of route origin authorizations added.
    #[serde(rename = "prefixAssertions")]
    pub prefix: Vec<PrefixAssertion>,

    /// The list of BGPsec router keys added.
    #[serde(rename = "bgpsecAssertions")]
    pub bgpsec: Vec<BgpsecAssertion>,
}

impl LocallyAddedAssertions {
    /// Creates a new value from its components.
    pub fn new(
        prefix: impl Into<Vec<PrefixAssertion>>,
        bgpsec: impl Into<Vec<BgpsecAssertion>>,
    ) -> Self {
        LocallyAddedAssertions {
            prefix: prefix.into(),
            bgpsec: bgpsec.into()
        }
    }

    /// Returns an iterator over RTR payload items to be added.
    pub fn iter_payload(&self) -> impl Iterator<Item = rtr::Payload> + '_ {
        self.prefix.iter().map(|item| item.to_payload()).chain(
            self.bgpsec.iter().map(|item| item.to_payload())
        )
    }
}


//------------ PrefixAssertion -----------------------------------------------

/// A route origin assertion.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PrefixAssertion {
    /// The prefix and optional max-length this assertion is for.
    pub prefix: MaxLenPrefix,

    /// The AS number of autonomous system authorized to announce the prefix.
    pub asn: Asn,

    /// An optional comment.
    pub comment: Option<String>,
}

impl PrefixAssertion {
    /// Creates a new prefix assertion.
    pub fn new(
        prefix: MaxLenPrefix,
        asn: Asn,
        comment: Option<String>,
    ) -> Self {
        PrefixAssertion { prefix, asn, comment }
    }

    fn to_payload(&self) -> rtr::Payload {
        rtr::Payload::origin(self.prefix, self.asn)
    }
}


//--- Deserialize and Serialize
//
// We neeed to enforce that max_prefix_len is greater or equal to
// prefix.len(), so we need to roll our own implementation.

impl<'de> Deserialize<'de> for PrefixAssertion {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        enum Fields { Prefix, Asn, MaxPrefixLength, Comment }

        struct StructVisitor;

        impl<'de> de::Visitor<'de> for StructVisitor {
            type Value = PrefixAssertion;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("PrefixAssertion struct")
            }

            fn visit_map<V: de::MapAccess<'de>>(
                self, mut map: V
            ) -> Result<Self::Value, V::Error> {
                let mut prefix = None;
                let mut asn: Option<u32> = None;
                let mut max_len = None;
                let mut comment = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Fields::Prefix => {
                            if prefix.is_some() {
                                return Err(
                                    de::Error::duplicate_field("prefix")
                                );
                            }
                            prefix = Some(map.next_value()?);
                        }
                        Fields::Asn => {
                            if asn.is_some() {
                                return Err(
                                    de::Error::duplicate_field("asn")
                                );
                            }
                            asn = Some(map.next_value()?);
                        }
                        Fields::MaxPrefixLength => {
                            if max_len.is_some() {
                                return Err(
                                    de::Error::duplicate_field("maxPrefixLen")
                                );
                            }
                            max_len = Some(map.next_value()?);
                        }
                        Fields::Comment => {
                            if comment.is_some() {
                                return Err(
                                    de::Error::duplicate_field("comment")
                                );
                            }
                            comment = Some(map.next_value()?);
                        }
                    }
                }

                let prefix: Prefix = prefix.ok_or_else(|| {
                    de::Error::missing_field("prefix")
                })?;
                let asn = asn.ok_or_else(|| {
                    de::Error::missing_field("asn")
                })?;

                let prefix = MaxLenPrefix::new(prefix, max_len).map_err(
                    de::Error::custom
                )?;

                Ok(PrefixAssertion { prefix, asn: asn.into(), comment })
            }
        }

        const FIELDS: &[&str] = &[
            "prefix", "asn", "maxPrefixLen", "comment"
        ];
        deserializer.deserialize_struct(
            "PrefixAssertion", FIELDS, StructVisitor
        )
    }
}

impl Serialize for PrefixAssertion {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut serializer = serializer.serialize_struct(
            "PrefixAssertion",
            match (self.prefix.max_len().is_some(), self.comment.is_some()) {
                (true, true) => 4,
                (true, false) | (false, true) => 3,
                (false, false) => 2
            }
        )?;
        serializer.serialize_field(
            "prefix", &self.prefix.prefix(),
        )?;
        serializer.serialize_field(
            "asn", &self.asn.into_u32()
        )?;
        if let Some(max_len) = self.prefix.max_len() {
            serializer.serialize_field(
                "maxPrefixLength", &max_len
            )?;
        }
        if let Some(comment) = self.comment.as_ref() {
            serializer.serialize_field(
                "comment", comment.as_str()
            )?;
        }
        serializer.end()
    }
}


//------------ BgpsecAssertion -----------------------------------------------

/// A BGPsec router key to be added to the data set.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BgpsecAssertion {
    /// The AS number of the autonomous system using the key.
    #[serde(with = "self::serde_asn")]
    pub asn: Asn,

    /// The Subject Key Identifier of the certificate.
    ///
    /// This is “the Base64 encoding without trailing ‘=’ (Section 5 of
    /// [RFC4648]) of the certificate’s Subject Key Identifier.”
    ///
    /// [RFC4648]: https://tools.ietf.org/html/rfc4648
    #[serde(rename = "SKI")]
    #[serde(with = "self::serde_key_identifier")]
    pub ski: KeyIdentifier,

    /// The public key.
    ///
    /// This is “the Base64 encoding without trailing ‘=’ (Section 5 of
    /// [RFC4648]) of the router certificate's public key.’
    ///
    /// [RFC4648]: https://tools.ietf.org/html/rfc4648
    #[serde(rename = "routerPublicKey")]
    pub router_public_key: Base64Binary,

    /// An optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

impl BgpsecAssertion {
    /// Creates a new router key assertion.
    pub fn new(
        asn: Asn,
        ski: KeyIdentifier,
        router_public_key: Base64Binary,
        comment: Option<String>,
    ) -> Self {
        BgpsecAssertion { asn, ski, router_public_key, comment }
    }

    fn to_payload(&self) -> rtr::Payload {
        rtr::Payload::router_key(
            self.ski, self.asn, self.router_public_key.0.clone()
        )
    }
}


//------------ Base64Binary --------------------------------------------------

/// A sequence of binary data encoded in Base64 when serialized.
///
/// Specifically, the data is encoded in Base64 using the URL and filename
/// safe alphabet without trailing equals signs. See section 5 of [RFC 4648]
/// for details.
///
/// The type holds the decoded data and provides access to it by derefing to
/// `[u8]`.
///
/// [RFC4648]: https://tools.ietf.org/html/rfc4648
#[derive(Clone, Default, Eq, Hash)]
pub struct Base64Binary(Bytes);

impl Base64Binary {
    const BASE64_CONFIG: base64::Config = base64::Config::new(
        base64::CharacterSet::UrlSafe, false
    );
}


//--- From

impl From<Vec<u8>> for Base64Binary {
    fn from(src: Vec<u8>) -> Self {
        Base64Binary(src.into())
    }
}

impl From<Bytes> for Base64Binary {
    fn from(src: Bytes) -> Self {
        Base64Binary(src)
    }
}

impl From<Base64Binary> for Bytes {
    fn from(src: Base64Binary) -> Self {
        src.0
    }
}


//--- FromStr

impl FromStr for Base64Binary {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        base64::decode_config(s, Self::BASE64_CONFIG).map(Into::into)
    }
}


//--- Deref, AsRef, Borrow

impl ops::Deref for Base64Binary {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for Base64Binary {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl borrow::Borrow<[u8]> for Base64Binary {
    fn borrow(&self) -> &[u8] {
        self.0.as_ref()
    }
}


//--- PartialEq

impl<T: AsRef<[u8]>> PartialEq<T> for Base64Binary {
    fn eq(&self, other: &T) -> bool {
        self.0.as_ref().eq(other.as_ref())
    }
}


//--- Display and Debug

impl fmt::Display for Base64Binary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        base64::display::Base64Display::with_config(
            self.0.as_ref(),
            Self::BASE64_CONFIG
        ).fmt(f)
    }
}

impl fmt::Debug for Base64Binary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Base64Binary")
        .field(&format_args!("{}", self))
        .finish()
    }
}


//--- Serialize and Deserialize

impl Serialize for Base64Binary {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        // XXX Can this be done without making a string first?
        serializer.serialize_str(&format!("{}", self))
    }
}

impl<'de> Deserialize<'de> for Base64Binary {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Base64Binary;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a Base64 string")
            }

            fn visit_str<E: serde::de::Error>(
                self, v: &str
            ) -> Result<Self::Value, E> {
                Base64Binary::from_str(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}


//----------- Serialization of ASNs -----------------------------------------

mod serde_asn {
    use super::Asn;

    pub fn serialize<S: serde::Serializer>(
        asn: &Asn, serializer: S
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(asn.into_u32())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Asn, D::Error> {
        <u32 as serde::Deserialize>::deserialize(deserializer).map(Into::into)
    }
}

mod serde_opt_asn {
    use super::Asn;

    pub fn serialize<S: serde::Serializer>(
        asn: &Option<Asn>, serializer: S
    ) -> Result<S::Ok, S::Error> {
        match asn.as_ref() {
            Some(asn) => serializer.serialize_u32(asn.into_u32()),
            None => serializer.serialize_none()
        }
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Option<Asn>, D::Error> {
        <Option::<u32> as serde::Deserialize>
            ::deserialize(deserializer).map(|ok| ok.map(Into::into))
    }
}


//----------- Serialization of Key Identifiers ------------------------------

mod serde_key_identifier {
    use std::fmt;
    use std::convert::TryFrom;
    use super::{Base64Binary, KeyIdentifier};

    pub fn serialize<S: serde::Serializer>(
        key_id: &KeyIdentifier, serializer: S
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(
            &base64::encode_config(
                key_id.as_slice(), Base64Binary::BASE64_CONFIG
            )
        )
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<KeyIdentifier, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = KeyIdentifier;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a Base64-encoded key identifier")
            }

            fn visit_str<E: serde::de::Error>(
                self, v: &str
            ) -> Result<Self::Value, E> {
                println!("visit_str '{}'", v);

                // The key identifier is 20 bytes. Which means the Base64
                // encoding has to be 27 characters wrong (since padding is
                // not included).
                if v.len() != 27 {
                    return Err(E::custom("invalid length for key identifier"))
                }

                // A 27 character Base64 string can contains 20 or 21 bytes.
                let mut buf = [0u8; 21];
                let len = base64::decode_config_slice(
                    v, Base64Binary::BASE64_CONFIG, &mut buf
                ).map_err(E::custom)?;

                // If we actually get 21 bytes, KeyIdentifier::try_from will
                // complain.
                KeyIdentifier::try_from(&buf[..len]).map_err(|_| {
                    E::custom("invalid length for key identifier")
                })
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

mod serde_opt_key_identifier {
    use super::KeyIdentifier;

    pub fn serialize<S: serde::Serializer>(
        key_id: &Option<KeyIdentifier>, serializer: S
    ) -> Result<S::Ok, S::Error> {
        match key_id.as_ref() {
            Some(key_id) => {
                super::serde_key_identifier::serialize(key_id, serializer)
            }
            None => serializer.serialize_none()
        }
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Option<KeyIdentifier>, D::Error> {
        // By not accepting a `None` here, we make sure that the field can
        // never be `null` in the JSON.
        super::serde_key_identifier::deserialize(deserializer).map(Some)
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn base64_binary_from_str() {
        // This uses the test vector from RFC 4648 which doesn’t actually
        // allow testing for the correct alphabet. Since there is hardly any
        // use of BGPsec in the wild, there also aren’t any real-world
        // examples. In other words, this test may succeed and we are still
        // using the wrong decoding config.
        assert_eq!(
            b"foo",
            Base64Binary::from_str("Zm9v").unwrap().as_ref()
        );
    }

    #[test]
    fn base64_binary_display() {
        assert_eq!(
            format!("{}", Base64Binary::from(Vec::from(b"foo".as_ref()))),
            "Zm9v".as_ref()
        );
    }

    #[test]
    fn parse_empty_slurm_file() {
        let json = r##"
            {
              "slurmVersion": 1,
              "validationOutputFilters": {
                "prefixFilters": [],
                "bgpsecFilters": []
              },
              "locallyAddedAssertions": {
                "prefixAssertions": [],
                "bgpsecAssertions": []
              }
            }
        "##;
        let exceptions = SlurmFile::from_str(json).unwrap();

        assert_eq!(0, exceptions.filters.prefix.len());
        assert_eq!(0, exceptions.filters.bgpsec.len());
        assert_eq!(0, exceptions.assertions.prefix.len());
        assert_eq!(0, exceptions.assertions.bgpsec.len());
    }

    fn full_slurm() -> SlurmFile {
        SlurmFile::new(
            ValidationOutputFilters::new(
                [
                    PrefixFilter::new(
                        Some(Prefix::new_v4(
                            [192, 0, 2, 0].into(), 24
                        ).unwrap()),
                        None,
                        Some(
                            String::from("All VRPs encompassed by prefix")
                        )
                    ),
                    PrefixFilter::new(
                        None,
                        Some(64496.into()),
                        Some(String::from("All VRPs matching ASN"))
                    ),
                    PrefixFilter::new(
                        Some(Prefix::new_v4(
                            [198, 51, 100, 0].into(), 24
                        ).unwrap()),
                        Some(64497.into()),
                        Some(String::from(
                            "All VRPs encompassed by prefix, matching ASN"
                        ))
                    ),
                ],
                [
                    BgpsecFilter::new(
                        None,
                        Some(64496.into()),
                        Some(String::from("All keys for ASN"))
                    ),
                    BgpsecFilter::new(
                        Some(KeyIdentifier::from(*b"12345678901234567890")),
                        None,
                        Some(String::from("Key matching Router SKI"))
                    ),
                    BgpsecFilter::new(
                        Some(KeyIdentifier::from(*b"deadbeatdeadbeatdead")),
                        Some(64497.into()),
                        Some(String::from("Key for ASN matching SKI"))
                    ),
                ],
            ),
            LocallyAddedAssertions::new(
                [
                    PrefixAssertion::new(
                        Prefix::new_v4(
                            [198, 51, 100, 0].into(), 24
                        ).unwrap().into(),
                        64496.into(),
                        Some(String::from("My other important route"))
                    ),
                    PrefixAssertion::new(
                        MaxLenPrefix::new(
                            Prefix::new_v6(
                                [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0].into(),
                                32
                            ).unwrap(),
                            Some(48),
                        ).unwrap().into(),
                        64496.into(),
                        Some(String::from("My de-aggregated route"))
                    ),
                ],
                [
                    BgpsecAssertion::new(
                        64496.into(),
                        KeyIdentifier::from(*b"12345678901234567890"),
                        Bytes::from(b"blubb".as_ref()).into(),
                        None,
                    ),
                ],
            ),
        )
    }

    #[test]
    fn parse_full_slurm_file() {
        assert_eq!(
            SlurmFile::from_str(
                include_str!("../test-data/slurm/full.json")
            ).unwrap(),
            full_slurm()
        );
    }

    #[test]
    fn ser_de_slurm_file() {
        assert_eq!(
            SlurmFile::from_str(&full_slurm().to_string_pretty()).unwrap(),
            full_slurm()
        )
    }

    #[test]
    fn parse_bad_slurm_files() {
        // Bad max len.
        assert!(
            SlurmFile::from_str(
                r##"
                    {
                      "slurmVersion": 1,
                      "validationOutputFilters": {
                        "prefixFilters": [],
                        "bgpsecFilters": []
                      },
                      "locallyAddedAssertions": {
                        "prefixAssertions": [
                          {
                            "asn": 64496,
                            "prefix": "198.51.100.0/24",
                            "maxPrefixLength": 20,
                            "comment": "invalid max len"
                          },
                        ],
                        "bgpsecAssertions": []
                      }
                    }
                "##
            ).is_err()
        );

        // Bad prefix len.
        assert!(
            SlurmFile::from_str(
                r##"
                    {
                      "slurmVersion": 1,
                      "validationOutputFilters": {
                        "prefixFilters": [],
                        "bgpsecFilters": []
                      },
                      "locallyAddedAssertions": {
                        "prefixAssertions": [
                          {
                            "asn": 64496,
                            "prefix": "198.51.100.0/44",
                            "maxPrefixLength": 46,
                            "comment": "invalid prefix len"
                          },
                        ],
                        "bgpsecAssertions": []
                      }
                    }
                "##
            ).is_err()
        );

        // Non-zero host prefix.
        assert!(
            SlurmFile::from_str(
                r##"
                    {
                      "slurmVersion": 1,
                      "validationOutputFilters": {
                        "prefixFilters": [],
                        "bgpsecFilters": []
                      },
                      "locallyAddedAssertions": {
                        "prefixAssertions": [
                          {
                            "asn": 64496,
                            "prefix": "198.51.100.0/16",
                            "maxPrefixLength": 16,
                            "comment": "non-zero"
                          },
                        ],
                        "bgpsecAssertions": []
                      }
                    }
                "##
            ).is_err()
        );
    }
}

