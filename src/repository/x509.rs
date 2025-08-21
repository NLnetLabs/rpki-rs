//! Types common to all things X.509.

use std::{error, fmt, io, ops, str};
use std::cmp::{min, max};
use std::str::FromStr;
use std::time::SystemTime;
use bcder::{decode, encode};
use bcder::{
    BitString, Captured, ConstOid, Mode, OctetString, Oid, Tag,
    Unsigned,
};
use bcder::decode::{DecodeError, ContentError, IntoSource, Source};
use bcder::encode::PrimitiveContent;
use bcder::string::{PrintableString, Utf8String};
use chrono::{
    Datelike, DateTime, LocalResult, TimeDelta, Timelike, TimeZone, Utc
};
use crate::oid;
use crate::crypto::{
    PublicKey, RpkiSignatureAlgorithm, Signature, SignatureAlgorithm, Signer,
    SignatureVerificationError,
};
#[cfg(feature = "serde")] use crate::util::base64;
use super::error::{InspectionError, VerificationError};


//------------ Functions -----------------------------------------------------

/// Updates an optional value the first time.
///
/// Always runs `op` but only assigns its result to `opt` if that doesn’t hold
/// a value yet.
pub fn update_first<F, T, E>(opt: &mut Option<T>, op: F) -> Result<(), E>
where F: FnOnce() -> Result<Option<T>, E> {
    if let Some(value) = op()? {
        if opt.is_none() {
            *opt = Some(value);
        }
    }
    Ok(())
}

/// Returns an encoder for a single certificate or CRL extension.
pub fn encode_extension<V: encode::Values>(
    oid: &'static ConstOid,
    critical: bool,
    content: V
) -> impl encode::Values {
    encode::sequence((
        oid.encode(),
        if critical {
            Some(critical.encode())
        }
        else {
            None
        },
        OctetString::encode_wrapped(Mode::Der, content)
    ))
}


//------------ Name ----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Name(Captured);

impl Name {
    pub(crate) fn from_captured(captured: Captured) -> Self {
        Name(captured)
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.capture(|cons| {
            cons.take_sequence(|cons| { // RDNSequence
                let mut empty_sequence = true;
                while let Some(()) = cons.take_opt_set(|cons| {
                    empty_sequence = false;
                    let mut empty_set = true;
                    while let Some(()) = cons.take_opt_sequence(|cons| {
                        empty_set = false;
                        Oid::skip_in(cons)?;
                        if cons.skip_one()?.is_none() {
                            return Err(cons.content_err(
                                "invalid name"
                            ))
                        }
                        Ok(())
                    })? { }
                    if empty_set {
                        return Err(cons.content_err(
                            "empty relative distinguished name"
                        ));
                    }
                    Ok(())
                })? { }
                if empty_sequence {
                    return Err(cons.content_err(
                        "empty distinguished name"
                    ))
                }
                Ok(())
            })
        }).map(Name)
    }

    /// Validate the name to conform with resource certificates.
    pub fn inspect_rpki(&self, strict: bool) -> Result<(), InspectionError> {
        fn inspect_strict<S: decode::Source>(
            cons: &mut decode::Constructed<S>
        ) -> Result<(), DecodeError<S::Error>> {
            let mut cn = false;
            let mut sn = false;
            cons.take_sequence(|cons| {
                while let Some(()) = cons.take_opt_set(|cons| {
                    while let Some(()) = cons.take_opt_sequence(|cons| {
                        let id = Oid::take_from(cons)?;
                        if id == oid::AT_COMMON_NAME {
                            if cn {
                                return Err(cons.content_err(
                                    "multiple common names"
                                ))
                            }
                            let _ = PrintableString::take_from(cons)?;
                            cn = true;
                        }
                        else if id == oid::AT_SERIAL_NUMBER {
                            if sn {
                                return Err(cons.content_err(
                                    "multiple serial numbers"
                                ))
                            }
                            let _ = PrintableString::take_from(cons)?;
                            sn = true;
                        }
                        Ok(())
                    })? { }
                    Ok(())
                })? {}
                Ok(())
            })?;
            // Common name is MUST.
            if cn {
                Ok(())
            }
            else {
                Err(cons.content_err("missing common name"))
            }
        }

        if strict {
            self.0.clone().decode(
                inspect_strict
            ).map_err(InspectionError::new)?
        }
        Ok(())
    }

    /// Validate the name to conform with BGPSec router certificates.
    pub fn inspect_router(
        &self, strict: bool
    ) -> Result<(), InspectionError> {
        fn inspect_strict<S: decode::Source>(
            cons: &mut decode::Constructed<S>
        ) -> Result<(), DecodeError<S::Error>> {
            let mut cn = false;
            let mut sn = false;
            cons.take_sequence(|cons| {
                while let Some(()) = cons.take_opt_set(|cons| {
                    while let Some(()) = cons.take_opt_sequence(|cons| {
                        let id = Oid::take_from(cons)?;
                        if id == oid::AT_COMMON_NAME {
                            if cn {
                                return Err(cons.content_err(
                                    "multiple common names"
                                ))
                            }
                            Name::skip_router_string(cons)?;
                            cn = true;
                        }
                        else if id == oid::AT_SERIAL_NUMBER {
                            if sn {
                                return Err(cons.content_err(
                                    "multiple serial numbers"
                                ))
                            }
                            Name::skip_router_string(cons)?;
                            sn = true;
                        }
                        Ok(())
                    })? { }
                    Ok(())
                })? {}
                Ok(())
            })?;
            // Common name is MUST.
            if cn {
                Ok(())
            }
            else {
                Err(cons.content_err("missing common name"))
            }
        }

        if strict {
            self.0.clone().decode(
                inspect_strict
            ).map_err(InspectionError::new)?
        }
        Ok(())
    }

    /// Skips a value if it is a PrintableString or UTF8String.
    fn skip_router_string<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(), DecodeError<S::Error>> {
        cons.take_value(|tag, content| {
            if tag == Tag::PRINTABLE_STRING {
                PrintableString::from_content(content).map(|_| ())
            }
            else if tag == Tag::UTF8_STRING {
                Utf8String::from_content(content).map(|_| ())
            }
            else {
                Err(content.content_err(
                    "unpermitted string variant in common name"
                ))
            }
        })
    }

    /// Derives a name from a public key info.
    ///
    /// Derives a name for use as issuer or subject from
    /// the public key of the issuer, or this certificate,
    /// respectively.
    ///
    /// This MUST be an X.500 Distinguished Name encoded as
    /// a PrintableString. There are no strong restrictions
    /// other than this because names in the RPKI are not
    /// considered important.
    ///
    /// Here we will use a simple strategy that guarantees
    /// uniqueness of these names, by generating them based
    /// on the hash of the public key. This is in line with
    /// the recommendations in RFC6487 sections 4.4, 4.5
    /// and 8.
    pub fn from_pub_key(key_info: &PublicKey) -> Self {
        let enc = key_info.key_identifier().into_hex();
        let values = encode::sequence(
            encode::set(
                encode::sequence((
                    oid::AT_COMMON_NAME.encode(),
                    enc.encode_as(Tag::PRINTABLE_STRING),
                ))
            )
        );
        Name(Captured::from_values(Mode::Der, values))
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        &self.0
    }
}

//--- PartialEq and Eq

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for Name {}

//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for Name {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let bytes = self.0.as_slice();
        let b64 = base64::Serde.encode(bytes);
        b64.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Name {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        let s = String::deserialize(deserializer)?;
        let decoded = base64::Serde.decode(&s).map_err(de::Error::custom)?;
        let bytes = bytes::Bytes::from(decoded);

        Mode::Der.decode(bytes, Name::take_from).map_err(de::Error::custom)
    }
}


//------------ Serial --------------------------------------------------------

/// A certificate serial number.
//
//  We encode the serial number in 20 octets left padded.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Serial([u8; 20]);

impl Serial {
    /// Creates a serial number from an octet slice.
    pub fn from_slice(s: &[u8]) -> Result<Self, SerialSliceError> {
        // Empty slice is malformed.
        if s.is_empty() {
            return Err(SerialSliceError::empty())
        }
        // We do not support more than 20 octets.
        if s.len() > 20 {
            return Err(SerialSliceError::long())
        }
        let mut res = <[u8; 20]>::default();
        res[20 - s.len()..].copy_from_slice(s);
        Self::from_array(res)
    }

    /// Creates a serial number from an array.
    pub fn from_array(array: [u8; 20]) -> Result<Self, SerialSliceError> {
        // The left-most bit must be 0 to indicate an unsigned integer.
        if array[0] & 0x80 != 0 {
            return Err(SerialSliceError::long())
        }
        Ok(Self(array))
    }

    /// Creates a random new serial number.
    pub fn random<S: Signer>(signer: &S) -> Result<Self, S::Error> {
        let mut res = <[u8; 20]>::default();
        signer.rand(&mut res)?;
        res[0] &= 0x7F;
        Ok(Self(res))
    }

    /// Creates a random serial number of a given length.
    ///
    /// The `len` argument provides the number of octets (!) of randomness
    /// the serial should have.
    ///
    /// # Panics
    ///
    /// The function panics if `len` is more than 20.
    pub fn short_random<S: Signer>(
        signer: &S,
        len: usize
    ) -> Result<Self, S::Error> {
        let mut res = <[u8; 20]>::default();
        signer.rand(&mut res[len..])?;
        res[0] &= 0x7F;
        Ok(Self(res))
    }

    /// Converts the serial number into a bytes array.
    pub fn into_array(self) -> [u8; 20] {
        self.0
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        Unsigned::take_from(cons).and_then(|s| {
            Self::from_slice(s.as_ref()).map_err(|err| cons.content_err(err))
        })
            
    }

    /// Returns the index of the first octet to encode.
    fn start(self) -> usize {
        let start = self.0.iter().enumerate().find_map(|(idx, &val)| {
            if val == 0 { None }
            else { Some(idx) }
        }).unwrap_or(19);
        if self.0[start] & 0x80 != 0 {
            start - 1
        }
        else {
            start
        }
    }

    fn checked_mul_u8(mut self, rhs: u8) -> Option<Self> {
        let mut overflow = 0;
        let rhs = u16::from(rhs);
        for i in (0..20_usize).rev() {
            let step = u16::from(self.0[i]) * rhs + overflow;
            self.0[i] = step as u8;
            overflow = step >> 8;
        }
        if overflow == 0 && self.0[0] & 0x80 == 0 {
            Some(self)
        }
        else {
            None
        }
    }

    fn checked_add_u8(mut self, rhs: u8) -> Option<Self> {
        let mut overflow = u16::from(rhs);
        for i in (0..20_usize).rev() {
            let step = u16::from(self.0[i]) + overflow;
            self.0[i] = step as u8;
            overflow = step >> 8;
        }
        if overflow == 0 && self.0[0] & 0x80 == 0 {
            Some(self)
        }
        else {
            None
        }
    }

    fn div_assign_u8(&mut self, rhs: u8) -> u8 {
        let mut step: u16 = 0;
        let rhs = u16::from(rhs);
        for i in 0..20 {
            step = step.overflowing_shl(8).0 + u16::from(self.0[i]);
            self.0[i] = (step / rhs) as u8;
            step %= rhs;
        }
        step as u8
    }

    fn is_zero(self) -> bool {
        self == Serial::default()
    }

    fn encode_dec(mut self, target: &mut [u8; 49]) -> &str {
        let mut len = 49;
        while !self.is_zero() {
            len -= 1;
            target[len] = self.div_assign_u8(10) + b'0';
        }
        unsafe { str::from_utf8_unchecked(&target[len..]) }
    }
}


//--- Default

// Derive would do the same thing, but let’s be explicit here.
#[allow(clippy::derivable_impls)]
impl Default for Serial {
    fn default() -> Self {
        Serial([0; 20])
    }
}


//--- From, TryFrom, and FromStr

impl TryFrom<[u8; 20]> for Serial {
    type Error = SerialSliceError;

    fn try_from(array: [u8; 20]) -> Result<Self, Self::Error> {
        Self::from_array(array)
    }
}

impl From<u128> for Serial {
    fn from(value: u128) -> Self {
        Self::from_slice(value.to_be_bytes().as_ref()).unwrap()
    }
}

impl From<u64> for Serial {
    fn from(value: u64) -> Self {
        Self::from_slice(value.to_be_bytes().as_ref()).unwrap()
    }
}

impl From<Serial> for [u8; 20] {
    fn from(serial: Serial) -> Self {
        serial.0
    }
}

impl From<Serial> for String {
    fn from(serial: Serial) -> String {
        let mut target = [0; 49];
        serial.encode_dec(&mut target).into()
    }
}

impl FromStr for Serial {
    type Err = RepresentationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut res = Serial::default();
        for ch in value.chars() {
            match ch {
                '0' ..= '9' => {
                    res = match res.checked_mul_u8(10) {
                        Some(res) => {
                            match res.checked_add_u8((ch as u8) - b'0') {
                                Some(res) => res,
                                None => return Err(RepresentationError)
                            }
                        }
                        None => return Err(RepresentationError)
                    }
                }
                _ => return Err(RepresentationError)
            }
        }
        Ok(res)
    }
}


//--- Display and Debug

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut target = [0; 49];
        write!(f, "{}", self.encode_dec(&mut target))
    }
}

impl fmt::Debug for Serial {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Serial({self})")
    }
}


//--- PrimitiveContent

impl PrimitiveContent for Serial {
    const TAG: Tag = Tag::INTEGER;

    fn encoded_len(&self, _mode: Mode) -> usize {
        20 - self.start()
    }

    fn write_encoded<W: io::Write>(
        &self,
        _mode: Mode,
        target: &mut W
    ) -> Result<(), io::Error> {
        target.write_all(&self.0[self.start()..])
    }
}


//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for Serial {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error> {
        let mut target = [0; 49];
        self.encode_dec(&mut target).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Serial {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct SerialVisitor;

        impl serde::de::Visitor<'_> for SerialVisitor {
            type Value = Serial;

            fn expecting(
                &self, formatter: &mut fmt::Formatter
            ) -> fmt::Result {
                write!(formatter, "a string containing a serial number")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where E: serde::de::Error {
                Serial::from_str(s).map_err(serde::de::Error::custom)
            }

            fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
            where E: serde::de::Error {
                Serial::from_str(&s).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(SerialVisitor)
    }
}


//------------ SignedData ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct SignedData<Alg = RpkiSignatureAlgorithm> {
    data: Captured,
    signature: Signature<Alg>,
}

impl<Alg> SignedData<Alg> {
    pub fn new(data: Captured, signature: Signature<Alg>) -> Self {
        Self { data, signature }
    }

    pub fn data(&self) -> &Captured {
        &self.data
    }

    pub fn signature(&self) -> &Signature<Alg> {
        &self.signature
    }
}

impl<Alg: SignatureAlgorithm> SignedData<Alg> {
    pub fn decode<S: IntoSource>(
        source: S
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::from_constructed)
    }

    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        Ok(SignedData {
            data: cons.capture_one()?,
            signature: Signature::new(
                Alg::x509_take_from(cons)?,
                BitString::take_from(cons)?.octet_bytes()
            )
        })
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            &self.data,
            self.signature.algorithm().x509_encode(),
            SignatureValueContent(self).encode(),
        ))
    }

    pub fn verify_signature(
        &self,
        public_key: &PublicKey
    ) -> Result<(), SignatureVerificationError> {
        public_key.verify(self.data.as_ref(), &self.signature)
    }
}


//--- PartialEq and Eq

impl PartialEq for SignedData {
    fn eq(&self, other: &Self) -> bool {
        self.data.as_slice() == other.data.as_slice() &&
            self.signature == other.signature
    }
}

impl Eq for SignedData {}


#[derive(Clone, Copy, Debug)]
pub struct SignatureValueContent<'a, Alg>(&'a SignedData<Alg>);

impl<Alg> PrimitiveContent for SignatureValueContent<'_, Alg> {
    const TAG: Tag = Tag::BIT_STRING;

    fn encoded_len(&self, _: Mode) -> usize {
        self.0.signature.value().len() + 1
    }

    fn write_encoded<W: io::Write>(
        &self,
        _: Mode,
        target: &mut W
    ) -> Result<(), io::Error> {
        target.write_all(&[0u8])?;
        target.write_all(self.0.signature.value().as_ref())
    }
}


//------------ Time ----------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Time(DateTime<Utc>);

impl Time {
    pub fn new(dt: DateTime<Utc>) -> Self {
        Time(dt)
    }

    pub fn now() -> Self {
        Self::new(Utc::now())
    }

    pub fn five_minutes_ago() -> Self {
        Self::now() - TimeDelta::try_minutes(5).unwrap()
    }

    pub fn five_minutes_from_now() -> Self {
        Self::now() + TimeDelta::try_minutes(5).unwrap()
    }

    pub fn tomorrow() -> Self {
        Self::now() + TimeDelta::try_days(1).unwrap()
    }

    pub fn next_week() -> Self {
        Self::now() + TimeDelta::try_weeks(1).unwrap()
    }

    pub fn next_year() -> Self {
        Self::years_from_now(1)
    }

    /// Adds number of years to the given date.
    ///
    /// If the given date happens to be a leap date,
    /// the resulting date would be normalized to February 28.
    ///
    /// This is the case even if the resulting year is also a leap year.
    pub fn years_from_date(years: i32, date: DateTime<Utc>) -> Self {

        let year = date.year();
        let month = date.month();

        let day = {
            if date.day() == 29 && month == 2 { 28 } else { date.day() }
        };

        let hour = date.hour();
        let min = date.minute();
        let sec = std::cmp::min(date.second(), 59);

        Self::utc(year + years, month, day, hour, min, sec)
    }

    /// Adds given years to the current date.
    ///
    /// If current date happens to be a leap date,
    /// the resulting date would be normalized to February 28.
    ///
    /// This is the case even if the resulting year is also a leap year.
    pub fn years_from_now(years: i32) -> Self {
        Self::years_from_date(years, Utc::now())
    }

    #[allow(deprecated)]
    pub fn utc(
        year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32
    ) -> Self {
        Time(Utc.ymd(year, month, day).and_hms(hour, min, sec))
    }

    #[deprecated(since="0.6.0", note="Use self.timestamp instead.")]
    pub fn to_binary_time(self) -> i64 {
        self.0.timestamp()
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_primitive(|tag, prim| {
            match tag {
                Tag::UTC_TIME => {
                    // RFC 5280 requires the format YYMMDDHHMMSSZ
                    let year = read_two_char(prim)? as i32;
                    let year = if year >= 50 { year + 1900 }
                               else { year + 2000 };
                    let res = (
                        year,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                    );
                    if prim.take_u8()? != b'Z' {
                        return Err(prim.content_err(
                            "malformed time value"
                        ))
                    }
                    Self::from_parts(res).map_err(|err| prim.content_err(err))
                }
                Tag::GENERALIZED_TIME => {
                    // RFC 5280 requires the format YYYYMMDDHHMMSSZ
                    let res = (
                        read_four_char(prim)? as i32,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                        read_two_char(prim)?,
                    );
                    if prim.take_u8()? != b'Z' {
                        return Err(prim.content_err(
                            "malformed time value"
                        ))
                    }
                    Self::from_parts(res).map_err(|err| prim.content_err(err))
                }
                _ => {
                    Err(prim.content_err(
                        "malformed time value"
                    ))
                }
            }
        })
    }

    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        let res = cons.take_opt_primitive_if(Tag::UTC_TIME, |prim| {
            let year = read_two_char(prim)? as i32;
            let year = if year >= 50 { year + 1900 }
                       else { year + 2000 };
            let res = (
                year,
                read_two_char(prim)?,
                read_two_char(prim)?,
                read_two_char(prim)?,
                read_two_char(prim)?,
                read_two_char(prim)?,
            );
            if prim.take_u8()? != b'Z' {
                return Err(prim.content_err(
                    "malformed time value"
                ))
            }
            Self::from_parts(res).map_err(|err| prim.content_err(err))
        })?;
        if let Some(res) = res {
            return Ok(Some(res))
        }
        cons.take_opt_primitive_if(Tag::GENERALIZED_TIME, |prim| {
            let res = (
                read_four_char(prim)? as i32,
                read_two_char(prim)?,
                read_two_char(prim)?,
                read_two_char(prim)?,
                read_two_char(prim)?,
                read_two_char(prim)?,
            );
            if prim.take_u8()? != b'Z' {
                return Err(prim.content_err(
                    "malformed time value"
                ))
            }
            Self::from_parts(res).map_err(|err| prim.content_err(err))
        })
    }

    #[allow(deprecated)]
    fn from_parts(
        parts: (i32, u32, u32, u32, u32, u32)
    ) -> Result<Self, ContentError> {
        Ok(Time(match Utc.ymd_opt(parts.0, parts.1, parts.2) {
            LocalResult::Single(dt) => {
                match dt.and_hms_opt(parts.3, parts.4, parts.5) {
                    Some(dt) => dt,
                    None => {
                        return Err(ContentError::from_static(
                            "malformed time value"
                        ))
                    }
                }
            }
            _ => return Err(ContentError::from_static("malformed time value"))
        }))
    }

    pub fn verify_not_before(
        &self,
        now: Time
    ) -> Result<(), ValidityPeriodError> {
        if now.0 < self.0 {
            Err(ValidityPeriodError::too_new())
        }
        else {
            Ok(())
        }
    }

    pub fn verify_not_after(
        &self,
        now: Time
    ) -> Result<(), ValidityPeriodError> {
        if now.0 > self.0 {
            Err(ValidityPeriodError::too_old())
        }
        else {
            Ok(())
        }
    }

    pub fn encode_utc_time(self) -> impl encode::Values {
        UtcTime(self).encode()
    }

    pub fn encode_generalized_time(self) -> impl encode::Values {
        GeneralizedTime(self).encode()
    }

    pub fn encode_varied(self) -> impl encode::Values {
        if self.year() < 1950 || self.year() > 2049 {
            (None, Some(self.encode_generalized_time()))
        }
        else {
            (Some(self.encode_utc_time()), None)
        }
    }
}


//--- Deref and AsRef

impl ops::Deref for Time {
    type Target = DateTime<Utc>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<DateTime<Utc>> for Time {
    fn as_ref(&self) -> &DateTime<Utc> {
        &self.0
    }
}


//--- From and FromStr

impl From<DateTime<Utc>> for Time {
    fn from(time: DateTime<Utc>) -> Self {
        Time(time)
    }
}

impl From<Time> for DateTime<Utc> {
    fn from(time: Time) -> Self {
        time.0
    }
}

impl From<SystemTime> for Time {
    fn from(time: SystemTime) -> Self {
        Time(time.into())
    }
}

impl From<Time> for SystemTime {
    fn from(time: Time) -> Self {
        time.0.into()
    }
}

impl FromStr for Time {
    type Err = chrono::format::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FromStr::from_str(s).map(Time)
    }
}


//--- Add

impl ops::Add<TimeDelta> for Time {
    type Output = Self;

    fn add(self, duration: TimeDelta) -> Self::Output {
        Self::new(self.0 + duration)
    }
}


//--- Sub

impl ops::Sub<TimeDelta> for Time {
    type Output = Self;

    fn sub(self, duration: TimeDelta) -> Self::Output {
        Self::new(self.0 - duration)
    }
}


fn read_two_char<S: decode::Source>(
    source: &mut S
) -> Result<u32, DecodeError<S::Error>> {
    let mut s = [0u8; 2];
    s[0] = source.take_u8()?;
    s[1] = source.take_u8()?;
    let s = match str::from_utf8(&s[..]) {
        Ok(s) => s,
        Err(_err) => {
            return Err(source.content_err("malformed time value"))
        }
    };
    u32::from_str(s).map_err(|_err| {
        source.content_err("malformed time value")
    })
}


fn read_four_char<S: decode::Source>(
    source: &mut S
) -> Result<u32, DecodeError<S::Error>> {
    let mut s = [0u8; 4];
    s[0] = source.take_u8()?;
    s[1] = source.take_u8()?;
    s[2] = source.take_u8()?;
    s[3] = source.take_u8()?;
    let s = match str::from_utf8(&s[..]) {
        Ok(s) => s,
        Err(_err) => {
            return Err(source.content_err("malformed time value"))
        }
    };
    u32::from_str(s).map_err(|_err| {
        source.content_err("malformed time value")
    })
}


//------------ AsUtcTime -----------------------------------------------------

pub struct UtcTime(Time);

impl PrimitiveContent for UtcTime {
    const TAG: Tag = Tag::UTC_TIME;

    fn encoded_len(&self, _: Mode) -> usize {
        13 // yyMMddhhmmssZ
    }

    fn write_encoded<W: io::Write>(
        &self, _: Mode, target: &mut W
    ) -> Result<(), io::Error> {
        write!(
            target, "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            self.0.year() % 100, self.0.month(), self.0.day(),
            self.0.hour(), self.0.minute(), self.0.second()
        )
    }
}


//------------ AsGeneralizedTime ---------------------------------------------

pub struct GeneralizedTime(Time);

impl PrimitiveContent for GeneralizedTime {
    const TAG: Tag = Tag::GENERALIZED_TIME;

    fn encoded_len(&self, _: Mode) -> usize {
        15 // yyyyMMddhhmmssZ
    }

    fn write_encoded<W: io::Write>(
        &self, _: Mode, target: &mut W
    ) -> Result<(), io::Error> {
        write!(
            target, "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            self.0.year(), self.0.month(), self.0.day(),
            self.0.hour(), self.0.minute(), self.0.second()
        )
    }
}


//------------ Validity ------------------------------------------------------

#[derive(Clone, Debug, Copy, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Validity {
    not_before: Time,
    not_after: Time,
}

impl Validity {
    pub fn new(not_before: Time, not_after: Time) -> Self {
        Validity { not_before, not_after }
    }

    pub fn from_duration(duration: TimeDelta) -> Self {
        let not_before = Time::now();
        let not_after = Time::new(Utc::now() + duration);
        if not_before < not_after {
            Validity::new(not_before, not_after)
        }
        else {
            Validity::new(not_after, not_before)
        }
    }

    pub fn from_secs(secs: i64) -> Self {
        Self::from_duration(TimeDelta::try_seconds(secs).unwrap())
    }

    pub fn not_before(self) -> Time {
        self.not_before
    }

    pub fn not_after(self) -> Time {
        self.not_after
    }

    pub fn trim(self, other: Self) -> Self {
        Validity::new(
            max(self.not_before, other.not_before),
            min(self.not_after, other.not_after)
        )
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            Ok(Validity::new(
                Time::take_from(cons)?,
                Time::take_from(cons)?,
            ))
        })
    }

    pub fn verify(self) -> Result<(), ValidityPeriodError> {
        self.verify_at(Time::now())
    }

    pub fn verify_at(self, now: Time) -> Result<(), ValidityPeriodError> {
        self.not_before.verify_not_before(now)?;
        self.not_after.verify_not_after(now)?;
        Ok(())
    }

    pub fn encode(self) -> impl encode::Values {
        encode::sequence((
            self.not_before.encode_varied(),
            self.not_after.encode_varied(),
        ))
    }
}


//------------ SerialSliceError ----------------------------------------------

/// A serial number’s slice is empty.
#[derive(Clone, Copy, Debug)]
pub struct SerialSliceError(SerialSliceErrorKind);

#[derive(Clone, Copy, Debug)]
enum SerialSliceErrorKind {
    Empty,
    Long,
}

impl SerialSliceError {
    fn empty() -> Self {
        SerialSliceError(SerialSliceErrorKind::Empty)
    }

    fn long() -> Self {
        SerialSliceError(SerialSliceErrorKind::Long)
    }
}

impl From<SerialSliceError> for ContentError {
    fn from(err: SerialSliceError) -> Self {
        ContentError::from_static(match err.0 {
            SerialSliceErrorKind::Empty => "empty serial number",
            SerialSliceErrorKind::Long => "serial number longer than 20 bytes"
        })
    }
}

impl fmt::Display for SerialSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(
            match self.0 {
                SerialSliceErrorKind::Empty => "empty serial number",
                SerialSliceErrorKind::Long => {
                    "serial number longer than 20 bytes"
                }
            }
        )
    }
}

impl error::Error for SerialSliceError { }


//------------ RepresentationError -------------------------------------------

/// A source value is not correctly formated for converting into a value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepresentationError;

impl fmt::Display for RepresentationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("wrong representation format")
    }
}

impl error::Error for RepresentationError { }


//------------ ValidityPeriodError -------------------------------------------

/// An object is outside of its period of validity.
#[derive(Clone, Copy, Debug)]
pub struct ValidityPeriodError {
    /// Is the object too new?
    ///
    /// It is too old otherwise.
    too_new: bool,
}

impl ValidityPeriodError {
    fn too_new() -> Self {
        ValidityPeriodError { too_new: true }
    }

    fn too_old() -> Self {
        ValidityPeriodError { too_new: false }
    }
}

impl From<ValidityPeriodError> for VerificationError {
    fn from(err: ValidityPeriodError) -> Self {
        VerificationError::new(
            if err.too_new {
                "certificate is not yet valid"
            }
            else {
                "certificate has expired"
            }
        )
    }
}

impl fmt::Display for ValidityPeriodError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(
            if self.too_new {
                "object is not yet valid"
            }
            else {
                "object has expired"
            }
        )
    }
}

impl error::Error for ValidityPeriodError { }


//------------ Testing. One. Two. Three --------------------------------------

#[cfg(test)]
mod test {
    use super::*;
    use bcder::decode::Constructed;
    use bcder::encode::Values;

    #[test]
    fn signed_data_decode_then_encode() {
        let data = include_bytes!("../../test-data/repository/ta.cer");
        let obj = SignedData::<RpkiSignatureAlgorithm>::decode(
            data.as_ref()
        ).unwrap();
        let mut encoded = Vec::new();
        obj.encode_ref().write_encoded(Mode::Der, &mut encoded).unwrap();
        assert_eq!(data.len(), encoded.len());
        assert_eq!(data.as_ref(), AsRef::<[u8]>::as_ref(&encoded));
    }

    #[test]
    fn serial_from_slice() {
        assert_eq!(
            Serial::from_slice(b"\x01\x02\x03").unwrap(),
            Serial([0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1,2,3])
        );
        assert_eq!(
            Serial::from(0x10203u64),
            Serial([0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1,2,3])
        );
    }

    #[test]
    fn serial_take_from() {
        assert_eq!(
            Constructed::decode(
                b"\x02\x03\x01\x02\x03".as_ref(),
                Mode::Der,
                Serial::take_from
            ).unwrap(),
            Serial([0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1,2,3])
        );
    }

    #[test]
    fn serial_from_str() {
        assert_eq!(
            Serial::from_str("383822").unwrap(),
            Serial::from_slice(b"\x05\xdb\x4e").unwrap()
        );
        assert_eq!(
            Serial::from_str("000000383822").unwrap(),
            Serial::from_slice(b"\x05\xdb\x4e").unwrap()
        );
        assert_eq!(
            Serial::from_str("0").unwrap(),
            Serial::from_slice(b"\0").unwrap()
        );
        assert_eq!(
            Serial::from_str("17085962136030120322").unwrap(),
            Serial::from_slice(b"\xed\x1d\x88\x09\x93\xd9\x89\x82").unwrap()
        );
        assert!(
            Serial::from_str(
                "1461501637330902918203684832716283019655932542975"
            ).is_err()
        );
        assert_eq!(
            Serial::from_str(
                "000730750818665451459101842416358141509827966271487"
            ).unwrap(),
            Serial::from_slice(
                b"\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
                  \xff\xff\xff\xff\xff\xff\xff\xff\xff"
            ).unwrap()
        );
        assert!(
            Serial::from_str(
                "730750818665451459101842416358141509827966271488"
            ).is_err()
        );
        assert!(Serial::from_str("hello").is_err());
        assert_eq!(Serial::from_str("0").unwrap(), Serial::default());
    }

    #[test]
    fn string_from_serial() {
        assert_eq!(
            String::from(Serial::from_slice(b"\x05\xdb\x4e").unwrap()),
            String::from("383822"),
        );
    }

    #[test]
    fn serial_encode() {
        let mut target = Vec::new();
        Serial([0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1,2,3])
            .encode().write_encoded(Mode::Der, &mut target).unwrap();
        assert_eq!(
            target,
            b"\x02\x03\x01\x02\x03"
        );

        let mut target = Vec::new();
        Serial([0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0x81,2,3])
            .encode().write_encoded(Mode::Der, &mut target).unwrap();
        assert_eq!(
            target,
            b"\x02\x04\x00\x81\x02\x03"
        );
    }

    #[test]
    fn next_year() {
        let now = Utc.with_ymd_and_hms(
            2014, 10, 21, 16, 39, 57
        ).unwrap();
        let future = Time::years_from_date(1, now);

        assert_eq!(future.year(), 2015);
        assert_eq!(future.month(), 10);
        assert_eq!(future.day(), 21);
        assert_eq!(future.hour(), 16);
        assert_eq!(future.minute(), 39);
        assert_eq!(future.second(), 57);
    }

    #[test]
    fn next_year_from_leap() {
        let now = Utc.with_ymd_and_hms(
            2020, 2, 29, 16, 39, 57
        ).unwrap();
        let future = Time::years_from_date(10, now);

        assert_eq!(future.year(), 2030);
        assert_eq!(future.month(), 2);
        assert_eq!(future.day(), 28);
        assert_eq!(future.hour(), 16);
        assert_eq!(future.minute(), 39);
        assert_eq!(future.second(), 57);
    }
}

