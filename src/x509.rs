//! Types common to all things X.509.

use std::{fmt, io, ops, str};
use std::cmp::{min, max};
use std::str::FromStr;
use std::time::SystemTime;
use bcder::{decode, encode};
use bcder::{
    BitString, Captured, ConstOid, Mode, OctetString, Oid, Tag, Unsigned, xerr
};
use bcder::string::PrintableString;
use bcder::decode::Source;
use bcder::encode::PrimitiveContent;
use chrono::{
    Datelike, DateTime, Duration, LocalResult, Timelike, TimeZone, Utc
};
use derive_more::Display;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::crypto::{
    PublicKey, Signature, SignatureAlgorithm, Signer, VerificationError
};
use crate::oid;


//------------ Functions -----------------------------------------------------

/// Updates an optional value once.
///
/// If another update is tried, returns a malformed error instead.
pub fn update_once<F, T, E>(opt: &mut Option<T>, op: F) -> Result<(), E>
where F: FnOnce() -> Result<T, E>, E: From<decode::Error> {
    if opt.is_some() {
        Err(decode::Malformed.into())
    }
    else {
        *opt = Some(op()?);
        Ok(())
    }
}

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
    ) -> Result<Self, S::Err> {
        cons.capture(|cons| {
            cons.take_sequence(|cons| { // RDNSequence
                while let Some(()) = cons.take_opt_set(|cons| {
                    while let Some(()) = cons.take_opt_sequence(|cons| {
                        Oid::skip_in(cons)?;
                        if cons.skip_one()?.is_none() {
                            xerr!(
                                return Err(decode::Error::Malformed.into())
                            );
                        }
                        Ok(())
                    })? { }
                    Ok(())
                })? { }
                Ok(())
            })
        }).map(Name)
    }

    pub fn validate_rpki(&self, strict: bool) -> Result<(), ValidationError> {
        if strict {
            self.0.clone().decode(|cons| {
                let mut cn = false;
                let mut sn = false;
                cons.take_sequence(|cons| {
                    while let Some(()) = cons.take_opt_set(|cons| {
                        while let Some(()) = cons.take_opt_sequence(|cons| {
                            let id = Oid::take_from(cons)?;
                            if id == oid::AT_COMMON_NAME {
                                if cn {
                                    xerr!(
                                        return Err(decode::Error::Malformed)
                                    )
                                }
                                let _ = PrintableString::take_from(cons)?;
                                cn = true;
                            }
                            else if id == oid::AT_SERIAL_NUMBER {
                                if sn {
                                    xerr!(
                                        return Err(decode::Error::Malformed)
                                    )
                                }
                                let _ = PrintableString::take_from(cons)?;
                                sn = true;
                            }
                            Ok(())
                        })? { }
                        Ok(())
                    })? {}
                    Ok(())
                })
            })?
        }
        Ok(())
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

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        &self.0
    }
}


//------------ Serial --------------------------------------------------------

/// A certificate serial number.
//
//  We encode the serial number in 20 octets left padded.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Serial([u8; 20]);

impl Serial {
    /// Creates a serial number from a octet slice.
    pub fn from_slice(s: &[u8]) -> Result<Self, decode::Error> {
        // Empty slice is malformed.
        if s.is_empty() {
            return Err(decode::Malformed)
        }
        // We do not support more than 20 octets or exactly 20 octets if the
        // sign bit is set.
        if s.len() > 20 || (s.len() == 20 && s[0] & 0x80 != 0) {
            return Err(decode::Unimplemented)
        }
        let mut res = <[u8; 20]>::default();
        res[20 - s.len()..].copy_from_slice(s);
        Ok(Self(res))
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

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        Unsigned::take_from(cons).and_then(|s| {
            Self::from_slice(s.as_ref()).map_err(Into::into)
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

impl Default for Serial {
    fn default() -> Self {
        // derive would probably do the same thing, but let’s be explicit
        // here.
        Serial([0; 20])
    }
}


//--- From and FromStr

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
        write!(f, "Serial({})", self)
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

impl Serialize for Serial {
    fn serialize<S: Serializer>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error> {
        let mut target = [0; 49];
        self.encode_dec(&mut target).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Serial {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        deserializer.deserialize_str(SerialVisitor)
    }
}


//------------ SignedData ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct SignedData {
    data: Captured,
    signature: Signature,
}

impl SignedData {
    pub fn new(data: Captured, signature: Signature) -> Self {
        Self { data, signature }
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}


impl SignedData {
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        Ok(SignedData {
            data: cons.capture_one()?,
            signature: Signature::new(
                SignatureAlgorithm::x509_take_from(cons)?,
                BitString::take_from(cons)?.octet_bytes()
            )
        })
    }

    pub fn data(&self) -> &Captured {
        &self.data
    }

    pub fn verify_signature(
        &self,
        public_key: &PublicKey
    ) -> Result<(), ValidationError> {
        public_key.verify(
            self.data.as_ref(),
            &self.signature
        ).map_err(Into::into)
    }

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            &self.data,
            self.signature.algorithm().x509_encode(),
            SignatureValueContent(self).encode(),
        ))
    }
}


#[derive(Clone, Copy, Debug)]
pub struct SignatureValueContent<'a>(&'a SignedData);

impl<'a> PrimitiveContent for SignatureValueContent<'a> {
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

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd,
    Serialize
)]
pub struct Time(DateTime<Utc>);

impl Time {
    pub fn new(dt: DateTime<Utc>) -> Self {
        Time(dt)
    }

    pub fn now() -> Self {
        Self::new(Utc::now())
    }

    pub fn five_minutes_ago() -> Self {
        Self::now() - Duration::minutes(5)
    }

    pub fn tomorrow() -> Self {
        Self::now() + Duration::days(1)
    }

    pub fn next_week() -> Self {
        Self::now() + Duration::weeks(1)
    }

    pub fn next_year() -> Self {
        Self::years_from_now(1)
    }

    pub fn next_year_from_date(years: i32, date: DateTime<Utc>) -> Self {
        let future_now = date + Duration::days(i64::from(365 * years));

        let year = future_now.year();
        let month = future_now.month();
        let day = future_now.day();
        let hour = future_now.hour();
        let min = future_now.minute();
        let sec = future_now.second();

        Self::utc(year, month, day, hour, min, sec)
    }

    pub fn years_from_now(years: i32) -> Self {
        Self::next_year_from_date(years, Utc::now())
    }

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
    ) -> Result<Self, S::Err> {
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
                        return Err(decode::Malformed.into())
                    }
                    Self::from_parts(res).map_err(Into::into)
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
                        return Err(decode::Malformed.into())
                    }
                    Self::from_parts(res).map_err(Into::into)
                }
                _ => {
                    xerr!(Err(decode::Malformed.into()))
                }
            }
        })
    }

    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
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
                return Err(decode::Malformed.into())
            }
            Self::from_parts(res).map_err(Into::into)
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
                return Err(decode::Malformed.into())
            }
            Self::from_parts(res).map_err(Into::into)
        })
    }

    fn from_parts(
        parts: (i32, u32, u32, u32, u32, u32)
    ) -> Result<Self, decode::Error> {
        Ok(Time(match Utc.ymd_opt(parts.0, parts.1, parts.2) {
            LocalResult::Single(dt) => {
                match dt.and_hms_opt(parts.3, parts.4, parts.5) {
                    Some(dt) => dt,
                    None => return Err(decode::Malformed),
                }
            }
            _ => return Err(decode::Malformed)
        }))
    }

    pub fn validate_not_before(
        &self,
        now: Time
    ) -> Result<(), ValidationError> {
        if now.0 < self.0 {
            Err(ValidationError)
        }
        else {
            Ok(())
        }
    }

    pub fn validate_not_after(
        &self,
        now: Time
    ) -> Result<(), ValidationError> {
        if now.0 > self.0 {
            Err(ValidationError)
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

impl ops::Add<Duration> for Time {
    type Output = Self;

    fn add(self, duration: Duration) -> Self::Output {
        Self::new(self.0 + duration)
    }
}


//--- Sub

impl ops::Sub<Duration> for Time {
    type Output = Self;

    fn sub(self, duration: Duration) -> Self::Output {
        Self::new(self.0 - duration)
    }
}


fn read_two_char<S: decode::Source>(source: &mut S) -> Result<u32, S::Err> {
    let mut s = [0u8; 2];
    s[0] = source.take_u8()?;
    s[1] = source.take_u8()?;
    let s = match str::from_utf8(&s[..]) {
        Ok(s) => s,
        Err(_err) => {
            xerr!(return Err(decode::Malformed.into()))
        }
    };
    u32::from_str(s).map_err(|_err| {
        xerr!(decode::Malformed.into())
    })
}


fn read_four_char<S: decode::Source>(source: &mut S) -> Result<u32, S::Err> {
    let mut s = [0u8; 4];
    s[0] = source.take_u8()?;
    s[1] = source.take_u8()?;
    s[2] = source.take_u8()?;
    s[3] = source.take_u8()?;
    let s = match str::from_utf8(&s[..]) {
        Ok(s) => s,
        Err(_err) => {
            xerr!(return Err(decode::Malformed.into()))
        }
    };
    u32::from_str(s).map_err(|_err| {
        xerr!(decode::Malformed.into())
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

#[derive(Clone, Debug, Deserialize, Copy, Eq, Hash, PartialEq, Serialize)]
pub struct Validity {
    not_before: Time,
    not_after: Time,
}

impl Validity {
    pub fn new(not_before: Time, not_after: Time) -> Self {
        Validity { not_before, not_after }
    }

    pub fn from_duration(duration: Duration) -> Self {
        let not_before = Time::now();
        let not_after = Time::new(Utc::now() + duration);
        if not_before < not_after {
            Validity { not_before, not_after }
        }
        else {
            Validity { not_after, not_before }
        }
    }

    pub fn from_secs(secs: i64) -> Self {
        Self::from_duration(Duration::seconds(secs))
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
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            Ok(Validity::new(
                Time::take_from(cons)?,
                Time::take_from(cons)?,
            ))
        })
    }

    pub fn validate(self) -> Result<(), ValidationError> {
        self.validate_at(Time::now())
    }

    pub fn validate_at(self, now: Time) -> Result<(), ValidationError> {
        self.not_before.validate_not_before(now)?;
        self.not_after.validate_not_after(now)?;
        Ok(())
    }

    pub fn encode(self) -> impl encode::Values {
        encode::sequence((
            self.not_before.encode_varied(),
            self.not_after.encode_varied(),
        ))
    }
}


//------------ SerialVisitor -------------------------------------------------

/// Private helper class for deserializing serials.
struct SerialVisitor;

impl<'de> de::Visitor<'de> for SerialVisitor {
    type Value = Serial;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a string containing a serial number")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where E: de::Error {
        Serial::from_str(s).map_err(de::Error::custom)
    }

    fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
    where E: de::Error {
        Serial::from_str(&s).map_err(de::Error::custom)
    }
}


//------------ RepresentationError -------------------------------------------

/// A source value is not correctly formated for converting into a value.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[display(fmt="wrong representation format")]
pub struct RepresentationError;


//------------ ValidationError -----------------------------------------------

#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[display(fmt="validation error")]
pub struct ValidationError;

impl From<decode::Error> for ValidationError {
    fn from(_: decode::Error) -> ValidationError {
        ValidationError
    }
}

impl From<VerificationError> for ValidationError {
    fn from(_: VerificationError) -> ValidationError {
        ValidationError
    }
}


//------------ Testing. One. Two. Three --------------------------------------

#[cfg(test)]
mod test {
    use super::*;
    use bcder::decode::Constructed;
    use bcder::encode::Values;
    use unwrap::unwrap;

    #[test]
    fn signed_data_decode_then_encode() {
        let data = include_bytes!("../test-data/ta.cer");
        let obj = SignedData::decode(data.as_ref()).unwrap();
        let mut encoded = Vec::new();
        obj.encode_ref().write_encoded(Mode::Der, &mut encoded).unwrap();
        assert_eq!(data.len(), encoded.len());
        assert_eq!(data.as_ref(), AsRef::<[u8]>::as_ref(&encoded));
    }

    #[test]
    fn serial_from_slice() {
        assert_eq!(
            unwrap!(Serial::from_slice(b"\x01\x02\x03")),
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
            unwrap!(
                Constructed::decode(
                    b"\x02\x03\x01\x02\x03".as_ref(),
                    Mode::Der,
                    Serial::take_from
                )
            ),
            Serial([0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1,2,3])
        );
    }

    #[test]
    fn serial_from_str() {
        assert_eq!(
            unwrap!(Serial::from_str("383822")),
            unwrap!(Serial::from_slice(b"\x05\xdb\x4e"))
        );
        assert_eq!(
            unwrap!(Serial::from_str("000000383822")),
            unwrap!(Serial::from_slice(b"\x05\xdb\x4e"))
        );
        assert_eq!(
            unwrap!(Serial::from_str("0")),
            unwrap!(Serial::from_slice(b"\0"))
        );
        assert_eq!(
            unwrap!(Serial::from_str("17085962136030120322")),
            unwrap!(Serial::from_slice(b"\xed\x1d\x88\x09\x93\xd9\x89\x82"))
        );
        assert!(
            Serial::from_str(
                "1461501637330902918203684832716283019655932542975"
            ).is_err()
        );
        assert_eq!(
            unwrap!(Serial::from_str(
                "000730750818665451459101842416358141509827966271487"
            )),
            unwrap!(Serial::from_slice(
                b"\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
                  \xff\xff\xff\xff\xff\xff\xff\xff\xff"
            ))
        );
        assert!(
            Serial::from_str(
                "730750818665451459101842416358141509827966271488"
            ).is_err()
        );
        assert!(Serial::from_str("hello").is_err());
        assert_eq!(unwrap!(Serial::from_str("0")), Serial::default());
    }

    #[test]
    fn string_from_serial() {
        assert_eq!(
            String::from(unwrap!(Serial::from_slice(b"\x05\xdb\x4e"))),
            String::from("383822"),
        );
    }

    #[test]
    fn serial_encode() {
        let mut target = Vec::new();
        unwrap!(
            Serial([0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1,2,3])
                .encode().write_encoded(Mode::Der, &mut target)
        );
        assert_eq!(
            target,
            b"\x02\x03\x01\x02\x03"
        );

        let mut target = Vec::new();
        unwrap!(
            Serial([0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0x81,2,3])
                .encode().write_encoded(Mode::Der, &mut target)
        );
        assert_eq!(
            target,
            b"\x02\x04\x00\x81\x02\x03"
        );
    }

    #[test]
    fn next_year() {
        let now = DateTime::parse_from_rfc3339("2014-10-21T16:39:57-00:00").unwrap();
        let future = Time::next_year_from_date(1, DateTime::from_utc(now.naive_utc(), Utc));

        assert_eq!(
            future.year(),
            2015
        );
        assert_eq!(
            future.month(),
            10
        );
        assert_eq!(
            future.day(),
            21
        );
        assert_eq!(
            future.hour(),
            16
        );
        assert_eq!(
            future.minute(),
            39
        );
        assert_eq!(
            future.second(),
            57
        );
    }

    #[test]
    fn next_year_from_leap() {
        let now = DateTime::parse_from_rfc3339("2020-02-29T16:39:57-00:00").unwrap();
        let future = Time::next_year_from_date(1, DateTime::from_utc(now.naive_utc(), Utc));

        assert_eq!(
            future.year(),
            2021
        );
        assert_eq!(
            future.month(),
            2
        );
        assert_eq!(
            future.day(),
            28
        );
        assert_eq!(
            future.hour(),
            16
        );
        assert_eq!(
            future.minute(),
            39
        );
        assert_eq!(
            future.second(),
            57
        );
    }
}

