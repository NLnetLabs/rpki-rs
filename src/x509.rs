//! Types common to all things X.509.

use std::str;
use std::str::FromStr;
use ber::{decode, encode};
use ber::{BitString, Captured, Mode, Tag};
use ber::cstring::PrintableString;
use ber::decode::Source;
use ber::encode::PrimitiveContent;
use cert::SubjectPublicKeyInfo;
use chrono::{Datelike, DateTime, LocalResult, Timelike, TimeZone, Utc};
use hex;
use super::time;
use signing::SignatureAlgorithm;
use std::io;
use ber::Oid;
use std::result::Result::Err;


//------------ Functions -----------------------------------------------------

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


//------------ Name ----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Name(Captured);

impl Name {
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
                            if id == oid::ID_AT_COMMON_NAME {
                                if cn {
                                    xerr!(
                                        return Err(decode::Error::Malformed)
                                    )
                                }
                                let _ = PrintableString::take_from(cons)?;
                                cn = true;
                            }
                            else if id == oid::ID_AT_SERIAL_NUMBER {
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
    pub fn from_pub_key(key_info: &SubjectPublicKeyInfo) -> Self {
        let ki = key_info.key_identifier();
        // Borrow checker shenanigans ...
        let enc = hex::encode(&ki);
        let enc = enc.as_bytes();
        let values = encode::sequence(
            encode::set(
                encode::sequence((
                    oid::ID_AT_COMMON_NAME.value(),
                    enc.tagged(Tag::PRINTABLE_STRING),
                ))
            )
        );
        Name(Captured::from_values(Mode::Der, values))
    }

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        &self.0
    }
}


//------------ SignedData ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct SignedData {
    data: Captured,
    signature_algorithm: SignatureAlgorithm,
    signature_value: BitString,
}

impl SignedData {
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::take_content_from)
    }

    pub fn take_content_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        Ok(SignedData {
            data: cons.capture_one()?,
            signature_algorithm: SignatureAlgorithm::take_from(cons)?,
            signature_value: BitString::take_from(cons)?,
        })
    }

    pub fn data(&self) -> &Captured {
        &self.data
    }

    pub fn verify_signature(
        &self,
        public_key: &[u8]
    ) -> Result<(), ValidationError> {
        ::ring::signature::verify(
            &::ring::signature::RSA_PKCS1_2048_8192_SHA256,
            ::untrusted::Input::from(public_key),
            ::untrusted::Input::from(self.data.as_ref()),
            ::untrusted::Input::from(
                self.signature_value.octet_slice().unwrap()
            )
        ).map_err(|_| ValidationError)
    }

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            &self.data,
            self.signature_algorithm.encode(),
            self.signature_value.encode(),
        ))
    }

}


//------------ Time ----------------------------------------------------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Time(DateTime<Utc>);

impl Time {
    pub fn new(dt: DateTime<Utc>) -> Self {
        Time(dt)
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

    pub fn validate_not_before(&self) -> Result<(), ValidationError> {
        if time::now() < self.0 {
            Err(ValidationError)
        }
        else {
            Ok(())
        }
    }

    pub fn validate_not_after(&self) -> Result<(), ValidationError> {
        if time::now() > self.0 {
            Err(ValidationError)
        }
        else {
            Ok(())
        }
    }
}

impl PrimitiveContent for Time {

    const TAG: Tag = Tag::GENERALIZED_TIME;

    fn encoded_len(&self, _: Mode) -> usize {
        15 // yyyyMMddhhmmssZ
    }

    fn write_encoded<W: io::Write>(&self, _: Mode, target: &mut W)
        -> Result<(), io::Error>
    {
        write!(target, "{:04}", self.0.year())?;
        write!(target, "{:02}", self.0.month())?;
        write!(target, "{:02}", self.0.day())?;
        write!(target, "{:02}", self.0.hour())?;
        write!(target, "{:02}", self.0.minute())?;
        write!(target, "{:02}", self.0.second())?;
        write!(target, "Z")?;

        Ok(())
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


//------------ ValidationError -----------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="validation error")]
pub struct ValidationError;

impl From<decode::Error> for ValidationError {
    fn from(_: decode::Error) -> ValidationError {
        ValidationError
    }
}


//------------ OIDs ----------------------------------------------------------

pub mod oid {
    use ::ber::Oid;

    // https://www.itu.int/ITU-T/formal-language/itu-t/x/x520/2012/SelectedAttributeTypes.html#SelectedAttributeTypes.id-at-commonName
    pub const ID_AT_COMMON_NAME: Oid<&[u8]> = Oid(&[85, 4, 3]); // 2 5 4 3

    // https://www.itu.int/ITU-T/formal-language/itu-t/x/x520/2012/SelectedAttributeTypes.html#SelectedAttributeTypes.id-at-serialNumber
    pub const ID_AT_SERIAL_NUMBER: Oid<&[u8]> = Oid(&[85, 4, 5]); // 2 5 4 5

}


//------------ Testing. One. Two. Three --------------------------------------

#[cfg(test)]
mod test {
    use super::*;
    use ber::encode::Values;

    #[test]
    fn signed_data_decode_then_encode() {
        let data = include_bytes!("../test/oob/id-publisher-ta.cer");
        let obj = SignedData::decode(data.as_ref()).unwrap();
        let mut encoded = Vec::new();
        obj.encode().write_encoded(Mode::Der, &mut encoded).unwrap();
        assert_eq!(data.len(), encoded.len());
        assert_eq!(data.as_ref(), AsRef::<[u8]>::as_ref(&encoded));
    }
}
