//! Handling of Base 64-encoded data.
//!
//! This module provides various methods for decoding and encoding data in
//! Base 64. Because there are different dialects of Base 64 and applications
//! have slight usage differences atop those, the module provides an number
//! of structs that describe flavors of Base 64 used within in a certain
//! context. That is, you don’t have to remember how an application uses Base
//! 64 exactly but just pick your application.
//!
//! Each flavor implements a number of methods for encoding and decoding.
//! These differ slightly between the flavors based on what they are used
//! for.
use std::{error, fmt, io, str};
use std::io::Read;
use base64::engine::{DecodeEstimate, Engine};
use base64::engine::general_purpose::{
    GeneralPurpose, GeneralPurposeConfig, STANDARD
};

pub use base64::{DecodeError, DecodeSliceError};


//------------ Xml -----------------------------------------------------------

/// The flavor used by `base64Binary` defined for XML.
///
/// This uses the standard alphabet with padding and ASCII white-space allowed
/// between alphabet characters.
pub struct Xml;

impl Xml {
    const ENGINE: GeneralPurpose = STANDARD;

    pub fn decode(self, input: &str) -> Result<Vec<u8>, XmlDecodeError> {
        let mut res = Vec::with_capacity(
            Self::ENGINE.internal_decoded_len_estimate(
                input.len()
            ).decoded_len_estimate()
        );
        base64::read::DecoderReader::new(
            SkipWhitespace::new(input),
            &Self::ENGINE,
        ).read_to_end(&mut res)?;
        Ok(res)
    }

    pub fn decode_bytes(
        self, input: &[u8]
    ) -> Result<Vec<u8>, XmlDecodeError> {
        let input = str::from_utf8(input).map_err(|err| {
            let pos = err.valid_up_to();
            io::Error::new(
                io::ErrorKind::Other,
                DecodeError::InvalidByte(pos, input[pos])
            )
        })?;
        self.decode(input)
    }

    pub fn encode(self, data: &[u8]) -> String {
        Self::ENGINE.encode(data)
    }

    pub fn decode_reader(
        self, input: &str,
    ) -> XmlDecoderReader {
        XmlDecoderReader(
            base64::read::DecoderReader::new(
                SkipWhitespace::new(input),
                &Self::ENGINE
            )
        )
    }

    pub fn encode_writer(
        self, writer: impl io::Write
    ) -> impl io::Write {
        base64::write::EncoderWriter::new(writer, &Self::ENGINE)
    }
}


//------------ Serde --------------------------------------------------------

/// The flavor used for serialization of objects in this crate.
///
/// This flavor is used whenever Base 64 is used for serialization of
/// binary objects in this crate.
///
/// It uses the standard alphabet with padding and no white space allowed.
pub struct Serde;

impl Serde {
    const ENGINE: GeneralPurpose = STANDARD;

    pub fn decode(self, input: &str) -> Result<Vec<u8>, DecodeError> {
        Self::ENGINE.decode(input)
    }

    pub fn encode(self, data: &[u8]) -> String {
        Self::ENGINE.encode(data)
    }
}


//------------ Slurm ---------------------------------------------------------

/// The flavor prescribed for some data in local exception files.
///
/// Uses the URL-safe alphabet. When decoding, it accepts both padding and no
/// padding. When encoding, it doesn’t add padding.
pub struct Slurm;

impl Slurm {
    const ENGINE: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(
                base64::engine::DecodePaddingMode::Indifferent
            )
    );

    pub fn decode(self, input: &str) -> Result<Vec<u8>, DecodeError> {
        Self::ENGINE.decode(input)
    }

    pub fn decode_slice(
        self, input: &str, output: &mut [u8]
    ) -> Result<usize, DecodeSliceError> {
        Self::ENGINE.decode_slice(input, output)
    }

    pub fn encode(self, data: &[u8]) -> String {
        Self::ENGINE.encode(data)
    }

    pub fn display(self, data: &[u8]) -> impl fmt::Display + '_ {
        base64::display::Base64Display::new(data, &Self::ENGINE)
    }
}


//------------ SkipWhitespace ------------------------------------------------

struct SkipWhitespace<'a> {
    splitter: str::SplitAsciiWhitespace<'a>,
    current: &'a [u8],
}

impl<'a> SkipWhitespace<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            splitter: s.split_ascii_whitespace(),
            current: b"",
        }
    }
}

impl<'a> io::Read for SkipWhitespace<'a> {
    fn read(&mut self, mut buf: &mut[u8]) -> Result<usize, io::Error> {
        let mut res = 0;

        loop {
            if self.current.is_empty() {
                let next = match self.splitter.next() {
                    Some(data) => data,
                    None => return Ok(res)
                };
                self.current = next.as_bytes();
            }
            let current_len = self.current.len();
            let buf_len = buf.len();
            if current_len < buf_len {
                buf[..current_len].copy_from_slice(self.current);
                res += current_len;
                buf = &mut buf[current_len..];
                self.current = b"";
            }
            else {
                let (head, tail) = self.current.split_at(buf_len);
                buf.copy_from_slice(head);
                self.current = tail;
                return Ok(res + buf_len);
            }
        }
    }
}


//------------ XmlDecoderReader ----------------------------------------------

pub struct XmlDecoderReader<'a>(
    base64::read::DecoderReader<
        'static, GeneralPurpose, SkipWhitespace<'a>
    >
);

impl<'a> io::Read for XmlDecoderReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.0.read(buf)
    }
}


//------------ XmlDecodeError ------------------------------------------------

#[derive(Debug)]
pub struct XmlDecodeError(io::Error);

impl From<io::Error> for XmlDecodeError {
    fn from(err: io::Error) -> Self {
        Self(err)
    }
}

impl fmt::Display for XmlDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0.get_ref() {
            Some(inner) => fmt::Display::fmt(inner, f),
            None => fmt::Display::fmt(&self.0, f),
        }
    }
}

impl error::Error for XmlDecodeError { } 


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn skip_whitespace() {
        fn test(s: &str) {
            let mut left = String::from(s);
            left.retain(|ch| !ch.is_ascii_whitespace());

            let mut right = String::new();
            SkipWhitespace::new(s).read_to_string(&mut right).unwrap();

            assert_eq!(left, right);

            let mut right = Vec::new();
            let mut reader = SkipWhitespace::new(s);
            loop {
                let mut buf = [0u8; 2];
                let read = reader.read(&mut buf).unwrap();
                if read == 0 {
                    break
                }
                right.extend_from_slice(buf.as_ref());
            }

            assert_eq!(left.as_bytes(), right.as_slice());
        }

        test("foobar");
        test("foo bar");
        test(" foo bar");
        test(" foo bar ");
    }

}

