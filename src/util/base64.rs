//! Handling of Base 64-encoded data.
//!
//! This module provides various methods for decoding and encoding data in
//! Base 64. Because there are different dialects of Base 64 and applications
//! again place slight differences atop those, the module provides an number
//! of structs that that describe flavors of Base 64 used within in a certain
//! context. That is, you don’t have to remember how an application uses
//! Base 64 exactly but just pick your application.
//!
//! Each flavor implements a number of methods for encoding and decoding.
//! These differ slightly between the flavors based on what they are used
//! for.
use std::{fmt, io, str};
use base64::Engine;
use base64::engine::general_purpose::{
    GeneralPurpose, GeneralPurposeConfig, STANDARD
};

pub use base64::{DecodeError, DecodeSliceError};

//------------ Xml -----------------------------------------------------------

/// The flavour used by `base64Binary` defined for XML.
///
/// This uses the standard alphabet with padding and allows XML white
/// space during decoding but doesn’t add any during encoding.
pub struct Xml;

impl Xml {
    const ENGINE: GeneralPurpose = STANDARD;

    pub fn decode(self, input: &str) -> Result<Vec<u8>, DecodeError> {
        Self::ENGINE.decode(input)
    }

    pub fn decode_bytes(self, input: &[u8]) -> Result<Vec<u8>, DecodeError> {
        let input = str::from_utf8(input).map_err(|err| {
            let pos = err.valid_up_to();
            DecodeError::InvalidByte(pos, input[pos])
        })?;
        Self::ENGINE.decode(input)
    }

    pub fn encode(self, data: &[u8]) -> String {
        Self::ENGINE.encode(data)
    }

    pub fn decode_reader<T: io::Read>(
        self, reader: T
    ) -> DecoderReader<T> {
        base64::read::DecoderReader::new(reader, &Self::ENGINE)
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

pub type DecoderReader<T> = base64::read::DecoderReader<'static, GeneralPurpose, T>;

