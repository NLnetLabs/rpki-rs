//! Error types uses in out of band exchanges.

use std::fmt;
use crate::{xml, uri};
use crate::repository::x509::ValidationError;


//------------ IdExchangeError -----------------------------------------------

#[derive(Debug)]
pub enum IdExchangeError {
    InvalidXml(xml::decode::Error),
    InvalidVersion,
    InvalidHandle,
    InvalidTaBase64(base64::DecodeError),
    InvalidTaCertEncoding(bcder::decode::Error),
    InvalidTaCert,
    InvalidUri(uri::Error),
}

impl fmt::Display for IdExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IdExchangeError::InvalidXml(e) => e.fmt(f),
            IdExchangeError::InvalidVersion => write!(f, "Invalid version"),
            IdExchangeError::InvalidHandle => write!(f, "Invalid handle"),
            IdExchangeError::InvalidTaBase64(e) => e.fmt(f),
            IdExchangeError::InvalidTaCertEncoding(e) => {
                write!(f, "Cannot decode TA cert: {}", e)
            },
            IdExchangeError::InvalidTaCert => write!(f, "Invalid TA cert"),
            &IdExchangeError::InvalidUri(e) => e.fmt(f),
        }
    }
}

impl From<xml::decode::Error> for IdExchangeError {
    fn from(e: xml::decode::Error) -> Self {
        IdExchangeError::InvalidXml(e)
    }
}

impl From<base64::DecodeError> for IdExchangeError {
    fn from(e: base64::DecodeError) -> Self {
        IdExchangeError::InvalidTaBase64(e)
    }
}

impl From<bcder::decode::Error> for IdExchangeError {
    fn from(e: bcder::decode::Error) -> Self {
        IdExchangeError::InvalidTaCertEncoding(e)
    }
}

impl From<ValidationError> for IdExchangeError {
    fn from(_e: ValidationError) -> Self {
        IdExchangeError::InvalidTaCert
    }
}

impl From<uri::Error> for IdExchangeError {
    fn from(e: uri::Error) -> Self {
        IdExchangeError::InvalidUri(e)
    }
}