//! Out of band exchange messages.
//!
//! Support for the RFC8183 out-of-band setup requests and responses
//! used to exchange identity and configuration between CAs and their
//! parent CA and/or RPKI Publication Servers.

use std::io;
use std::path::Path;
use base64;
use base64::DecodeError;
use ber;
use bytes::Bytes;
use x509;
use super::idcert::IdCert;
use super::xml::{XmlReader, XmlReaderErr};
use super::xml::AttributesError;


//------------ PublisherRequest ----------------------------------------------

/// Type representing a <publisher_request/>
///
/// This is the XML message with identity information that a CA sends to a
/// Publication Server.
///
/// For more info, see: https://tools.ietf.org/html/rfc8183#section-5.2.3
#[derive(Debug)]
pub struct PublisherRequest {
    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,

    /// The name the publishing CA likes to call itself by
    publisher_handle: String,

    /// The encoded Identity Certificate
    /// (for now, will be replaced by a concrete IdCert once it's defined)
    id_cert: IdCert,
}

impl PublisherRequest {

    /// Parses a <publisher_request /> message.
    pub fn open<P: AsRef<Path>>(path: P)
        -> Result<Self, PublisherRequestError> {

        let mut r = XmlReader::open(path)?;
        r.start_document()?;

        let att = r.expect_element("publisher_request")?;

        match att.get_opt("version") {
            Some(version) => {
                if version != "1".to_string() {
                    return Err(PublisherRequestError::InvalidVersion)
                }
            },
            _ => return Err(PublisherRequestError::InvalidVersion)
        }

        let tag = att.get_opt("tag");
        let publisher_handle = att.get_req("publisher_handle")?;

        r.expect_element("publisher_bpki_ta")?;

        let base64_cert = r.expect_characters()?;
        let encoded_cert = base64::decode_config(&base64_cert, base64::MIME)?;

        r.expect_close("publisher_bpki_ta")?;
        r.expect_close("publisher_request")?;
        r.end_document()?;

        let id_cert = IdCert::decode(Bytes::from(encoded_cert))?;
        let id_cert = id_cert.validate_ta()?;

        Ok(PublisherRequest{tag, publisher_handle, id_cert})
    }

}


//------------ PublisherRequestError -----------------------------------------

#[derive(Debug, Fail)]
pub enum PublisherRequestError {
    #[fail(display = "Invalid XML for Publisher Request")]
    InvalidXml,

    #[fail(display = "Invalid version for Publisher Request")]
    InvalidVersion,

    #[fail(display = "Could not parse XML file: {}", _0)]
    FileError(io::Error),

    #[fail(display = "Invalid XML file: {}", _0)]
    XmlReadError(XmlReaderErr),

    #[fail(display = "Invalid XML file: {}", _0)]
    XmlAttributesError(AttributesError),

    #[fail(display = "Invalid base64: {}", _0)]
    Base64Error(DecodeError),

    #[fail(display = "Cannot parse identity certificate: {}", _0)]
    CannotParseIdCert(ber::Error),

    #[fail(display = "Invalid identity certificate: {}", _0)]
    InvalidIdCert(x509::ValidationError),
}

impl From<io::Error> for PublisherRequestError {
    fn from(e: io::Error) -> PublisherRequestError{
        PublisherRequestError::FileError(e)
    }
}

impl From<XmlReaderErr> for PublisherRequestError {
    fn from(e: XmlReaderErr) -> PublisherRequestError{
        PublisherRequestError::XmlReadError(e)
    }
}

impl From<AttributesError> for PublisherRequestError {
    fn from(e: AttributesError) -> PublisherRequestError{
        PublisherRequestError::XmlAttributesError(e)
    }
}

impl From<DecodeError> for PublisherRequestError {
    fn from(e: DecodeError) -> PublisherRequestError {
        PublisherRequestError::Base64Error(e)
    }
}

impl From<ber::Error> for PublisherRequestError {
    fn from(e: ber::Error) -> PublisherRequestError {
        PublisherRequestError::CannotParseIdCert(e)
    }
}

impl From<x509::ValidationError> for PublisherRequestError {
    fn from(e: x509::ValidationError) -> PublisherRequestError {
        PublisherRequestError::InvalidIdCert(e)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use time;
    use chrono::{TimeZone, Utc};

    # [test]
    fn test_parse_publisher_request() {
        let d = Utc.ymd(2012, 1, 1).and_hms(0, 0, 0);

        time::with_now(d, || {
            let pr = PublisherRequest::open("test/oob/publisher_request.xml")
                .unwrap();
            assert_eq!("Bob", pr.publisher_handle);
            assert_eq!(Some("A0001".to_string()), pr.tag);
        });
    }
}