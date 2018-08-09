//! Common components for publication protocol messages

use std::io;
use remote::xml::{XmlReader, XmlReaderErr};
use remote::xml::AttributesError;
use publication::query::Query;
use uri;


//------------ PublicationMessage --------------------------------------------

pub enum PublicationMessage {
    Query(Query),
}


impl PublicationMessage {

    pub fn decode<R>(reader: R) -> Result<Self, PublicationMessageError>
        where R: io::Read {

        XmlReader::decode(reader, |r| {
            r.take_named_element("msg", |mut a, r| {

                match a.take_req("version")?.as_ref() {
                    "4" => { },
                    _ => return Err(PublicationMessageError::InvalidVersion)
                }
                let msg_type = a.take_req("type")?;
                a.exhausted()?;

                match msg_type.as_ref() {
                    "query" => {
                        Ok(PublicationMessage::Query(Query::decode(r)?))
                    },
                    _ => {
                        return Err(PublicationMessageError::UnknownMessageType)
                    }
                }
            })
        })
    }

}

//------------ PublicationMessageError ---------------------------------------

#[derive(Debug, Fail)]
pub enum PublicationMessageError {

    #[fail(display = "Invalid version")]
    InvalidVersion,

    #[fail(display = "Unknown message type")]
    UnknownMessageType,

    #[fail(display = "Unexpected XML Start Tag: {}", _0)]
    UnexpectedStart(String),

    #[fail(display = "Invalid XML file: {}", _0)]
    XmlReadError(XmlReaderErr),

    #[fail(display = "Invalid use of attributes in XML file: {}", _0)]
    XmlAttributesError(AttributesError),

    #[fail(display = "Invalid URI: {}", _0)]
    UriError(uri::Error),
}

impl From<XmlReaderErr> for PublicationMessageError {
    fn from(e: XmlReaderErr) -> PublicationMessageError {
        PublicationMessageError::XmlReadError(e)
    }
}

impl From<AttributesError> for PublicationMessageError {
    fn from(e: AttributesError) -> PublicationMessageError {
        PublicationMessageError::XmlAttributesError(e)
    }
}

impl From<uri::Error> for PublicationMessageError {
    fn from(e: uri::Error) -> PublicationMessageError {
        PublicationMessageError::UriError(e)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn should_parse_publish_xml() {

        let xml = include_str!("../../test/publication/publish.xml");
        PublicationMessage::decode(xml.as_bytes()).unwrap();

    }

}