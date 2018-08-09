//! Common components for publication protocol messages

use std::io;
use uri;
use publication::query::Query;
use remote::xml::{AttributesError, XmlReader, XmlReaderErr, XmlWriter};
use remote::xml::AttributePair;


//------------ PublicationMessage --------------------------------------------

pub const VERSION: &'static str = "4";
pub const NS: &'static str = "http://www.hactrn.net/uris/rpki/publication-spec/";

/// This type represents the Publication Messages defined in RFC8181
#[derive(Debug, Eq, PartialEq)]
pub enum PublicationMessage {
    Query(Query),
}

impl PublicationMessage {

    /// Decodes an XML structure
    pub fn decode<R>(reader: R) -> Result<Self, PublicationMessageError>
        where R: io::Read {

        XmlReader::decode(reader, |r| {
            r.take_named_element("msg", |mut a, r| {

                match a.take_req("version")?.as_ref() {
                    VERSION => { },
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

    /// Encodes to a Vec
    pub fn encode_vec(&self) -> Vec<u8> {
        XmlWriter::encode_vec(|w| {

            let msg_type = match self {
                PublicationMessage::Query(_) => "query"
            };
            let a = vec![
                AttributePair::from("version", VERSION),
                AttributePair::from("type", msg_type),
            ];

            w.put_first_element_with_attributes(
                "msg",
                NS,
                a,
                |w| {
                    match self {
                        PublicationMessage::Query(q) => { q.encode_vec(w) }
                    }
                }
            )
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
    use std::str;

    #[test]
    fn should_parse_publish_xml() {
        let xml = include_str!("../../test/publication/publish.xml");
        PublicationMessage::decode(xml.as_bytes()).unwrap();
    }

    #[test]
    fn should_encode_publish() {
        let xml = include_str!("../../test/publication/publish.xml");
        let pm = PublicationMessage::decode(xml.as_bytes()).unwrap();
        let vec = pm.encode_vec();
        let encoded = str::from_utf8(&vec).unwrap();
        let pm_from_encoded = PublicationMessage::decode(encoded.as_bytes()).unwrap();
        assert_eq!(pm, pm_from_encoded);
        assert_eq!(xml, encoded);
    }

}