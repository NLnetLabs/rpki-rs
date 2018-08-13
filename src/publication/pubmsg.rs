//! Common components for publication protocol messages

use std::io;
use uri;
use publication::query::PublishQuery;
use remote::xml::{AttributesError, XmlReader, XmlReaderErr, XmlWriter};
use publication::query::ListQuery;
use publication::reply::SuccessReply;


//------------ PublicationMessage --------------------------------------------

pub const VERSION: &'static str = "4";
pub const NS: &'static str = "http://www.hactrn.net/uris/rpki/publication-spec/";

/// This type represents the Publication Messages defined in RFC8181
#[derive(Debug, Eq, PartialEq)]
pub enum Message {
    PublishQuery(PublishQuery),
    ListQuery(ListQuery),
    SuccessReply(SuccessReply)
}

impl Message {

    /// Decodes an XML structure
    pub fn decode<R>(reader: R) -> Result<Self, MessageError>
        where R: io::Read {

        XmlReader::decode(reader, |r| {
            r.take_named_element("msg", |mut a, r| {

                match a.take_req("version")?.as_ref() {
                    VERSION => { },
                    _ => return Err(MessageError::InvalidVersion)
                }
                let msg_type = a.take_req("type")?;
                a.exhausted()?;

                match msg_type.as_ref() {
                    "query" => {
                        if r.next_element_name("list") {
                            Ok(Message::ListQuery(ListQuery::decode(r)?))
                        } else {
                            Ok(Message::PublishQuery(PublishQuery::decode(r)?))
                        }
                    },
                    "reply" => {
                        Ok(Message::SuccessReply(SuccessReply::decode(r)?))
                    }
                    _ => {
                        return Err(MessageError::UnknownMessageType)
                    }
                }
            })
        })
    }

    /// Encodes to a Vec
    pub fn encode_vec(&self) -> Vec<u8> {
        XmlWriter::encode_vec(|w| {

            let msg_type = match self {
                Message::PublishQuery(_) => "query",
                Message::ListQuery(_) => "query",
                Message::SuccessReply(_) => "reply"
            };
            let a = [
                ("xmlns", NS),
                ("version", VERSION),
                ("type", msg_type),
            ];

            w.put_element(
                "msg",
                Some(&a),
                |w| {
                    match self {
                        Message::PublishQuery(q) => { q.encode_vec(w) }
                        Message::ListQuery(l) => { l.encode_vec(w) }
                        Message::SuccessReply(s) => { s.encode_vec(w) }
                    }
                }
            )
        })
    }

}

//------------ PublicationMessageError ---------------------------------------

#[derive(Debug, Fail)]
pub enum MessageError {

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

impl From<XmlReaderErr> for MessageError {
    fn from(e: XmlReaderErr) -> MessageError {
        MessageError::XmlReadError(e)
    }
}

impl From<AttributesError> for MessageError {
    fn from(e: AttributesError) -> MessageError {
        MessageError::XmlAttributesError(e)
    }
}

impl From<uri::Error> for MessageError {
    fn from(e: uri::Error) -> MessageError {
        MessageError::UriError(e)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::str;

    #[test]
    fn should_parse_multi_element_query() {
        let xml = include_str!("../../test/publication/publish.xml");
        Message::decode(xml.as_bytes()).unwrap();
    }

    #[test]
    fn should_encode_multi_element_query() {
        let xml = include_str!("../../test/publication/publish.xml");
        let pm = Message::decode(xml.as_bytes()).unwrap();
        let vec = pm.encode_vec();
        let encoded = str::from_utf8(&vec).unwrap();
        let pm_from_encoded = Message::decode(encoded.as_bytes()).unwrap();
        assert_eq!(pm, pm_from_encoded);
        assert_eq!(xml, encoded);
    }

    #[test]
    fn should_parse_list_query() {
        let xml = include_str!("../../test/publication/list.xml");
        let l = Message::decode(xml.as_bytes()).unwrap();
        let vec = l.encode_vec();
        let xml_enc = str::from_utf8(&vec).unwrap();
        let l_from_enc = Message::decode(xml_enc.as_bytes()).unwrap();
        assert_eq!(l, l_from_enc);
        assert_eq!(xml, xml_enc);
    }

    #[test]
    fn should_parse_success_reply() {
        let xml = include_str!("../../test/publication/success.xml");
        let s = Message::decode(xml.as_bytes()).unwrap();
        let vec = s.encode_vec();
        let xml_enc = str::from_utf8(&vec).unwrap();
        let s_from_enc = Message::decode(xml_enc.as_bytes()).unwrap();
        assert_eq!(s, s_from_enc);
        assert_eq!(xml, xml_enc);
    }
}