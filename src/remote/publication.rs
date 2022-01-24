//! Support for RFC 8181 Publication Messages

use std::fmt;
use std::io;
use log::error;

use crate::xml;
use crate::xml::decode::Content;
use crate::xml::decode::{
    Error as XmlError, Name
};

// Constants for the RFC 8183 XML
const VERSION: &str = "4";
const NS: &[u8] = b"http://www.hactrn.net/uris/rpki/publication-spec/";

const MSG: Name = Name::qualified(NS, b"msg");

const QUERY_PDU_LIST: Name = Name::qualified(NS, b"list");
const QUERY_PDU_LIST_UNQ: Name = Name::unqualified(b"list");


//------------ Message -------------------------------------------------------

/// This type represents all Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    QueryMessage(QueryMessage),
}

/// # Encoding to XML
/// 
impl Message {
    /// Writes the Message's XML representation.
    pub fn write_xml(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);

        let type_value = match self {
            Message::QueryMessage(_) => "query"
        };

        writer.element(MSG.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("type", type_value)?
            .content(|content|{
                match self {
                    Message::QueryMessage(msg) => {
                        match msg {
                            QueryMessage::ListQuery => {
                                content.element(QUERY_PDU_LIST_UNQ)?;
                            }
                        }
                    }
                }
                Ok(())
            })?;
        writer.done()
    }

    #[cfg(test)]
    fn to_xml_string(&self) -> String {
        use std::str::from_utf8;

        let mut vec = vec![];
        self.write_xml(&mut vec).unwrap(); // safe
        let xml = from_utf8(vec.as_slice()).unwrap(); // safe

        xml.to_string()
    }   
}

/// # Decoding from XML
/// 
impl Message {
    /// Parses an RFC 8181 <msg />
    pub fn decode<R: io::BufRead>(reader: R) -> Result<Self, Error> {
        let mut reader = xml::decode::Reader::new(reader);

        let mut kind: Option<MessageKind> = None;

        let mut outer = reader.start(|element| {
            if element.name() != MSG {
                return Err(XmlError::Malformed)
            }
            
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<String>()? != VERSION {
                        return Err(XmlError::Malformed)
                    }
                    Ok(())
                }
                b"type" => {
                    match value.ascii_into::<String>()?.as_str() {
                        "query" => {
                            kind = Some(MessageKind::Query);
                            Ok(())
                        }
                        _ => Err(XmlError::Malformed)
                    }
                }
                _ => Err(XmlError::Malformed)
            })
        })?;

        // Dispatch to message kind for content parsing
        let msg = match kind.ok_or(XmlError::Malformed)? {
            MessageKind::Query => Message::QueryMessage(
                QueryMessage::decode(&mut outer, &mut reader)?
            ),
        };

        // Check that there is no additional stuff
        outer.take_end(&mut reader)?;
        reader.end()?;

        Ok(msg)
    }
}


//------------ MessageKind ---------------------------------------------------

/// This type represents all Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
enum MessageKind {
    Query,
}

//------------ QueryMessage --------------------------------------------------

/// This type represents query type Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryMessage {
    ListQuery,
}


/// # Decoding from XML
/// 
impl QueryMessage {
    /// Decodes the content of an RFC 8181 query type message
    //
    // See https://datatracker.ietf.org/doc/html/rfc8181#section-2.1
    //
    // The content of a 'query' type 'msg' can be zero or more PDUs
    // of the following types:
    //  - <list />
    //  - <publish />
    //  - <withdraw />
    //
    // If this is a 'list' type query then there MUST be one only one PDU
    // present - of type <list />. This cannot me mixed with other types.
    //
    // If this is a 'publication/withdraw' type query then there can be zero
    // PDUs (although it would not make sense to send an empty update, this is
    // allowed), or 1 for a single change, or many for a multi-element query,
    // i.e. an atomic delta. All PDUs must be of type <publish /> or
    // <withdraw />.
    //
    // So, in short we need to do a bit of probing below to figure out which
    // kind of query we're actually dealing with.
    fn decode<R: io::BufRead>(
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        let mut pdus: Vec<QueryPdu> = vec![];
        loop {
            let mut pdu_type = None;

            // We need to do a two step analysis of elements. First we need
            // to determine which type of element we are dealing with, and
            // then we can evaluate the content. For <publish /> and
            // <withdraw /> elements we will need to parse information from
            // the element attributes *before* we can use the reader and
            // inspect the content of a <publish /> element.
            let inner = content.take_opt_element(reader, |element| {
                match element.name() {
                    QUERY_PDU_LIST => {
                        pdu_type = Some(QueryPduType::List);
                        Ok(())
                    },
                    _ => {
                        Err(XmlError::Malformed)
                    }
                }
            })?;

            // Break out of loop if we got no element, get the
            // actual element if we can.
            let mut inner = match inner {
                Some(inner) => inner,
                None => break
            };

            // We had an element so we can unwrap the type.
            let pdu_type = pdu_type.unwrap(); 

            inner.take_end(reader)?;

            match pdu_type {
                QueryPduType::List => {
                    if !pdus.is_empty() {
                        error!("Found list pdu in multi-element query");
                        Err(XmlError::Malformed)
                    } else {
                        pdus.push(QueryPdu::List);
                        Ok(())
                    }
                }
            }?;
        }

        if pdus.get(0) == Some(&QueryPdu::List) {
            Ok(QueryMessage::ListQuery)
        } else {
            todo!()
        }
    }
}


//------------ QueryPduType --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryPduType {
    List,
}

//------------ QueryPdu ------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryPdu {
    List,
}


//------------ PublicationMessageError ---------------------------------------

#[derive(Debug)]
pub enum Error {
    InvalidVersion,
    XmlError(XmlError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidVersion => write!(f, "Invalid version"),
            Error::XmlError(e) => e.fmt(f),
        }
    }
}

impl From<XmlError> for Error {
    fn from(e: XmlError) -> Self {
        Error::XmlError(e)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parse_and_encode_list_query() {
        let xml = include_bytes!("../../test-data/remote/rfc8181/list.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }


}