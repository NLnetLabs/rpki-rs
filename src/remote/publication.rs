//! Support for RFC 8181 Publication Messages

use std::fmt;
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use log::error;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use crate::rrdp;
use crate::uri;
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
const QUERY_PDU_PUBLISH: Name = Name::qualified(NS, b"publish");
const QUERY_PDU_WITHDRAW: Name = Name::qualified(NS, b"withdraw");

const REPLY_PDU_LIST: Name = Name::qualified(NS, b"list");
const REPLY_PDU_SUCCESS: Name = Name::qualified(NS, b"success");


//------------ Message -------------------------------------------------------

/// This type represents all Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    QueryMessage(QueryMessage),
    ReplyMessage(ReplyMessage),
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
            Message::QueryMessage(_) => "query",
            Message::ReplyMessage(_) => "reply",
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
                                content.element(
                                    QUERY_PDU_LIST.into_unqualified()
                                )?;
                            },
                            QueryMessage::Delta(delta) => {
                                for el in &delta.0 {
                                    match el {
                                        PublishDeltaElement::Publish(p) => {
                                            content.element(
                                                QUERY_PDU_PUBLISH
                                                        .into_unqualified()
                                            )?
                                            .attr("tag", p.tag_for_xml())?
                                            .attr("uri", &p.uri)?
                                            .content(|content| {
                                                content.raw(&p.content)
                                            })?;
                                        },
                                        PublishDeltaElement::Update(u) => {
                                            content.element(
                                                QUERY_PDU_PUBLISH
                                                        .into_unqualified()
                                            )?
                                            .attr("tag", u.tag_for_xml())?
                                            .attr("uri", &u.uri)?
                                            .attr("hash", &u.hash)?
                                            .content(|content| {
                                                content.raw(&u.content)
                                            })?;
                                        },
                                        PublishDeltaElement::Withdraw(w) => {
                                            content.element(
                                                QUERY_PDU_WITHDRAW
                                                        .into_unqualified()
                                            )?
                                            .attr("tag", w.tag_for_xml())?
                                            .attr("uri", &w.uri)?
                                            .attr("hash", &w.hash)?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Message::ReplyMessage(msg) => {
                        match msg {
                            ReplyMessage::ListReply(list) => {
                                for el in &list.elements {
                                    content.element(
                                        REPLY_PDU_LIST.into_unqualified()
                                    )?
                                    .attr("uri", &el.uri)?
                                    .attr("hash", &el.hash)?;
                                }
                            }
                            ReplyMessage::Success => {
                                content.element(
                                    REPLY_PDU_SUCCESS.into_unqualified()
                                )?;
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
                        "reply" => {
                            kind = Some(MessageKind::Reply);
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
            MessageKind::Reply => Message::ReplyMessage(
                ReplyMessage::decode(&mut outer, &mut reader)?
            )
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
    Reply
}

//------------ QueryMessage --------------------------------------------------

/// This type represents query type Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryMessage {
    ListQuery,
    Delta(PublishDelta),
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
        
        // First parse *all* PDUs, then we can decide what query type we had
        let mut pdus: Vec<QueryPdu> = vec![];
        loop {
            let mut pdu_type = None;

            // We need to do a two step analysis of elements. First we need
            // to determine which type of element we are dealing with, and
            // then we can evaluate the content. For <publish /> and
            // <withdraw /> elements we will need to parse information from
            // the element attributes *before* we can use the reader and
            // inspect the content of a <publish /> element.

            // possible attributes
            let mut tag: Option<String> = None;
            let mut uri: Option<uri::Rsync> = None;
            let mut hash: Option<rrdp::Hash> = None;

            let pdu_element = content.take_opt_element(reader, |element| {
                // Determine the PDU type
                pdu_type = Some(match element.name() {
                    QUERY_PDU_LIST => {
                        Ok(QueryPduType::List)
                    },
                    QUERY_PDU_PUBLISH => {
                        Ok(QueryPduType::Publish)
                    },
                    QUERY_PDU_WITHDRAW => {
                        Ok(QueryPduType::Withdraw)
                    }
                    _ => {
                        Err(XmlError::Malformed)
                    }
                }?);

                // parse element attributes - we treat them as optional
                // at this point so it does not matter that not all attributes
                // are applicable to all element types.
                element.attributes(|name, value| match name {
                    b"tag" => {
                        tag = Some(value.ascii_into()?);
                        Ok(())
                    }
                    b"hash" => {
                        let hex: String = value.ascii_into()?;
                        if let Ok(hash_value) =rrdp::Hash::from_str(&hex) {
                            hash = Some(hash_value);
                            Ok(())
                        } else {
                            Err(XmlError::Malformed)
                        }
                    }
                    b"uri" => {
                        uri = Some(value.ascii_into()?);
                        Ok(())
                    }
                    _ => {
                        Err(XmlError::Malformed)
                    }
                })

            })?;

            // Break out of loop if we got no element, get the
            // actual element if we can.
            let mut pdu_element = match pdu_element {
                Some(inner) => inner,
                None => break
            };
            
            // We had an element so we can unwrap the type.
            let pdu_type = pdu_type.unwrap(); 

            
            match pdu_type {
                QueryPduType::List => {
                    if !pdus.is_empty() {
                        error!("Found list pdu in multi-element query");
                        Err(XmlError::Malformed)
                    } else {
                        pdus.push(QueryPdu::List);
                        Ok(())
                    }
                },
                QueryPduType::Publish => {
                    let uri = uri.ok_or(XmlError::Malformed)?;
                    
                    // even though we store the base64 as [`Base64`] which
                    // uses an inner `Arc<str>`, we decode it first to ensure
                    // that it can be parsed.
                    let bytes = pdu_element.take_text(reader, |text| {
                        text.base64_decode()
                    })?;
                    
                    let content = Base64::from_content(&bytes);
                    
                    match hash {
                        None => {
                            pdus.push(QueryPdu::PublishDeltaElement(
                                PublishDeltaElement::Publish(
                                    Publish {
                                        tag,
                                        uri,
                                        content,
                                    }
                                )
                            ));
                            Ok(())
                        },
                        Some(hash) => {
                            pdus.push(QueryPdu::PublishDeltaElement(
                                PublishDeltaElement::Update(
                                    Update {
                                        tag,
                                        uri,
                                        content,
                                        hash,
                                    }
                                )
                            ));
                            Ok(())
                        }
                    }
                }
                QueryPduType::Withdraw => {
                    let uri = uri.ok_or(XmlError::Malformed)?;
                    let hash = hash.ok_or(XmlError::Malformed)?;

                    pdus.push(QueryPdu::PublishDeltaElement(
                        PublishDeltaElement::Withdraw(
                            Withdraw { tag, uri, hash }
                        )
                    ));
                    Ok(())
                }
            }?;

            pdu_element.take_end(reader)?;
        }

        if pdus.get(0) == Some(&QueryPdu::List) {
            Ok(QueryMessage::ListQuery)
        } else {
            let mut delta = PublishDelta::default();
            for pdu in pdus.into_iter() {
                match pdu {
                    QueryPdu::List => {} // should be unreachable,
                    QueryPdu::PublishDeltaElement(el) => delta.0.push(el)
                }
            }
            Ok(QueryMessage::Delta(delta))
        }
    }
}


//------------ QueryPduType --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryPduType {
    List,
    Publish,
    Withdraw,
}

//------------ QueryPdu ------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryPdu {
    List,
    PublishDeltaElement(PublishDeltaElement)
}


//------------ PublishDelta ------------------------------------------------

/// This type represents a multi element query as described in
/// https://tools.ietf.org/html/rfc8181#section-3.7
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishDelta(Vec<PublishDeltaElement>);


//------------ PublishDeltaElement -------------------------------------------

/// Represents the available options for publish elements that can occur in
/// a delta.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PublishDeltaElement {
    Publish(Publish),
    Update(Update),
    Withdraw(Withdraw),
}


//------------ Publish -------------------------------------------------------

/// Represents a publish element, that does not update any existing object.
/// See: https://tools.ietf.org/html/rfc8181#section-3.1
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Publish {
    tag: Option<String>,
    uri: uri::Rsync,
    content: Base64,
}

impl Publish {
    fn tag_for_xml(&self) -> &str {
        self.tag.as_deref().unwrap_or("")
    }
}


//------------ Update --------------------------------------------------------

/// Represents a publish element, that replaces an existing object.
/// See: https://tools.ietf.org/html/rfc8181#section-3.2
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Update {
    tag: Option<String>,
    uri: uri::Rsync,
    content: Base64,
    hash: rrdp::Hash,
}

impl Update {
    fn tag_for_xml(&self) -> &str {
        self.tag.as_deref().unwrap_or("")
    }
}


//------------ Withdraw ------------------------------------------------------

/// Represents a withdraw element that removes an object.
/// See: https://tools.ietf.org/html/rfc8181#section-3.3
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Withdraw {
    tag: Option<String>,
    uri: uri::Rsync,
    hash: rrdp::Hash,
}

impl Withdraw {
    fn tag_for_xml(&self) -> &str {
        self.tag.as_deref().unwrap_or("")
    }
}


//------------ ReplyMessage --------------------------------------------------

/// This type represents query type Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyMessage {
    ListReply(ListReply),
    Success
}

impl ReplyMessage {
    /// Decoded the content of an RFC 8181 reply type message.
    //
    // See https://datatracker.ietf.org/doc/html/rfc8181#section-2.1
    //
    // The content of a 'reply' type 'msg' can be zero or more PDUs
    // of the following types:
    //  - <list />
    //  - <success />
    //  - <report_error />
    //
    // If this is a 'success' type reply then there MUST be one only one PDU
    // present - of type <success />.
    //
    // If this is a 'report_error' type reply then there MUST be one only one
    // PDU present - of type <report_error />.
    //
    // If this is a 'list' type reply then there can be zero or more <list />
    // PDUs for each currently published object.
    //
    // So, in short we need to do a bit of probing of elements to figure out
    // which kind of reply we're actually dealing with.
    fn decode<R: io::BufRead>(
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        
        // First parse *all* PDUs, then we can decide what reply type we had
        let mut pdus: Vec<ReplyPdu> = vec![];
        loop {
            let mut pdu_type = None;

            // We need to do a two step analysis of elements. First we need
            // to determine which type of element we are dealing with, and
            // then we can evaluate the content. For <list /> and
            // <error_report /> elements we will need to parse information
            // from the element attributes. We need to do this *before* we
            // can use the reader to inspect the content of an element.

            // possible attributes
            let mut uri: Option<uri::Rsync> = None;
            let mut hash: Option<rrdp::Hash> = None;
            let mut tag: Option<String> = None;
            let mut error_code: Option<String> = None;

            let pdu_element = content.take_opt_element(reader, |element| {
                // Determine the PDU type
                pdu_type = Some(match element.name() {
                    REPLY_PDU_LIST => {
                        Ok(ReplyPduType::List)
                    },
                    REPLY_PDU_SUCCESS => {
                        Ok(ReplyPduType::Success)
                    }
                    _ => {
                        Err(XmlError::Malformed)
                    }
                }?);

                // parse element attributes - we treat them as optional
                // at this point so it does not matter that not all attributes
                // are applicable to all element types.
                element.attributes(|name, value| match name {
                    b"hash" => {
                        let hex: String = value.ascii_into()?;
                        if let Ok(hash_value) =rrdp::Hash::from_str(&hex) {
                            hash = Some(hash_value);
                            Ok(())
                        } else {
                            Err(XmlError::Malformed)
                        }
                    }
                    b"uri" => {
                        uri = Some(value.ascii_into()?);
                        Ok(())
                    }
                    b"tag" => {
                        tag = Some(value.ascii_into()?);
                        Ok(())
                    }
                    b"error_code" => {
                        error_code = Some(value.ascii_into()?);
                        Ok(())
                    }
                    _ => {
                        Err(XmlError::Malformed)
                    }
                })
            })?;

            // Break out of loop if we got no element, get the
            // actual element if we can.
            let mut pdu_element = match pdu_element {
                Some(inner) => inner,
                None => break
            };
            
            // We had an element so we can unwrap the type.
            let pdu_type = pdu_type.unwrap(); 

            match pdu_type {
                ReplyPduType::List => {
                    let uri = uri.ok_or(XmlError::Malformed)?;
                    let hash = hash.ok_or(XmlError::Malformed)?;

                    pdus.push(ReplyPdu::List(ListElement { uri, hash } ));
                }
                ReplyPduType::Success => {
                    if pdus.is_empty() {
                        pdus.push(ReplyPdu::Success)
                    } else {
                        error!("Found success pdu in multi-element reply");
                        return Err(Error::XmlError(XmlError::Malformed))
                    }
                }
            }

            // close the processed PDU
            pdu_element.take_end(reader)?;
        }

        if pdus.get(0) == Some(&ReplyPdu::Success) {
            Ok(ReplyMessage::Success)
        } else {
            let mut list = ListReply::default();
            for pdu in pdus.into_iter() {
                if let ReplyPdu::List(el) = pdu {
                    list.elements.push(el);
                }
            }
            Ok(ReplyMessage::ListReply(list))
        }

    }
}


//------------ ReplyPduType --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyPduType {
    List,
    Success,
}


//------------ ReplyPdu ------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyPdu {
    List(ListElement),
    Success,
}

//------------ ListReply -----------------------------------------------------

/// This type represents the list reply as described in
/// https://tools.ietf.org/html/rfc8181#section-2.3
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListReply {
    elements: Vec<ListElement>,
}


//------------ ListElement ---------------------------------------------------

/// This type represents a single object that is published at a publication
/// server.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ListElement {
    uri: uri::Rsync,
    hash: rrdp::Hash,
}




//------------ Base64 --------------------------------------------------------

/// This type contains a base64 encoded structure. The publication protocol
/// deals with objects in their base64 encoded form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Base64(Arc<str>);

impl Base64 {
    pub fn from_content(content: &[u8]) -> Self {
        Base64(base64::encode(content).into())
    }
}

impl fmt::Display for Base64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Base64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Base64 {
    fn deserialize<D>(deserializer: D) -> Result<Base64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Ok(Base64(string.into()))
    }
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

    #[test]
    fn parse_and_encode_publish_multi_query() {
        let xml = include_bytes!("../../test-data/remote/rfc8181/publish-multi.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_encode_publish_single_query() {
        let xml = include_bytes!("../../test-data/remote/rfc8181/publish-single.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_encode_publish_empty_query() {
        let xml = include_bytes!("../../test-data/remote/rfc8181/publish-empty.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_encode_publish_empty_short_query() {
        let xml = include_bytes!("../../test-data/remote/rfc8181/publish-empty-short.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_list_reply() {
        let xml = include_bytes!("../../test-data/remote/rfc8181/list-reply.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_list_reply_single() {
        let xml = include_bytes!("../../test-data/remote/rfc8181/list-reply-single.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_list_reply_empty() {
        let xml = include_bytes!("../../test-data/remote/rfc8181/list-reply-empty.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_list_reply_empty_short() {
        let xml = include_bytes!("../../test-data/remote/rfc8181/list-reply-empty-short.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_success_reply() {
        let xml = include_bytes!("../../test-data/remote/rfc8181/success-reply.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }
}