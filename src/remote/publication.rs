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
use crate::xml::encode;

// Constants for the RFC 8183 XML
const VERSION: &str = "4";
const NS: &[u8] = b"http://www.hactrn.net/uris/rpki/publication-spec/";

const MSG: Name = Name::qualified(NS, b"msg");

const QUERY_PDU_LIST: Name = Name::qualified(NS, b"list");
const QUERY_PDU_PUBLISH: Name = Name::qualified(NS, b"publish");
const QUERY_PDU_WITHDRAW: Name = Name::qualified(NS, b"withdraw");

const LIST_LOCAL: &[u8] = b"list";
const LIST: Name = Name::qualified(NS, LIST_LOCAL);
const SUCCESS_LOCAL: &[u8] = b"success";
const SUCCESS: Name = Name::qualified(NS, SUCCESS_LOCAL);
const REPORT_ERROR_LOCAL: &[u8] = b"report_error";
const REPORT_ERROR: Name = Name::qualified(NS, REPORT_ERROR_LOCAL);

const REPLY_PDU_ERROR_TEXT: Name = Name::qualified(NS, b"error_text");
const REPLY_PDU_ERROR_PDU: Name = Name::qualified(NS, b"failed_pdu");


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
                    Message::QueryMessage(msg) => msg.write_xml(content),
                    Message::ReplyMessage(msg) => msg.write_xml(content)
                }
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
                    kind = Some(match value.ascii_into::<String>()?.as_str() {
                        "query" => Ok(MessageKind::Query),
                        "reply" => Ok(MessageKind::Reply),
                        _ => Err(XmlError::Malformed)
                    }?);
                    Ok(())
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

            match QueryPdu::decode_opt(content, reader)? {
                None => break,
                Some(pdu) => {
                    if !pdus.is_empty() && pdu == QueryPdu::List {
                        error!("Found list pdu in multi-element query");
                        return Err(Error::XmlError(XmlError::Malformed));
                    }
                    pdus.push(pdu);
                }
            }
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


/// # Encoding to XML
/// 
impl QueryMessage {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        match self {
            QueryMessage::ListQuery => {
                content.element(
                    QUERY_PDU_LIST.into_unqualified()
                )?;
            },
            QueryMessage::Delta(delta) => {
                for el in &delta.0 {
                    el.write_xml(content)?;
                }
            }
        }

        Ok(())
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

impl QueryPdu {
    // Decodes an optional query PDU
    fn decode_opt<R: io::BufRead>(
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Option<Self>, Error> {
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
                QUERY_PDU_LIST => Ok(QueryPduType::List),
                QUERY_PDU_PUBLISH => Ok(QueryPduType::Publish),
                QUERY_PDU_WITHDRAW => Ok(QueryPduType::Withdraw),
                _ => Err(XmlError::Malformed)
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
            None => return Ok(None)
        };
        
        // We had an element so we can unwrap the type.
        let pdu_type = pdu_type.unwrap(); 

        
        let pdu: Result<QueryPdu, Error> = match pdu_type {
            QueryPduType::List => {
                Ok(QueryPdu::List)
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
                        Ok(QueryPdu::PublishDeltaElement(
                            PublishDeltaElement::Publish(
                                Publish {
                                    tag,
                                    uri,
                                    content,
                                }
                            )
                        ))
                    },
                    Some(hash) => {
                        Ok(QueryPdu::PublishDeltaElement(
                            PublishDeltaElement::Update(
                                Update {
                                    tag,
                                    uri,
                                    content,
                                    hash,
                                }
                            )
                        ))
                    }
                }
            }
            QueryPduType::Withdraw => {
                let uri = uri.ok_or(XmlError::Malformed)?;
                let hash = hash.ok_or(XmlError::Malformed)?;

                Ok(QueryPdu::PublishDeltaElement(
                    PublishDeltaElement::Withdraw(
                        Withdraw { tag, uri, hash }
                    )
                ))
            }
        };

        let pdu = pdu?;

        pdu_element.take_end(reader)?;

        Ok(Some(pdu))
    }

    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        match self {
            QueryPdu::List => {
                content.element(QUERY_PDU_LIST.into_unqualified())?;
                Ok(())
            }
            QueryPdu::PublishDeltaElement(el) => el.write_xml(content)
        }
    }

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

/// # Encode to XML
/// 
impl PublishDeltaElement {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        match self {
            PublishDeltaElement::Publish(p) => p.write_xml(content),
            PublishDeltaElement::Update(u) => u.write_xml(content),
            PublishDeltaElement::Withdraw(w) => w.write_xml(content)
        }
    }
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

/// # Encode to XML
/// 
impl Publish {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        content
            .element(QUERY_PDU_PUBLISH.into_unqualified())?
            .attr("tag", self.tag_for_xml())?
            .attr("uri", &self.uri)?
            .content(|content| content.raw(&self.content))?;

        Ok(())
    }

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

/// # Encode to XML
/// 
impl Update {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        content
            .element(QUERY_PDU_PUBLISH.into_unqualified())?
            .attr("tag", self.tag_for_xml())?
            .attr("uri", &self.uri)?
            .attr("hash", &self.hash)?
            .content(|content| content.raw(&self.content))?;

        Ok(())
    }

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

/// # Encode to XML
/// 
impl Withdraw {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        content.element(QUERY_PDU_WITHDRAW.into_unqualified())?
            .attr("tag", self.tag_for_xml())?
            .attr("uri", &self.uri)?
            .attr("hash", &self.hash)?;
        
        Ok(())
    }


    fn tag_for_xml(&self) -> &str {
        self.tag.as_deref().unwrap_or("")
    }
}


//------------ ReplyMessage --------------------------------------------------

/// This type represents query type Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyMessage {
    ListReply(ListReply),
    Success,
    ErrorReply(ErrorReply),
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
    // If this is a 'report_error' type reply then there MUST be one or more
    // PDU presents - of type <report_error />. There can be no other PDU
    // types.
    //
    // If this is a 'list' type reply then there can be zero or more <list />
    // PDUs for each currently published object. There can be no other PDU
    // types.
    //
    // So, in short we need to do a bit of probing of elements to figure out
    // which kind of reply we're actually dealing with. We need to parse ALL
    // PDUs and then figure out if the message was correct at all, and which
    // type it is.
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
            let mut error_code: Option<ReportErrorCode> = None;

            let pdu_element = content.take_opt_element(reader, |element| {
                // Determine the PDU type
                pdu_type = Some(match element.name().local() {
                    LIST_LOCAL => Ok(ReplyPduType::List),
                    SUCCESS_LOCAL => Ok(ReplyPduType::Success),
                    REPORT_ERROR_LOCAL => Ok(ReplyPduType::Error),
                    _ => Err(XmlError::Malformed)
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
                        // let error_code_str = value.ascii_into()?;
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
                ReplyPduType::Error => {
                    if pdus.iter().any(|existing| {
                        existing.kind() != ReplyPduType::Error
                    }) {
                        error!("Found error report in non-error reply");
                        return Err(Error::XmlError(XmlError::Malformed));
                    } else {
                        let error = ReportError::decode_inner(
                            error_code.ok_or(XmlError::Malformed)?,
                            tag,
                            &mut pdu_element,
                            reader
                        )?;
                        
                        pdus.push(ReplyPdu::Error(error));
                    }
                }
            }

            // close the processed PDU
            pdu_element.take_end(reader)?;
        }

        let reply_kind = match pdus.get(0) {
            Some(el) => el.kind(),
            None => ReplyPduType::List
        };

        match reply_kind {
            ReplyPduType::Success => Ok(ReplyMessage::Success),
            ReplyPduType::List => {
                let mut list = ListReply::default();
                for pdu in pdus.into_iter() {
                    if let ReplyPdu::List(el) = pdu {
                        list.elements.push(el);
                    }
                }
                Ok(ReplyMessage::ListReply(list))
            }
            ReplyPduType::Error => {
                let mut errors  = ErrorReply::default();
                for pdu in pdus.into_iter() {
                    if let ReplyPdu::Error(err) = pdu {
                        errors.errors.push(err);
                    }
                }
                Ok(ReplyMessage::ErrorReply(errors))
            }
        }
    }
}

/// # Encode to XML
/// 
impl ReplyMessage {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        match self {
            ReplyMessage::ListReply(list) => {
                for el in &list.elements {
                    el.write_xml(content)?;
                }
            }
            ReplyMessage::Success => {
                content.element(SUCCESS.into_unqualified())?;
            }
            ReplyMessage::ErrorReply(errors) => {
                for err in &errors.errors {
                    err.write_xml(content)?;
                }
            }
        }
        Ok(())
    }
}

//------------ ReplyPduType --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyPduType {
    List,
    Success,
    Error,
}


//------------ ReplyPdu ------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyPdu {
    List(ListElement),
    Success,
    Error(ReportError),
}

impl ReplyPdu {
    fn kind(&self) -> ReplyPduType {
        match self {
            ReplyPdu::List(_) => ReplyPduType::List,
            ReplyPdu::Success => ReplyPduType::Success,
            ReplyPdu::Error(_) => ReplyPduType::Error
        }
    }
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

/// # Encoding to XML
/// 
impl ListElement {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        content
            .element(LIST.into_unqualified())?
            .attr("uri", &self.uri)?
            .attr("hash", &self.hash)?;

        Ok(())
    }
}

//------------ ErrorReply ----------------------------------------------------

/// This type represents the error report as described in
/// https://tools.ietf.org/html/rfc8181#section-3.5 and 3.6
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ErrorReply {
    errors: Vec<ReportError>,
}


//------------ ReportError ---------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportError {
    error_code: ReportErrorCode,
    tag: Option<String>,
    error_text: Option<String>,
    failed_pdu: Option<QueryPdu>,
}

/// # Encode to XML
/// 
impl ReportError {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        content
            .element(REPORT_ERROR.into_unqualified())?
            .attr("error_code", &self.error_code)?
            .attr("tag", self.tag_for_xml())?
            .content(|content| {
                content
                    .element(REPLY_PDU_ERROR_TEXT.into_unqualified())?
                    .content(|error_text_content|
                        error_text_content.raw(self.error_text_or_default())
                    )?;

                content
                    .opt_element(
                        self.failed_pdu.as_ref(),
                        REPLY_PDU_ERROR_PDU.into_unqualified(),
                        |pdu, el| {
                            el.content(|content| pdu.write_xml(content))?;
                            Ok(())
                        }
                    )?;
                
                Ok(())
            })?;

        Ok(())
    }

    fn tag_for_xml(&self) -> &str {
        self.tag.as_deref().unwrap_or("")
    }

    fn error_text_or_default(&self) -> &str {
        self.error_text.as_deref()
                .unwrap_or_else(|| self.error_code.to_text())
    }
}

/// Decode from XML support
/// 
impl ReportError {
    /// Decodes the inner elements nested inside <report_error>.
    // 
    // Expects the error_code and tag to be supplied because those are
    // attributes on the <report_error> element.
    fn decode_inner<R: io::BufRead>(
        error_code: ReportErrorCode,
        tag: Option<String>,
        report_error_element: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        let mut error_text: Option<String> = None;
        let mut failed_pdu: Option<QueryPdu> = None;
        
        // if only we could look ahead to see if/what elements
        // are present then this would be easier..
        loop {
            let mut error_text_found = false;
            let mut failed_pdu_found = false;
            
            let error_element = report_error_element.take_opt_element(
                reader,
                |error_element| {
                    match error_element.name() {
                        REPLY_PDU_ERROR_TEXT => {
                            error_text_found = true;
                            Ok(())
                        }
                        REPLY_PDU_ERROR_PDU => {
                            failed_pdu_found = true;
                            Ok(())
                        }
                        _ => {
                            println!("Found: {:?}", error_element.name());
                            Err(XmlError::Malformed)
                        }
                    }
                }
            )?;
            
            // get the element, break if there was none
            let mut el = match error_element {
                Some(el) => el,
                None => break
            };
            
            if error_text_found {
                let text = el.take_text( reader, |text| {
                    text.to_ascii().map(|t| t.to_string())
                })?;
                
                error_text = Some(text);
            }
            
            if failed_pdu_found {
                failed_pdu = QueryPdu::decode_opt(&mut el, reader)?;
            }

            // close element
            el.take_end(reader)?;
        }

        Ok(ReportError { error_code, tag, error_text, failed_pdu })
    }
}

//------------ ReportErrorCodes ----------------------------------------------

/// The allowed error codes defined in RFC8181 section 2.5
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReportErrorCode {
    XmlError,
    PermissionFailure,
    BadCmsSignature,
    ObjectAlreadyPresent,
    NoObjectPresent,
    NoObjectMatchingHash,
    ConsistencyProblem,
    OtherError,
}

impl fmt::Display for ReportErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReportErrorCode::XmlError => write!(f, "xml_error"),
            ReportErrorCode::PermissionFailure => write!(f, "permission_failure"),
            ReportErrorCode::BadCmsSignature => write!(f, "bad_cms_signature"),
            ReportErrorCode::ObjectAlreadyPresent => write!(f, "object_already_present"),
            ReportErrorCode::NoObjectPresent => write!(f, "no_object_present"),
            ReportErrorCode::NoObjectMatchingHash => write!(f, "no_object_matching_hash"),
            ReportErrorCode::ConsistencyProblem => write!(f, "consistency_problem"),
            ReportErrorCode::OtherError => write!(f, "other_error"),
        }
    }
}

impl FromStr for ReportErrorCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "xml_error" => Ok(ReportErrorCode::XmlError),
            "permission_failure" => Ok(ReportErrorCode::PermissionFailure),
            "bad_cms_signature" => Ok(ReportErrorCode::BadCmsSignature),
            "object_already_present" => Ok(ReportErrorCode::ObjectAlreadyPresent),
            "no_object_present" => Ok(ReportErrorCode::NoObjectPresent),
            "no_object_matching_hash" => Ok(ReportErrorCode::NoObjectMatchingHash),
            "consistency_problem" => Ok(ReportErrorCode::ConsistencyProblem),
            "other_error" => Ok(ReportErrorCode::OtherError),
            _ => Err(Error::InvalidErrorCode(s.to_string())),
        }
    }
}

impl ReportErrorCode {
    /// Provides default texts for error codes (taken from RFC).
    fn to_text(&self) -> &str {
        match self {
            ReportErrorCode::XmlError => "Encountered an XML problem.",
            ReportErrorCode::PermissionFailure => "Client does not have permission to update this URI.",
            ReportErrorCode::BadCmsSignature => "Encountered bad CMS signature.",
            ReportErrorCode::ObjectAlreadyPresent => "An object is already present at this URI, yet a \"hash\" attribute was not specified.",
            ReportErrorCode::NoObjectPresent => "There is no object present at this URI, yet a \"hash\" attribute was specified.",
            ReportErrorCode::NoObjectMatchingHash => "The \"hash\" attribute supplied does not match the \"hash\" attribute of the object at this URI.",
            ReportErrorCode::ConsistencyProblem => "Server detected an update that looks like it will cause a consistency problem (e.g., an object was deleted, but the manifest was not updated).",
            ReportErrorCode::OtherError => "Found some other issue."
        }
    }
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
    InvalidErrorCode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidVersion => write!(f, "Invalid version"),
            Error::XmlError(e) => e.fmt(f),
            Error::InvalidErrorCode(code) => {
                write!(f, "Invalid error code: {}", code)
            }
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

    #[test]
    fn parse_and_error_reply() {
        let xml = include_bytes!("../../test-data/remote/rfc8181/error-reply.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();

        println!("{}", re_encoded);

        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }
}