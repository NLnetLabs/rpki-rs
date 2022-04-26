//! Support for RFC 8181 Publication Messages

use std::fmt;
use std::io;
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use log::error;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer
};

use crate::repository::Cert;
use crate::repository::Crl;
use crate::repository::Manifest;
use crate::repository::Roa;
use crate::repository::aspa::Aspa;
use crate::repository::crypto::Signer;
use crate::repository::crypto::SigningError;
use crate::repository::x509::Time;
use crate::repository::x509::ValidationError;
use crate::repository::x509::Validity;
use crate::rrdp;
use crate::uri;
use crate::xml;
use crate::xml::decode::{
    Content, Error as XmlError
};
use crate::xml::encode;

use super::idcert::IdCert;
use super::sigmsg::SignedMessage;

// Constants for the RFC 8183 XML
const VERSION: &str = "4";
const NS: &[u8] = b"http://www.hactrn.net/uris/rpki/publication-spec/";

const MSG: &[u8] = b"msg";
const LIST: &[u8] = b"list";
const SUCCESS: &[u8] = b"success";
const PUBLISH: &[u8] = b"publish";
const WITHDRAW: &[u8] = b"withdraw";
const REPORT_ERROR: &[u8] = b"report_error";
const ERROR_TEXT: &[u8] = b"error_text";
const FAILED_PDU: &[u8] = b"failed_pdu";

// Content-type for HTTP(s) exchanges
pub const CONTENT_TYPE: &str = "application/rpki-publication";

//------------ PublicationCms ------------------------------------------------

// This type represents a created, or parsed, RFC 8181 CMS object.
#[derive(Clone, Debug)]
pub struct PublicationCms {
    signed_msg: SignedMessage,
    message: Message,
}

impl PublicationCms {
    /// Creates a publication CMS for the given content and signing (ID) key.
    /// This will use a validity time of five minutes before and after 'now'
    /// in order to allow for some NTP drift as well as processing delay
    /// between generating this CMS, sending it, and letting the receiver
    /// validate it.
    pub fn create<S: Signer>(
        message: Message,
        issuing_key_id: &S::KeyId,
        signer: &S,
    ) -> Result<Self, SigningError<S::Error>> {
        let data = message.to_xml_bytes();
        let validity = Validity::new(
            Time::five_minutes_ago(),
            Time::five_minutes_from_now()
        );

        let signed_msg = SignedMessage::create(
            data,
            validity,
            issuing_key_id,
            signer
        )?;

        Ok(PublicationCms { signed_msg, message})
    }

    /// Unpack into its SignedMessage and Message
    pub fn unpack(self) -> (SignedMessage, Message) {
        (self.signed_msg, self.message)
    }

    pub fn into_message(self) -> Message {
        self.message
    }

    /// Encode this to Bytes
    pub fn to_bytes(&self) -> Bytes {
        self.signed_msg.to_captured().into_bytes()
    }

    /// Decodes the CMS and enclosed publication Message from the source.
    pub fn decode(
        bytes: &[u8]
    ) -> Result<Self, Error> {
        let signed_msg = SignedMessage::decode(bytes, false)
            .map_err(|e| Error::CmsDecode(e.to_string()))?;

        let content = signed_msg.content().to_bytes();
        let message = Message::decode(content.as_ref())?;

        Ok(PublicationCms { signed_msg, message })
    }

    pub fn validate(&self, issuer: &IdCert) -> Result<(), Error> {
        self.signed_msg.validate(issuer).map_err(|e| e.into())
    }

    pub fn validate_at(
        &self, issuer: &IdCert, when: Time
    ) -> Result<(), Error> {
        self.signed_msg.validate_at(issuer, when).map_err(|e| e.into())
    }
}


//------------ Message -------------------------------------------------------

/// This type represents all Publication Messages defined in RFC8181
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    Query(Query),
    Reply(Reply),
}

/// Constructing
///
impl Message {
    pub fn list_query() -> Self {
        Message::Query(Query::List)
    }

    pub fn list_reply(reply: ListReply) -> Self {
        Message::Reply(Reply::List(reply))
    }

    pub fn delta(delta: PublishDelta) -> Self {
        Message::Query(Query::Delta(delta))
    }

    pub fn success() -> Self {
        Message::Reply(Reply::Success)
    }

    pub fn error(error: ErrorReply) -> Self {
        Message::Reply(Reply::ErrorReply(error))
    }
}

/// # Access
/// 
impl Message {
    pub fn as_reply(self) -> Result<Reply, Error> {
        match self {
            Message::Query(_) => Err(Error::NotReply),
            Message::Reply(reply) => Ok(reply)
        }
    }

    pub fn as_query(self) -> Result<Query, Error> {
        match self {
            Message::Query(query) => Ok(query),
            Message::Reply(_) => Err(Error::NotQuery),
        }
    }
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
            Message::Query(_) => "query",
            Message::Reply(_) => "reply",
        };

        writer.element(MSG.into())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("type", type_value)?
            .content(|content|{
                match self {
                    Message::Query(msg) => msg.write_xml(content),
                    Message::Reply(msg) => msg.write_xml(content)
                }
            })?;
        writer.done()
    }

    /// Writes the Message's XML representation to a new String.
    pub fn to_xml_string(&self) -> String {
        let bytes = self.to_xml_bytes();
        
        std::str::from_utf8(&bytes)
            .unwrap() // safe
            .to_string()
    }

    /// Writes the Message's XML representation to a new Bytes
    pub fn to_xml_bytes(&self) -> Bytes {
        let mut vec = vec![];
        self.write_xml(&mut vec).unwrap(); // safe
        
        Bytes::from(vec)
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
            if element.name().local() != MSG {
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
            MessageKind::Query => Message::Query(
                Query::decode(&mut outer, &mut reader)?
            ),
            MessageKind::Reply => Message::Reply(
                Reply::decode(&mut outer, &mut reader)?
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
pub enum Query {
    List,
    Delta(PublishDelta),
}


/// # Decoding from XML
/// 
impl Query {
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
            Ok(Query::List)
        } else {
            let mut delta = PublishDelta::default();
            for pdu in pdus.into_iter() {
                match pdu {
                    QueryPdu::List => {} // should be unreachable,
                    QueryPdu::PublishDeltaElement(el) => delta.0.push(el)
                }
            }
            Ok(Query::Delta(delta))
        }
    }
}


/// # Encoding to XML
/// 
impl Query {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        match self {
            Query::List => {
                content.element(LIST.into())?;
            },
            Query::Delta(delta) => {
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
            pdu_type = Some(match element.name().local() {
                LIST => Ok(QueryPduType::List),
                PUBLISH => Ok(QueryPduType::Publish),
                WITHDRAW => Ok(QueryPduType::Withdraw),
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
                content.element(LIST.into())?;
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

impl PublishDelta {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn add_publish(&mut self, publish: Publish) {
        self.0.push(PublishDeltaElement::Publish(publish));
    }

    pub fn add_update(&mut self, update: Update) {
        self.0.push(PublishDeltaElement::Update(update));
    }

    pub fn add_withdraw(&mut self, withdraw: Withdraw) {
        self.0.push(PublishDeltaElement::Withdraw(withdraw));
    }

    pub fn into_elements(self) -> Vec<PublishDeltaElement> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::ops::Add for PublishDelta {
    
    type Output = PublishDelta;

    fn add(mut self, mut other: Self) -> Self::Output {
        self.0.append(&mut other.0);
        self
    }
}


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

/// # Data and Access
/// 
impl Publish {
    pub fn new(
        tag: Option<String>,
        uri: uri::Rsync,
        content: Base64
    ) -> Self {
        Publish { tag, uri, content }
    }

    pub fn with_hash_tag(uri: uri::Rsync, content: Base64) -> Self {
        let tag = Some(content.to_hash().to_string());
        Publish { tag, uri, content }
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn content(&self) -> &Base64 {
        &self.content
    }

    pub fn unpack(self) -> (Option<String>, uri::Rsync, Base64) {
        (self.tag, self.uri, self.content)
    }
}

/// # Encode to XML
/// 
impl Publish {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        content
            .element(PUBLISH.into())?
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

/// # Data and Access
/// 
impl Update {
    pub fn new(
        tag: Option<String>,
        uri: uri::Rsync,
        content: Base64,
        old_hash: rrdp::Hash
    ) -> Self {
        Update {
            tag,
            uri,
            content,
            hash: old_hash,
        }
    }

    pub fn with_hash_tag(
        uri: uri::Rsync,
        content: Base64,
        old_hash: rrdp::Hash
    ) -> Self {
        let tag = Some(content.to_hash().to_string());
        Update {
            tag,
            uri,
            content,
            hash: old_hash,
        }
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn content(&self) -> &Base64 {
        &self.content
    }

    pub fn hash(&self) -> &rrdp::Hash {
        &self.hash
    }

    pub fn unpack(self) -> (Option<String>, uri::Rsync, Base64, rrdp::Hash) {
        (self.tag, self.uri, self.content, self.hash)
    }
}

/// # Encode to XML
/// 
impl Update {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        content
            .element(PUBLISH.into())?
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

/// # Data and Access
/// 
impl Withdraw {
    pub fn new(tag: Option<String>, uri: uri::Rsync, hash: rrdp::Hash) -> Self {
        Withdraw { tag, uri, hash }
    }

    pub fn with_hash_tag(uri: uri::Rsync, hash: rrdp::Hash) -> Self {
        let tag = Some(hash.to_string());
        Withdraw { tag, uri, hash }
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()

    }
    
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn hash(&self) -> &rrdp::Hash {
        &self.hash
    }

    pub fn unpack(self) -> (Option<String>, uri::Rsync, rrdp::Hash) {
        (self.tag, self.uri, self.hash)
    }
}

/// # Encode to XML
/// 
impl Withdraw {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        content.element(WITHDRAW.into())?
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
pub enum Reply {
    List(ListReply),
    Success,
    ErrorReply(ErrorReply),
}

impl Reply {
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
                    LIST => Ok(ReplyPduType::List),
                    SUCCESS => Ok(ReplyPduType::Success),
                    REPORT_ERROR => Ok(ReplyPduType::Error),
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
            ReplyPduType::Success => Ok(Reply::Success),
            ReplyPduType::List => {
                let mut list = ListReply::default();
                for pdu in pdus.into_iter() {
                    if let ReplyPdu::List(el) = pdu {
                        list.elements.push(el);
                    }
                }
                Ok(Reply::List(list))
            }
            ReplyPduType::Error => {
                let mut errors  = ErrorReply::default();
                for pdu in pdus.into_iter() {
                    if let ReplyPdu::Error(err) = pdu {
                        errors.errors.push(err);
                    }
                }
                Ok(Reply::ErrorReply(errors))
            }
        }
    }
}

/// # Encode to XML
/// 
impl Reply {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        match self {
            Reply::List(list) => {
                for el in &list.elements {
                    el.write_xml(content)?;
                }
            }
            Reply::Success => {
                content.element(SUCCESS.into())?;
            }
            Reply::ErrorReply(errors) => {
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

impl ListReply {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new(elements: Vec<ListElement>) -> Self {
        ListReply { elements }
    }

    pub fn add_element(&mut self, element: ListElement) {
        self.elements.push(element);
    }

    pub fn elements(&self) -> &Vec<ListElement> {
        &self.elements
    }

    pub fn into_elements(self) -> Vec<ListElement> {
        self.elements
    }

    pub fn into_withdraw_delta(self) -> PublishDelta {
        let mut delta = PublishDelta::empty();

        for el in self.elements.into_iter() {
            let (uri, hash) = el.unpack();
            let withdraw = Withdraw::with_hash_tag(uri, hash);
            delta.add_withdraw(withdraw);

        }

        delta
    }
}


//------------ ListElement ---------------------------------------------------

/// This type represents a single object that is published at a publication
/// server.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ListElement {
    uri: uri::Rsync,
    hash: rrdp::Hash,
}

/// # Data and Access
/// 
impl ListElement {
    pub fn new(
        uri: uri::Rsync,
        hash: rrdp::Hash
    ) -> Self {
        ListElement { uri, hash }
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn hash(&self) -> &rrdp::Hash {
        &self.hash
    }

    pub fn unpack(self) -> (uri::Rsync, rrdp::Hash) {
        (self.uri, self.hash)
    }
}

/// # Encoding to XML
/// 
impl ListElement {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        content
            .element(LIST.into())?
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

/// # Data and Access
/// 
impl ErrorReply {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn for_error(error: ReportError) -> Self {
        ErrorReply { errors: vec![error] }
    }

    pub fn add_error(&mut self, error: ReportError) {
        self.errors.push(error)
    }

    pub fn errors(&self) -> &Vec<ReportError> {
        &self.errors
    }
}

impl fmt::Display for ErrorReply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "error reply including: ")?;
        for err in &self.errors {
            match &err.error_text {
                None => write!(f, "error code: {} ", err.error_code)?,
                Some(text) => write!(f, "error code: {}, text: {} ", err.error_code, text)?,
            }
        }
        Ok(())
    }
}

//------------ ReportError ---------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportError {
    error_code: ReportErrorCode,
    tag: Option<String>,
    error_text: Option<String>,
    failed_pdu: Option<QueryPdu>,
}

/// # Construct
/// 
impl ReportError {

    /// Creates an entry to include in an ErrorReply.
    pub fn with_code(
        error_code: ReportErrorCode,
    ) -> Self {
        let error_text = Some(error_code.to_text().to_string());

        ReportError {
            error_code,
            tag: None,
            error_text,
            failed_pdu: None,
        }
    }
}

/// # Encode to XML
/// 
impl ReportError {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        content
            .element(REPORT_ERROR.into())?
            .attr("error_code", &self.error_code)?
            .attr_opt("tag", self.tag.as_ref())?
            .content(|content| {
                content
                    .element(ERROR_TEXT.into())?
                    .content(|error_text_content|
                        error_text_content.raw(self.error_text_or_default())
                    )?;

                content
                    .element_opt(
                        self.failed_pdu.as_ref(),
                        FAILED_PDU.into(),
                        |pdu, el| {
                            el.content(|content| pdu.write_xml(content))?;
                            Ok(())
                        }
                    )?;
                
                Ok(())
            })?;

        Ok(())
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
                    match error_element.name().local() {
                        ERROR_TEXT => {
                            error_text_found = true;
                            Ok(())
                        }
                        FAILED_PDU => {
                            failed_pdu_found = true;
                            Ok(())
                        }
                        _ => {
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

    /// Decodes into bytes (e.g. for saving to disk for rsync)
    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(base64::decode(self.0.as_bytes()).unwrap())
    }

    /// Generates the rrdp::Hash for the base64 encoded content
    pub fn to_hash(&self) -> rrdp::Hash {
        rrdp::Hash::from_data(self.to_bytes().as_ref())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_ref()
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
        self.as_str().serialize(serializer)
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

impl From<&Cert> for Base64 {
    fn from(cert: &Cert) -> Self {
        Base64::from_content(&cert.to_captured().into_bytes())
    }
}

impl From<&Roa> for Base64 {
    fn from(roa: &Roa) -> Self {
        Base64::from_content(&roa.to_captured().into_bytes())
    }
}

impl From<&Aspa> for Base64 {
    fn from(aspa: &Aspa) -> Self {
        Base64::from_content(&aspa.to_captured().into_bytes())
    }
}

impl From<&Manifest> for Base64 {
    fn from(mft: &Manifest) -> Self {
        Base64::from_content(&mft.to_captured().into_bytes())
    }
}

impl From<&Crl> for Base64 {
    fn from(crl: &Crl) -> Self {
        Base64::from_content(&crl.to_captured().into_bytes())
    }
}

//------------ PublicationMessageError ---------------------------------------

#[derive(Debug)]
pub enum Error {
    InvalidVersion,
    XmlError(XmlError),
    InvalidErrorCode(String),
    CmsDecode(String),
    Validation(ValidationError),
    NotQuery,
    NotReply
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidVersion => write!(f, "Invalid version"),
            Error::XmlError(e) => e.fmt(f),
            Error::InvalidErrorCode(code) => {
                write!(f, "Invalid error code: {}", code)
            }
            Error::CmsDecode(msg) => {
                write!(f, "Could not decode CMS: {}", msg)
            }
            Error::Validation(e) => {
                write!(f, "CMS is not valid: {}", e)
            }
            Error::NotQuery => {
                write!(f, "was not a query message")
            }
            Error::NotReply => {
                write!(f, "was not a reply message")
            }
        }
    }
}

impl From<XmlError> for Error {
    fn from(e: XmlError) -> Self {
        Error::XmlError(e)
    }
}

impl From<ValidationError> for Error {
    fn from(e: ValidationError) -> Self {
        Error::Validation(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parse_and_encode_list_query() {
        let xml = include_bytes!("../../test-data/ca/rfc8181/list.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_encode_publish_multi_query() {
        let xml = include_bytes!("../../test-data/ca/rfc8181/publish-multi.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_encode_publish_single_query() {
        let xml = include_bytes!("../../test-data/ca/rfc8181/publish-single.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_encode_publish_empty_query() {
        let xml = include_bytes!("../../test-data/ca/rfc8181/publish-empty.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_encode_publish_empty_short_query() {
        let xml = include_bytes!("../../test-data/ca/rfc8181/publish-empty-short.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_list_reply() {
        let xml = include_bytes!("../../test-data/ca/rfc8181/list-reply.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_list_reply_single() {
        let xml = include_bytes!("../../test-data/ca/rfc8181/list-reply-single.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_list_reply_empty() {
        let xml = include_bytes!("../../test-data/ca/rfc8181/list-reply-empty.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_list_reply_empty_short() {
        let xml = include_bytes!("../../test-data/ca/rfc8181/list-reply-empty-short.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_success_reply() {
        let xml = include_bytes!("../../test-data/ca/rfc8181/success-reply.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }

    #[test]
    fn parse_and_error_reply() {
        let xml = include_bytes!("../../test-data/ca/rfc8181/error-reply.xml");
        let msg = Message::decode(xml.as_ref()).unwrap();

        let re_encoded = msg.to_xml_string();
        let re_decoded = Message::decode(re_encoded.as_bytes()).unwrap();

        assert_eq!(msg, re_decoded);
    }
}


#[cfg(all(test, feature="softkeys"))]
mod signer_test {

    use super::*;

    use crate::{
        ca::idcert::IdCert,
        repository::crypto::{softsigner::{OpenSslSigner, KeyId}, PublicKeyFormat}
    };

    fn sign_and_validate_msg(
        signer: &OpenSslSigner,
        ta_key: KeyId,
        ta_cert: &IdCert,
        message: Message
    ) {
        let cms = PublicationCms::create(
            message.clone(),
            &ta_key,
            signer
        ).unwrap();

        let bytes = cms.to_bytes();

        let decoded = PublicationCms::decode(&bytes).unwrap();
        decoded.validate(ta_cert).unwrap();

        let decoded_message = decoded.into_message();

        assert_eq!(message, decoded_message);
    }

    fn element(uri: &str, content: &[u8]) -> ListElement {
        let uri = uri::Rsync::from_str(uri).unwrap();
        let hash = Base64::from_content(content).to_hash();

        ListElement::new(uri, hash)
    }

    fn publish(uri: &str, content: &[u8]) -> Publish {
        let uri = uri::Rsync::from_str(uri).unwrap();
        let content = Base64::from_content(content);

        Publish::with_hash_tag(uri, content)
    }

    fn update(uri: &str, content: &[u8], old_content: &[u8]) -> Update {
        let uri = uri::Rsync::from_str(uri).unwrap();
        let content = Base64::from_content(content);

        let hash = Base64::from_content(old_content).to_hash();

        Update::with_hash_tag(uri, content, hash)
    }

    fn withdraw(uri: &str, content: &[u8]) -> Withdraw {
        let uri = uri::Rsync::from_str(uri).unwrap();
        let hash = Base64::from_content(content).to_hash();

        Withdraw::with_hash_tag(uri, hash)
    }

    #[test]
    fn sign_and_validate() {
        let signer = OpenSslSigner::new();

        let key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
        let cert = IdCert::new_ta(
            Validity::from_secs(60),
            &key,
            &signer
        ).unwrap();

        sign_and_validate_msg(&signer, key, &cert, Message::list_query());

        let mut rpl = ListReply::empty();
        rpl.add_element(element("rsync://localhost/ca/f1.txt", b"a"));
        rpl.add_element(element("rsync://localhost/ca/f2.txt", b"b"));
        rpl.add_element(element("rsync://localhost/ca/f3.txt", b"c"));
        sign_and_validate_msg(&signer, key, &cert, Message::list_reply(rpl));

        let mut delta = PublishDelta::empty();
        delta.add_publish(publish("rsync://localhost/ca/f1.txt", b"a"));
        delta.add_update(update("rsync://localhost/ca/f2.txt", b"b", b"c"));
        delta.add_withdraw(withdraw("rsync://localhost/ca/f3.txt", b"d"));
        sign_and_validate_msg(&signer, key, &cert, Message::delta(delta));

        sign_and_validate_msg(&signer, key, &cert, Message::success());

        let mut error_reply = ErrorReply::empty();
        let error = ReportError::with_code(ReportErrorCode::PermissionFailure);
        error_reply.add_error(error);
        sign_and_validate_msg(&signer, key, &cert, Message::error(error_reply));
    }
}