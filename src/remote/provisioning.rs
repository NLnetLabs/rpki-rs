//! Support RFC 6492 Provisioning Protocol (aka up-down)

use std::str::FromStr;
use std::sync::Arc;
use std::{io, fmt};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer
};

use crate::repository::Csr;
use crate::repository::resources::{AsBlocks, IpBlocks};
use crate::{xml, uri};
use crate::xml::decode::{
    Content, Error as XmlError
};
use crate::xml::encode;

use super::idexchange::Handle;


// Some type aliases that help make the context of Handles more explicit.
pub type Sender = Handle;
pub type Recipient = Handle;

// Constants for the RFC 6492 XML
const VERSION: &str = "1";
const NS: &[u8] = b"http://www.apnic.net/specs/rescerts/up-down/";

const MESSAGE: &[u8] = b"message";
const REQUEST: &[u8] = b"request";

const PAYLOAD_TYPE_LIST: &str = "list";
const PAYLOAD_TYPE_ISSUE: &str = "issue";


// Content-type for HTTP(s) exchanges
pub const CONTENT_TYPE: &str = "application/rpki-updown";

//------------ Message -------------------------------------------------------

/// This type represents all Provisioning Messages defined in RFC 6492.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    sender: Sender,
    recipient: Recipient,
    payload: Payload,
}

/// # Encoding to XML
/// 
impl Message {
    /// Writes the Message's XML representation.
    pub fn write_xml(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);

        writer.element(MESSAGE.into())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("sender", &self.sender)?
            .attr("recipient", &self.recipient)?
            .attr("type", self.payload.payload_type())?
            .content(|content| self.payload.write_xml(content) )?;

        writer.done()
    }

    /// Writes the Message's XML representation to a new String.
    pub  fn to_xml_string(&self) -> String {
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
    /// Parses an RFC 6492 <message />
    pub fn decode<R: io::BufRead>(reader: R) -> Result<Self, Error> {
        
        let mut reader = xml::decode::Reader::new(reader);

        let mut sender: Option<Sender> = None;
        let mut recipient: Option<Recipient> = None;
        let mut payload_type: Option<String> = None;

        let mut outer = reader.start(|element| {
            if element.name().local() != MESSAGE {
                return Err(XmlError::Malformed)
            }
            
            
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<String>()? != VERSION {
                        return Err(XmlError::Malformed)
                    }
                    Ok(())
                }
                b"sender" => {
                    sender = Some(value.ascii_into()?);
                    Ok(())
                }
                b"recipient" => {
                    recipient = Some(value.ascii_into()?);
                    Ok(())
                }
                b"type" => {
                    payload_type = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => {
                    Err(XmlError::Malformed)
                }
            })
        })?;

        // Get required attributes - return error if anything is missing.
        let sender = sender.ok_or(XmlError::Malformed)?;
        let recipient = recipient.ok_or(XmlError::Malformed)?;
        let payload_type = payload_type.ok_or(XmlError::Malformed)?;

        // Parse the nested payload
        let payload = Payload::decode(
            payload_type,
            &mut outer,
            &mut reader
        )?;

        // Check that there is no additional stuff
        outer.take_end(&mut reader)?;
        reader.end()?;

        Ok(Message { sender, recipient, payload })
    }

}


//------------ Payload -------------------------------------------------------

/// Contains the query or reply payload of the message.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Payload {
    List,
    Issue(IssuanceRequest)
}

/// # Decoding from XML
/// 
impl Payload {
    /// Decodes the nested payload, needs to be given the value of the 'type'
    /// attribute from the outer <message /> element so it can delegate to the
    /// proper enclosed payload variant.
    fn decode<R: io::BufRead>(
        payload_type: String,
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        match payload_type.as_str() {
            PAYLOAD_TYPE_LIST => Ok(Payload::List),
            PAYLOAD_TYPE_ISSUE => {
                let req = IssuanceRequest::decode(content, reader)?;
                Ok(Payload::Issue(req))
            }
            _ => Err(Error::InvalidPayloadType(payload_type))
        }
    }
}

/// # Encoding to XML
/// 
impl Payload {
    /// Value for the type attribute in the <message /> element.
    fn payload_type(&self) -> &str {
        match self {
            Payload::List => PAYLOAD_TYPE_LIST,
            Payload::Issue(_) => PAYLOAD_TYPE_ISSUE
        }
    }

    /// Encode payload content
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        match self {
            Payload::List => Ok(()), // nothing to write
            Payload::Issue(issue) => issue.write_xml(content)
        }
    }
}



//------------ IssuanceRequest -----------------------------------------------

/// This type reflects the content of a Certificate Issuance Request
/// defined in section 3.4.1 of RFC6492.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuanceRequest {
    class_name: ResourceClassName,
    limit: RequestResourceLimit,
    csr: Csr,
}

/// # Data
/// 
impl IssuanceRequest {
    pub fn new(
        class_name: ResourceClassName,
        limit: RequestResourceLimit,
        csr: Csr
    ) -> Self {
        IssuanceRequest { class_name, limit, csr }
    }

    pub fn unpack(self) -> (ResourceClassName, RequestResourceLimit, Csr) {
        (self.class_name, self.limit, self.csr)
    }

    pub fn class_name(&self) -> &ResourceClassName {
        &self.class_name
    }
    pub fn limit(&self) -> &RequestResourceLimit {
        &self.limit
    }
    pub fn csr(&self) -> &Csr {
        &self.csr
    }
}

/// Decode from XML
/// 
impl IssuanceRequest {
    /// Decodes an RFC 6492 section 3.4.1 issue request.
    /// 
    /// Requests have the following format. The req_* attributes are
    /// optional:
    /// 
    /// <request
    ///    class_name="class name"
    ///    req_resource_set_as="as resource set"
    ///    req_resource_set_ipv4="ipv4 resource set"
    ///    req_resource_set_ipv6="ipv6 resource set">
    ///    [Certificate request]
    /// </request>
    fn decode<R: io::BufRead>(
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {

        let mut class_name: Option<ResourceClassName> = None;
        let mut limit = RequestResourceLimit::default();

        let mut request_el = content.take_element(reader, |element| {
            if element.name().local() != REQUEST {
                return Err(XmlError::Malformed);
            }

            element.attributes(|name, value| match name {
                b"class_name" => {
                    class_name = Some(value.ascii_into()?);
                    Ok(())
                },
                b"req_resource_set_as" => {
                    limit.set_asn(value.ascii_into()?);
                    Ok(())
                }
                b"req_resource_set_ipv4" => {
                    limit.set_ipv4(value.ascii_into()?);
                    Ok(())
                }
                b"req_resource_set_ipv6" => {
                    limit.set_ipv6(value.ascii_into()?);
                    Ok(())
                }
                _ => {
                    Err(XmlError::Malformed)
                }
            })
        })?;

        let class_name = class_name.ok_or(XmlError::Malformed)?;

        let csr_bytes = request_el.take_text(reader, |text| {
            text.base64_decode()
        })?;

        let csr = Csr::decode(csr_bytes.as_ref())
                        .map_err(|e| Error::InvalidCsr(e.to_string()))?;

        request_el.take_end(reader)?;

        Ok(IssuanceRequest { class_name, limit, csr })
    }
}

/// # Encode to XML
/// 
impl IssuanceRequest {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        content
            .element(REQUEST.into())?
            .attr("class_name", self.class_name())?
            .opt_attr("req_resource_set_as", self.limit().asn_opt())?
            .opt_attr(
                "req_resource_set_ipv4",
                self.limit().v4_opt().map(|blocks| blocks.as_v4()).as_ref()
            )?
            .opt_attr(
                "req_resource_set_ipv6",
                self.limit().v6_opt().map(|blocks| blocks.as_v6()).as_ref()
            )?
            .content(|content| content.base64(
                self.csr().to_captured().as_slice()
            ))?;

        Ok(())
    }
}

impl PartialEq for IssuanceRequest {
    fn eq(&self, other: &IssuanceRequest) -> bool {
        self.class_name == other.class_name
            && self.limit == other.limit
            && self.csr.to_captured().as_slice() == 
                                            other.csr.to_captured().as_slice()
    }
}

impl Eq for IssuanceRequest {}

impl fmt::Display for IssuanceRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ki = self.csr.public_key().key_identifier();
        let none = "<none>".to_string();
        let rpki_notify = self
            .csr
            .rpki_notify()
            .map(uri::Https::to_string)
            .unwrap_or_else(|| none.clone());
        let ca_repo = self
            .csr
            .ca_repository()
            .map(uri::Rsync::to_string)
            .unwrap_or_else(|| none.clone());
        let rpki_manifest = self
            .csr
            .rpki_manifest()
            .map(uri::Rsync::to_string)
            .unwrap_or_else(|| none.clone());

        write!(
            f,
            "class name '{}' limit '{}' csr for key '{}' rrdp notify '{}' ca repo '{}' mft '{}'",
            self.class_name, self.limit, ki, rpki_notify, ca_repo, rpki_manifest
        )
    }
}

//------------ RequestResourceLimit ------------------------------------------

/// The scope of resources that a child CA wants to have certified. By default
/// there are no limits, i.e. all the child wants all resources the parent is
/// willing to give. Only if some values are specified for certain resource
/// types will the scope be limited for that type only. Note that asking for
/// more than you are entitled to as a child, will anger a parent. In this case
/// the IssuanceRequest will be rejected.
///
/// See: https://tools.ietf.org/html/rfc6492#section-3.4.1
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestResourceLimit {
    asn: AsBlocks,
    
    #[serde(
        deserialize_with = "IpBlocks::deserialize_v4",
        serialize_with = "IpBlocks::serialize_v4"
    )]
    v4: IpBlocks,

    #[serde(
        deserialize_with = "IpBlocks::deserialize_v6",
        serialize_with = "IpBlocks::serialize_v6"
    )]
    v6: IpBlocks,
}

impl RequestResourceLimit {
    pub fn new() -> RequestResourceLimit {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.asn.is_empty() && self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn set_asn(&mut self, asn: AsBlocks) {
        self.asn = asn;
    }

    pub fn set_ipv4(&mut self, ipv4: IpBlocks) {
        self.v4 = ipv4;
    }

    pub fn set_ipv6(&mut self, ipv6: IpBlocks) {
        self.v6 = ipv6;
    }

    pub fn asn(&self) -> &AsBlocks {
        &self.asn
    }
    
    pub fn v4(&self) -> &IpBlocks {
        &self.v4
    }
    
    pub fn v6(&self) -> &IpBlocks {
        &self.v6
    }

    /// Returns None if the limit is empty.
    pub fn asn_opt(&self) -> Option<&AsBlocks> {
        if self.asn.is_empty() {
            None
        } else {
            Some(&self.asn)
        }
    }

    /// Returns None if the limit is empty.
    pub fn v4_opt(&self) -> Option<&IpBlocks> {
        if self.v4.is_empty() {
            None
        } else {
            Some(&self.v4)
        }
    }

    /// Returns None if the limit is empty.
    pub fn v6_opt(&self) -> Option<&IpBlocks> {
        if self.v6.is_empty() {
            None
        } else {
            Some(&self.v6)
        }
    }
}

impl Default for RequestResourceLimit {
    fn default() -> Self {
        RequestResourceLimit {
            asn: AsBlocks::empty(),
            v4: IpBlocks::empty(),
            v6: IpBlocks::empty(),
        }
    }
}


//--- Display

impl fmt::Display for RequestResourceLimit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_empty() {
            write!(f, "none")
        } else {
            if !self.asn.is_empty() {
                write!(f, "asn: {} ", self.asn)?;
            }
            if !self.v4.is_empty() {
                write!(f, "ipv4: {} ", self.v4.as_v4())?;
            }
            if !self.v6.is_empty() {
                write!(f, "ipv6: {} ", self.v6.as_v6())?;
            }

            Ok(())
        }
    }
}


//------------ ResourceClassName ---------------------------------------------

/// This type represents a resource class name, as used in RFC6492.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub struct ResourceClassName {
    name: Arc<str>,
}

pub type ParentResourceClassName = ResourceClassName;

impl Default for ResourceClassName {
    fn default() -> ResourceClassName {
        ResourceClassName::from(0)
    }
}

impl AsRef<str> for ResourceClassName {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

impl From<u32> for ResourceClassName {
    fn from(nr: u32) -> ResourceClassName {
        ResourceClassName { name: nr.to_string().into() }
    }
}

impl From<&str> for ResourceClassName {
    fn from(s: &str) -> ResourceClassName {
        ResourceClassName { name: s.into() }
    }
}

impl From<String> for ResourceClassName {
    fn from(s: String) -> ResourceClassName {
        ResourceClassName { name: s.into() }
    }
}

impl FromStr for ResourceClassName {
    type Err = (); // can't fail, FromStr provided for convenience

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ResourceClassName::from(s))
    }
}

//--- Display

impl fmt::Display for ResourceClassName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

//--- Serialize and Deserialize

impl Serialize for ResourceClassName {
    fn serialize<S: Serializer>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ResourceClassName {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D
    ) -> Result<ResourceClassName, D::Error> {
        let string = String::deserialize(deserializer)?;
        Ok(ResourceClassName::from(string))
    }
}


//------------ ProvisioningMessageError --------------------------------------

#[derive(Debug)]
pub enum Error {
    InvalidVersion,
    XmlError(XmlError),
    InvalidErrorCode(String),
    InvalidPayloadType(String),
    InvalidCsr(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidVersion => write!(f, "Invalid version"),
            Error::XmlError(e) => e.fmt(f),
            Error::InvalidErrorCode(code) => {
                write!(f, "Invalid error code: {}", code)
            }
            Error::InvalidPayloadType(payload_type) => {
                write!(f, "Invalid payload type: {}", payload_type)
            }
            Error::InvalidCsr(msg) => {
                write!(f, "Could not decoded CSR: {}", msg)
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

    use std::str::from_utf8_unchecked;
    use crate::remote::sigmsg::SignedMessage;

    use super::*;

    /// Test that the we can re-encode the message to xml, parse it,
    /// and end up with an equal message.
    fn assert_re_encode_equals(msg: Message) {
        let xml = msg.to_xml_string();
        let re_decoded = Message::decode(xml.as_bytes()).unwrap();
        assert_eq!(msg, re_decoded);
    }

    // Extract the XML content from provisioning CMS message that
    // was caught in the wild..
    fn extract_xml(message: &[u8]) -> String {
        let msg = SignedMessage::decode(message, false).unwrap();
        let content = msg.content().to_bytes();
        let xml = unsafe { from_utf8_unchecked(content.as_ref()) };
        xml.to_string()
    }

    #[test]
    fn parse_and_encode_list() {
        let xml = extract_xml(include_bytes!("../../test-data/remote/rfc6492/rpkid-rfc6492-list.der"));
        let list = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(list);
    }

    #[test]
    fn parse_and_encode_issue() {
        let xml = extract_xml(include_bytes!("../../test-data/remote/rfc6492/rpkid-rfc6492-issue.der"));
        let issue = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(issue);
    }
}