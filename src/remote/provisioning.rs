//! Support RFC 6492 Provisioning Protocol (aka up-down)

use std::{io, fmt};

use crate::xml;
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

const PAYLOAD_TYPE_LIST: &str = "list";


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
pub enum Payload {
    List
}

/// # Decoding from XML
/// 
impl Payload {
    /// Decodes the nested payload, needs to be given the value of the 'type'
    /// attribute from the outer <message /> element so it can delegate to the
    /// proper enclosed payload variant.
    fn decode<R: io::BufRead>(
        payload_type: String,
        _content: &mut Content,
        _reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        match payload_type.as_str() {
            PAYLOAD_TYPE_LIST => Ok(Payload::List),
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
            Payload::List => PAYLOAD_TYPE_LIST
        }
    }

    /// Encode payload content
    fn write_xml<W: io::Write>(
        &self,
        _content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        match self {
            Payload::List => Ok(()) // nothing to write
        }
    }
}


//------------ ProvisioningMessageError --------------------------------------

#[derive(Debug)]
pub enum Error {
    InvalidVersion,
    XmlError(XmlError),
    InvalidErrorCode(String),
    InvalidPayloadType(String),
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






}