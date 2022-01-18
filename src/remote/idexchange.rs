//! Out of band exchange messages.
//!
//! Support for the RFC8183 out-of-band setup requests and responses
//! used to exchange identity and configuration between CAs and their
//! parent CA and/or RPKI Publication Servers.

use std::fmt;
use std::io;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use serde::{
    Deserialize, Serialize, Serializer, Deserializer
};
use crate::repository::x509::Time;
use crate::repository::x509::ValidationError;
use crate::xml;
use crate::xml::decode::{
    Error as XmlError, Name
};
use super::idcert::IdCert;

// Constants for the RFC 8183 XML
const VERSION: &str = "1";
const NS: &[u8] = b"http://www.hactrn.net/uris/rpki/rpki-setup/";
const CHILD_REQUEST: Name = Name::qualified(NS, b"child_request");
const CHILD_BPKI_TA: Name = Name::unqualified(b"child_bpki_ta");


//------------ Handle --------------------------------------------------------

// Some type aliases that help make the context of Handles more explicit.
pub type ParentHandle = Handle;
pub type ChildHandle = Handle;
pub type PublisherHandle = Handle;
pub type RepositoryHandle = Handle;

/// This type represents the identifying 'handles' as used between RPKI
/// entities. Handles are like strings, but they are restricted to the
/// following - taken from the RELAX NG schema in RFC 8183:
/// 
/// handle  = xsd:string { maxLength="255" pattern="[\-_A-Za-z0-9/]*" }
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Handle {
    name: Arc<str>,
}

impl Handle {
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }

    /// We replace "/" with "+" and "\" with "=" to make file system
    /// safe names.
    pub fn to_path_buf(&self) -> PathBuf {
        let s = self.to_string();
        let s = s.replace("/", "+");
        let s = s.replace("\\", "=");
        PathBuf::from(s)
    }
}

impl TryFrom<&PathBuf> for Handle {
    type Error = InvalidHandle;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        if let Some(path) = path.file_name() {
            let s = path.to_string_lossy().to_string();
            let s = s.replace("+", "/");
            let s = s.replace("=", "\\");
            Self::from_str(&s)
        } else {
            Err(InvalidHandle)
        }
    }
}

impl FromStr for Handle {
    type Err = InvalidHandle;

    /// Accepted pattern: [-_A-Za-z0-9/]{1,255}
    /// See Appendix A of RFC8183.
    ///
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.bytes()
            .all(|b| {
                b.is_ascii_alphanumeric() || b == b'-' || b == b'_' ||
                b == b'/' || b == b'\\'
            })
            && !s.is_empty()
            && s.len() < 256
        {
            Ok(Handle { name: s.into() })
        } else {
            Err(InvalidHandle)
        }
    }
}

impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

impl AsRef<[u8]> for Handle {
    fn as_ref(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for Handle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Handle {
    fn deserialize<D>(deserializer: D) -> Result<Handle, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Handle::from_str(&string).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug)]
pub struct InvalidHandle;

impl fmt::Display for InvalidHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Handle MUST have pattern: [-_A-Za-z0-9/]{{1,255}}")
    }
}

//------------ ChildRequest --------------------------------------------------

/// Type representing a <child_request /> defined in section 5.2.1 of
/// RFC8183.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildRequest {
    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,

    /// The handle the child wants to use for itself. This may not be honored
    /// by the parent.
    child_handle: Handle,

    /// The self-signed IdCert containing the child's public key.
    id_cert: IdCert,
}


/// # Data Access
///
impl ChildRequest {
    pub fn new(child_handle: Handle, id_cert: IdCert) -> Self {
        ChildRequest {
            tag: None,
            child_handle,
            id_cert,
        }
    }

    pub fn unpack(self) -> (Option<String>, Handle, IdCert) {
        (self.tag, self.child_handle, self.id_cert)
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }
    pub fn child_handle(&self) -> &Handle {
        &self.child_handle
    }
    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }
}


/// # XML Support
///
impl ChildRequest {
    /// Parses a <child_request /> message, and validates the
    /// embedded certificate. MUST be a validly signed TA cert.
    pub fn validate<R: io::BufRead>(
        reader: R
    ) -> Result<Self, IdExchangeError> {
        Self::validate_at(reader, Time::now())
    }

    /// Writes the ChildRequest's XML representation.
    pub fn write_xml(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);

        writer.element(CHILD_REQUEST.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("child_handle", self.child_handle())?
            .opt_attr("tag", self.tag())?
            .content(|content| {
                content.element(CHILD_BPKI_TA.into_unqualified())?
                    .content(|content| {
                        content.base64(self.id_cert.to_captured().as_slice())
                    })?;
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

    /// Parses a <child_request /> message.
    fn validate_at<R: io::BufRead>(
        reader: R, when: Time
    ) -> Result<Self, IdExchangeError> {
        let mut reader = xml::decode::Reader::new(reader);

        let mut child_handle: Option<ChildHandle> = None;
        let mut tag: Option<String> = None;
        
        let mut outer = reader.start(|element| {
            if element.name() != CHILD_REQUEST {
                return Err(XmlError::Malformed)
            }
            
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<String>()? != VERSION {
                        return Err(XmlError::Malformed)
                    }
                    Ok(())
                }
                b"child_handle" => {
                    child_handle = Some(value.ascii_into()?);
                    Ok(())
                }
                b"tag" => {
                    tag = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => Err(XmlError::Malformed)
            })
        })?;

        let child_handle = child_handle.ok_or(XmlError::Malformed)?;

        let id_cert = {
            let mut content = outer.take_element(&mut reader, |element| {
                if element.name().local() != CHILD_BPKI_TA.local() {
                    Err(XmlError::Malformed)
                } else {
                    Ok(())
                }
            })?;

            let base64 = content.take_text(&mut reader, |text| {
                // The text is supposed to be xsd:base64Binary which only allows
                // the base64 characters plus whitespace.
                text.to_ascii()
                    .map_err(|_| XmlError::Malformed)
                    .map(|text| {
                      text.as_bytes().iter().filter_map(|b| {
                        if b.is_ascii_whitespace() { None }
                        else { Some(*b) }
                    })
                    .collect::<Vec<_>>()  
                })
            })?;

            let bytes = base64::decode(base64)?;

            let id_cert = IdCert::decode(bytes.as_slice())?;
            id_cert.validate_ta_at(when)?;

            content.take_end(&mut reader)?;

            id_cert
        };
        
        outer.take_end(&mut reader)?;
        reader.end()?;

        Ok(ChildRequest { tag, child_handle, id_cert })
    }
}



//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum IdExchangeError {
    InvalidXml(xml::decode::Error),
    InvalidVersion,
    InvalidHandle,
    InvalidTaBase64(base64::DecodeError),
    InvalidTaCertEncoding(bcder::decode::Error),
    InvalidTaCert,
}

impl fmt::Display for IdExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IdExchangeError::InvalidXml(e) => e.fmt(f),
            IdExchangeError::InvalidVersion => write!(f, "Invalid version"),
            IdExchangeError::InvalidHandle => write!(f, "Invalid handle"),
            IdExchangeError::InvalidTaBase64(e) => e.fmt(f),
            IdExchangeError::InvalidTaCertEncoding(e) => {
                write!(f, "Cannot decode TA cert: {}", e)
            },
            IdExchangeError::InvalidTaCert => write!(f, "Invalid TA cert"),
        }
    }
}

impl From<xml::decode::Error> for IdExchangeError {
    fn from(e: xml::decode::Error) -> Self {
        IdExchangeError::InvalidXml(e)
    }
}

impl From<base64::DecodeError> for IdExchangeError {
    fn from(e: base64::DecodeError) -> Self {
        IdExchangeError::InvalidTaBase64(e)
    }
}

impl From<bcder::decode::Error> for IdExchangeError {
    fn from(e: bcder::decode::Error) -> Self {
        IdExchangeError::InvalidTaCertEncoding(e)
    }
}

impl From<ValidationError> for IdExchangeError {
    fn from(_e: ValidationError) -> Self {
        IdExchangeError::InvalidTaCert
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    
    use super::*;
    
    fn rpkid_time() -> Time {
        Time::utc(2012, 1, 1, 0, 0, 0)
    }

    #[test]
    fn child_request() {
        let xml = include_str!("../../test-data/remote/rpkid-child-id.xml");
        let req = ChildRequest::validate_at(
            xml.as_bytes(), rpkid_time()
        ).unwrap();

        assert_eq!(&Handle::from_str("Carol").unwrap(), req.child_handle());
        assert_eq!(None, req.tag());

        let re_encoded_xml = req.to_xml_string();
        let re_decoded = ChildRequest::validate_at(
            re_encoded_xml.as_bytes(),
            rpkid_time()
        ).unwrap();

        assert_eq!(req, re_decoded);
    }

    
}
