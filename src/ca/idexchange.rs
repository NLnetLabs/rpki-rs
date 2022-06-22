//! Out of band exchange messages.
//!
//! Support for the RFC8183 out-of-band setup requests and responses
//! used to exchange identity and configuration between CAs and their
//! parent CA and/or RPKI Publication Servers.

use std::borrow;
use std::convert::TryFrom;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::str::from_utf8;
use std::str::FromStr;
use std::sync::Arc;

use log::debug;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ca::idcert::IdCert;
use crate::ca::publication::Base64;
use crate::repository::x509::{Time, ValidationError};
use crate::uri;
use crate::xml;
use crate::xml::decode::{Error as XmlError, Name};

// Constants for the RFC 8183 XML
const VERSION: &str = "1";
const NS: &[u8] = b"http://www.hactrn.net/uris/rpki/rpki-setup/";

const CHILD_REQUEST: Name = Name::qualified(NS, b"child_request");
const CHILD_BPKI_TA: Name = Name::qualified(NS, b"child_bpki_ta");

const PUBLISHER_REQUEST: Name = Name::qualified(NS, b"publisher_request");
const PUBLISHER_BPKI_TA: Name = Name::qualified(NS, b"publisher_bpki_ta");

const PARENT_RESPONSE: Name = Name::qualified(NS, b"parent_response");
const PARENT_BPKI_TA: Name = Name::qualified(NS, b"parent_bpki_ta");
const PARENT_REFERRAL: Name = Name::qualified(NS, b"referral");
const PARENT_OFFER: Name = Name::qualified(NS, b"offer");

const REPOSITORY_RESPONSE: Name = Name::qualified(NS, b"repository_response");
const REPOSITORY_BPKI_TA: Name = Name::qualified(NS, b"repository_bpki_ta");

//------------ Handle --------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Myself;

/// A handle for an entity on its own, i.e. not in relation to others.
pub type MyHandle = Handle<Myself>;

/// A handle for a CA on its own, i.e. not in relation to others.
pub type CaHandle = Handle<Myself>;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Parent;

/// A handle for a parent of a CA
pub type ParentHandle = Handle<Parent>;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Child;

/// A handle for the child of a CA
pub type ChildHandle = Handle<Child>;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Publisher;

/// A handle for the publisher in a repository (i.e. a CA)
pub type PublisherHandle = Handle<Publisher>;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Repository;

/// A handle for the repository used by a publisher
pub type RepositoryHandle = Handle<Repository>;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Sender;

/// A handle referring to the sender of a message
pub type SenderHandle = Handle<Sender>;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Recipient;

/// A handle referring to the recipient of a message
pub type RecipientHandle = Handle<Recipient>;

//------------ Handle --------------------------------------------------------

/// This type represents the identifying 'handles' as used between RPKI
/// entities. Handles are like strings, but they are restricted to the
/// following - taken from the RELAX NG schema in RFC 8183:
///
/// handle  = xsd:string { maxLength="255" pattern="[\-_A-Za-z0-9/]*" }
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(try_from = "String")]
pub struct Handle<T> {
    name: Arc<str>,
    marker: std::marker::PhantomData<T>
}

impl<T> Handle<T> {
    pub fn new(name: Arc<str>) -> Self {
        Handle { name, marker: std::marker::PhantomData }
    }

    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    pub fn into_name(self) -> Arc<str> {
        self.name
    }

    pub fn as_str(&self) -> &str {
        self.as_ref()
    }

    /// Creates a new handle of another type from this.
    pub fn convert<Y>(&self) -> Handle<Y> {
        Handle::new(self.name.clone())
    }

    /// Converts this handle into a handle of another type.
    pub fn into_converted<Y>(self) -> Handle<Y> {
        Handle::new(self.name)
    }

    /// We replace "/" with "+" and "\" with "=" to make file system
    /// safe names.
    pub fn to_path_buf(&self) -> PathBuf {
        let s = self.to_string();
        let s = s.replace('/', "+");
        let s = s.replace('\\', "=");
        PathBuf::from(s)
    }

    fn verify_name(s: &str) -> Result<(), InvalidHandle> {
        if s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'/' || b == b'\\')
            && !s.is_empty()
            && s.len() < 256
        {
            Ok(())
        } else {
            Err(InvalidHandle)
        }
    }
}

impl<T> TryFrom<&PathBuf> for Handle<T> {
    type Error = InvalidHandle;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        if let Some(path) = path.file_name() {
            let s = path.to_string_lossy().to_string();
            let s = s.replace('+', "/");
            let s = s.replace('=', "\\");
            Self::from_str(&s)
        } else {
            Err(InvalidHandle)
        }
    }
}

impl<T> FromStr for Handle<T> {
    type Err = InvalidHandle;

    /// Accepted pattern: [-_A-Za-z0-9/]{1,255}
    /// See Appendix A of RFC8183.
    ///
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::verify_name(s)?;
        Ok(Handle::new(s.into()))
    }
}

impl<T> TryFrom<String> for Handle<T> {
    type Error = InvalidHandle;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::verify_name(&value)?;
        Ok(Handle::new(value.into()))
    }
}

impl<T> From<&Arc<str>> for Handle<T> {
    fn from(arc: &Arc<str>) -> Self {
        Self::new(arc.clone())
    }
}

impl<T> AsRef<str> for Handle<T> {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

impl<T> borrow::Borrow<str> for Handle<T> {
    fn borrow(&self) -> &str {
        self.as_ref()
    }
}

impl<T> AsRef<[u8]> for Handle<T> {
    fn as_ref(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl<T> fmt::Display for Handle<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl<T> Serialize for Handle<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

#[derive(Debug)]
pub struct InvalidHandle;

impl fmt::Display for InvalidHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Handle MUST have pattern: [-_A-Za-z0-9/]{{1,255}}")
    }
}

impl std::error::Error for InvalidHandle { }


//------------ ServiceUri ----------------------------------------------------

/// The RFC 8183 service URI for use with RFC 6492 or RFC 8181
/// 
/// Can be an HTTPS or HTTP URI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceUri {
    Https(uri::Https),
    Http(String),
}

impl ServiceUri {
    pub fn as_str(&self) -> &str {
        match self {
            ServiceUri::Http(http) => http,
            ServiceUri::Https(https) => https.as_str(),
        }
    }
}

impl TryFrom<String> for ServiceUri {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

impl FromStr for ServiceUri {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.to_lowercase().starts_with("http://") {
            Ok(ServiceUri::Http(value.to_string()))
        } else {
            Ok(ServiceUri::Https(uri::Https::from_str(value)?))
        }
    }
}

impl fmt::Display for ServiceUri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ServiceUri::Http(string) => string.fmt(f),
            ServiceUri::Https(https) => https.fmt(f),
        }
    }
}

impl Serialize for ServiceUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServiceUri {
    fn deserialize<D>(deserializer: D) -> Result<ServiceUri, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        ServiceUri::try_from(string).map_err(serde::de::Error::custom)
    }
}

impl AsRef<str> for ServiceUri {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

//------------ ChildRequest --------------------------------------------------

/// Type representing a <child_request /> defined in section 5.2.1 of
/// RFC8183.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildRequest {
    /// The self-signed IdCert containing the child's public key.
    id_cert: Base64,

    /// The handle the child wants to use for itself. This may not be honored
    /// by the parent.
    child_handle: ChildHandle,

    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,
}

/// # Data Access
///
impl ChildRequest {
    pub fn new(id_cert: Base64, child_handle: ChildHandle) -> Self {
        ChildRequest {
            id_cert,
            child_handle,
            tag: None,
        }
    }

    pub fn unpack(self) -> (Base64, ChildHandle, Option<String>) {
        (self.id_cert, self.child_handle, self.tag)
    }

    pub fn id_cert(&self) -> &Base64 {
        &self.id_cert
    }

    pub fn child_handle(&self) -> &ChildHandle {
        &self.child_handle
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }
}

/// # XML Support
///
impl ChildRequest {
    /// Parses a <child_request /> message.
    pub fn parse<R: io::BufRead>(reader: R) -> Result<Self, Error> {
        let mut reader = xml::decode::Reader::new(reader);

        let mut child_handle: Option<ChildHandle> = None;
        let mut tag: Option<String> = None;

        let mut outer = reader.start(|element| {
            if element.name() != CHILD_REQUEST {
                return Err(XmlError::Malformed);
            }

            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<String>()? != VERSION {
                        return Err(XmlError::Malformed);
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
                _ => Err(XmlError::Malformed),
            })
        })?;

        let child_handle = child_handle.ok_or(XmlError::Malformed)?;

        // We expect a single element 'child_bpki_ta' to be present which
        // will contain the child id_cert.
        let mut content = outer.take_element(&mut reader, |element| match element.name() {
            CHILD_BPKI_TA => Ok(()),
            _ => Err(XmlError::Malformed),
        })?;

        // Do base64 decoding of the certificate to ensure that it CAN be
        // decoded.
        let bytes = content.take_text(
            &mut reader, |text| text.base64_decode()
        )?;

        // Then re-encode as Base64 for keeping this data.
        let id_cert = Base64::from_content(bytes.as_slice());

        content.take_end(&mut reader)?;
        outer.take_end(&mut reader)?;
        reader.end()?;

        Ok(ChildRequest {
            tag,
            child_handle,
            id_cert,
        })
    }

    /// Validates and return the IdCert if it is correct and valid.
    pub fn validate(&self) -> Result<IdCert, Error> {
        self.validate_at(Time::now())
    }

    fn validate_at(&self, when: Time) -> Result<IdCert, Error> {
        validate_idcert_at(&self.id_cert, when)
    }

    /// Writes the ChildRequest's XML representation.
    pub fn write_xml(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);

        writer
            .element(CHILD_REQUEST.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("child_handle", self.child_handle())?
            .attr_opt("tag", self.tag())?
            .content(|content| {
                content
                    .element(CHILD_BPKI_TA.into_unqualified())?
                    .content(|content| content.raw(&self.id_cert))?;
                Ok(())
            })?;

        writer.done()
    }

    /// Writes the ChildRequest's XML representation to a new Vec<u8>.
    pub fn to_xml_vec(&self) -> Vec<u8> {
        let mut vec = vec![];
        self.write_xml(&mut vec).unwrap(); // safe
        vec
    }

    /// Writes the ChildRequest's XML representation to a new String.
    pub fn to_xml_string(&self) -> String {
        let vec = self.to_xml_vec();
        let xml = from_utf8(vec.as_slice()).unwrap(); // safe

        xml.to_string()
    }
}

//--- Display

impl fmt::Display for ChildRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_xml_string())
    }
}

//------------ ParentResponse ------------------------------------------------

/// Type representing a <parent_response /> defined in section 5.2.2 of
/// RFC8183.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentResponse {
    /// The parent CA's IdCert
    id_cert: Base64,

    /// The handle of the parent CA.
    parent_handle: ParentHandle,

    /// The handle chosen for the child CA. Note that this may not be the
    /// same as the handle the CA asked for.
    child_handle: ChildHandle,

    /// The URI where the CA needs to send its RFC6492 messages
    service_uri: ServiceUri,

    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,
}

/// # Construct and Data Access
///
impl ParentResponse {
    pub fn new(
        id_cert: Base64,
        parent_handle: ParentHandle,
        child_handle: ChildHandle,
        service_uri: ServiceUri,
        tag: Option<String>,
    ) -> Self {
        ParentResponse {
            id_cert,
            parent_handle,
            child_handle,
            service_uri,
            tag,
        }
    }

    pub fn id_cert(&self) -> &Base64 {
        &self.id_cert
    }

    pub fn parent_handle(&self) -> &ParentHandle {
        &self.parent_handle
    }

    pub fn child_handle(&self) -> &ChildHandle {
        &self.child_handle
    }

    pub fn service_uri(&self) -> &ServiceUri {
        &self.service_uri
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }
}

/// # XML Support
///
impl ParentResponse {
    /// Parses a <parent_response /> message.
    pub fn parse<R: io::BufRead>(reader: R) -> Result<Self, Error> {
        let mut reader = xml::decode::Reader::new(reader);

        let mut child_handle: Option<ChildHandle> = None;
        let mut parent_handle: Option<ParentHandle> = None;
        let mut service_uri: Option<ServiceUri> = None;
        let mut tag: Option<String> = None;

        let mut outer = reader.start(|element| {
            if element.name() != PARENT_RESPONSE {
                return Err(XmlError::Malformed);
            }

            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<String>()? != VERSION {
                        return Err(XmlError::Malformed);
                    }
                    Ok(())
                }
                b"service_uri" => {
                    service_uri = Some(value.ascii_into()?);
                    Ok(())
                }
                b"parent_handle" => {
                    parent_handle = Some(value.ascii_into()?);
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
                _ => {
                    debug!(
                        "Ignoring attribute in <parent_response />: {:?}",
                        from_utf8(name).unwrap_or("can't parse attr!?")
                    );
                    Ok(())
                }
            })
        })?;

        let service_uri = service_uri.ok_or(XmlError::Malformed)?;
        let parent_handle = parent_handle.ok_or(XmlError::Malformed)?;
        let child_handle = child_handle.ok_or(XmlError::Malformed)?;

        // There can be three different elements:
        //  - parent_bpki_ta
        //  - referral
        //  - offer
        //
        // We only care about the first, we can ignore the others. But,
        // we cannot assume that 'parent_bpki_ta' will be the first element.
        // And we should return an error if we find any other unexpected
        // element here.
        let mut id_cert: Option<Base64> = None;

        loop {
            let mut bpki_ta_element_found = false;
            let inner = outer.take_opt_element(&mut reader, |element| match element.name() {
                PARENT_BPKI_TA => {
                    bpki_ta_element_found = true;
                    Ok(())
                }
                PARENT_OFFER | PARENT_REFERRAL => Ok(()),
                _ => Err(XmlError::Malformed),
            })?;

            // Break out of loop if we got no element, get the
            // actual element if we can.
            let mut inner = match inner {
                Some(inner) => inner,
                None => break,
            };

            if bpki_ta_element_found {
                // parse inner text as the ID certificate
                
                // Do base64 decoding of the certificate to ensure that it CAN be
                // decoded.
                let bytes = inner.take_text(
                    &mut reader, |text| text.base64_decode()
                )?;

                // Then re-encode as Base64 for keeping this data.
                id_cert = Some(Base64::from_content(bytes.as_slice()));
            } else {
                // skip inner text if there is any (offer does not have any)
                inner.skip_opt_text(&mut reader)?;
            }

            inner.take_end(&mut reader)?;
        }

        let id_cert = id_cert.ok_or(XmlError::Malformed)?;

        outer.take_end(&mut reader)?;

        reader.end()?;

        Ok(ParentResponse {
            tag,
            id_cert,
            parent_handle,
            child_handle,
            service_uri,
        })
    }

    /// Writes the ParentResponse's XML representation.
    pub fn write_xml(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);

        writer
            .element(PARENT_RESPONSE.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("parent_handle", self.parent_handle())?
            .attr("child_handle", self.child_handle())?
            .attr("service_uri", self.service_uri())?
            .attr_opt("tag", self.tag())?
            .content(|content| {
                content
                    .element(PARENT_BPKI_TA.into_unqualified())?
                    .content(|content| content.raw(&self.id_cert))?;
                Ok(())
            })?;
        writer.done()
    }

    /// Validates and return the IdCert if it is correct and valid.
    pub fn validate(&self) -> Result<IdCert, Error> {
        self.validate_at(Time::now())
    }

    fn validate_at(&self, when: Time) -> Result<IdCert, Error> {
        validate_idcert_at(&self.id_cert, when)
    }

    /// Writes the ParentResponse's XML representation to a new Vec<u8>.
    pub fn to_xml_vec(&self) -> Vec<u8> {
        let mut vec = vec![];
        self.write_xml(&mut vec).unwrap(); // safe
        vec
    }

    /// Writes the ParentResponse's XML representation to a new String.
    pub fn to_xml_string(&self) -> String {
        let vec = self.to_xml_vec();
        let xml = from_utf8(vec.as_slice()).unwrap(); // safe

        xml.to_string()
    }
}

//--- Display

impl fmt::Display for ParentResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_xml_string())
    }
}

//------------ PublisherRequest ----------------------------------------------

/// Type representing a <publisher_request/>
///
/// This is the XML message with identity information that a CA sends to a
/// Publication Server.
///
/// For more info, see: https://tools.ietf.org/html/rfc8183#section-5.2.3
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherRequest {
    /// The self-signed IdCert containing the publisher's public key.
    id_cert: Base64,

    /// The name the publishing CA likes to call itself by
    publisher_handle: PublisherHandle,

    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,
}

/// # Construct and Data Access
///
impl PublisherRequest {
    pub fn new(id_cert: Base64, publisher_handle: PublisherHandle, tag: Option<String>) -> Self {
        PublisherRequest {
            id_cert,
            publisher_handle,
            tag,
        }
    }

    pub fn unpack(self) -> (Base64, PublisherHandle, Option<String>) {
        (self.id_cert, self.publisher_handle, self.tag)
    }

    pub fn id_cert(&self) -> &Base64 {
        &self.id_cert
    }

    pub fn publisher_handle(&self) -> &PublisherHandle {
        &self.publisher_handle
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }
}

/// # XML Support
///
impl PublisherRequest {
    /// Parses a <publisher_request /> message.
    pub fn parse<R: io::BufRead>(reader: R) -> Result<Self, Error> {
        let mut reader = xml::decode::Reader::new(reader);

        let mut publisher_handle: Option<PublisherHandle> = None;
        let mut tag: Option<String> = None;

        let mut outer = reader.start(|element| {
            if element.name() != PUBLISHER_REQUEST {
                return Err(XmlError::Malformed);
            }

            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<String>()? != VERSION {
                        return Err(XmlError::Malformed);
                    }
                    Ok(())
                }
                b"publisher_handle" => {
                    publisher_handle = Some(value.ascii_into()?);
                    Ok(())
                }
                b"tag" => {
                    tag = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => Err(XmlError::Malformed),
            })
        })?;

        let publisher_handle = publisher_handle.ok_or(XmlError::Malformed)?;

        // We expect a single element 'child_bpki_ta' to be present which
        // will contain the child id_cert.
        let mut content = outer.take_element(&mut reader, |element| match element.name() {
            PUBLISHER_BPKI_TA => Ok(()),
            _ => Err(XmlError::Malformed),
        })?;

        // Do base64 decoding of the certificate to ensure that it CAN be
        // decoded.
        let bytes = content.take_text(
            &mut reader, |text| text.base64_decode()
        )?;

        // Then re-encode as Base64 for keeping this data.
        let id_cert = Base64::from_content(bytes.as_slice());
        
        content.take_end(&mut reader)?;

        outer.take_end(&mut reader)?;

        reader.end()?;

        Ok(PublisherRequest {
            tag,
            publisher_handle,
            id_cert,
        })
    }

    /// Validates and return the IdCert if it is correct and valid.
    pub fn validate(&self) -> Result<IdCert, Error> {
        self.validate_at(Time::now())
    }

    fn validate_at(&self, when: Time) -> Result<IdCert, Error> {
        validate_idcert_at(&self.id_cert, when)
    }

    /// Writes the PublisherRequest's XML representation.
    pub fn write_xml(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);

        writer
            .element(PUBLISHER_REQUEST.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("publisher_handle", self.publisher_handle())?
            .attr_opt("tag", self.tag())?
            .content(|content| {
                content
                    .element(PUBLISHER_BPKI_TA.into_unqualified())?
                    .content(|content| content.raw(&self.id_cert))?;
                Ok(())
            })?;

        writer.done()
    }

    /// Writes the PublisherRequest's XML representation to a new Vec<u8>.
    pub fn to_xml_vec(&self) -> Vec<u8> {
        let mut vec = vec![];
        self.write_xml(&mut vec).unwrap(); // safe
        vec
    }

    /// Writes the PublisherRequest's XML representation to a new String.
    pub fn to_xml_string(&self) -> String {
        let vec = self.to_xml_vec();
        let xml = from_utf8(vec.as_slice()).unwrap(); // safe

        xml.to_string()
    }


}

//--- Display

impl fmt::Display for PublisherRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_xml_string())
    }
}

//------------ RepositoryResponse --------------------------------------------

/// Type representing a <repository_response/>
///
/// This is the response sent to a CA by the publication server. It contains
/// the details needed by the CA to send publication messages to the server.
///
/// See https://tools.ietf.org/html/rfc8183#section-5.2.4
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct RepositoryResponse {
    /// The Publication Server Identity Certificate
    id_cert: Base64,

    /// The name the publication server decided to call the CA by.
    /// Note that this may not be the same as the handle the CA asked for.
    publisher_handle: PublisherHandle,

    /// The URI where the CA needs to send its RFC8181 messages
    service_uri: ServiceUri,

    /// Contains the rsync base (sia_base) and optional RRDP (RFC8182)
    /// notification xml uri
    repo_info: RepoInfo,

    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,
}

/// # Construct and Data Access
///
impl RepositoryResponse {
    /// Creates a new response.
    pub fn new(
        id_cert: Base64,
        publisher_handle: PublisherHandle,
        service_uri: ServiceUri,
        sia_base: uri::Rsync,
        rrdp_notification_uri: Option<uri::Https>,
        tag: Option<String>,
    ) -> Self {
        let repo_info = RepoInfo::new(sia_base, rrdp_notification_uri);
        
        RepositoryResponse {
            id_cert,
            publisher_handle,
            service_uri,
            repo_info,
            tag,
        }
    }

    pub fn id_cert(&self) -> &Base64 {
        &self.id_cert
    }

    pub fn publisher_handle(&self) -> &PublisherHandle {
        &self.publisher_handle
    }

    pub fn service_uri(&self) -> &ServiceUri {
        &self.service_uri
    }

    pub fn repo_info(&self) -> &RepoInfo {
        &self.repo_info
    }

    pub fn sia_base(&self) -> &uri::Rsync {
        &self.repo_info.sia_base
    }

    pub fn rrdp_notification_uri(&self) -> Option<&uri::Https> {
        self.repo_info.rrdp_notification_uri.as_ref()
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }
}

/// # XML Support
///
impl RepositoryResponse {
    /// Parses a <repository_response /> message.
    fn parse<R: io::BufRead>(reader: R) -> Result<Self, Error> {
        let mut reader = xml::decode::Reader::new(reader);

        let mut tag: Option<String> = None;
        let mut publisher_handle: Option<PublisherHandle> = None;
        let mut service_uri: Option<ServiceUri> = None;

        let mut sia_base: Option<uri::Rsync> = None;
        let mut rrdp_notification_uri: Option<uri::Https> = None;

        let mut outer = reader.start(|element| {
            if element.name() != REPOSITORY_RESPONSE {
                return Err(XmlError::Malformed);
            }

            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<String>()? != VERSION {
                        return Err(XmlError::Malformed);
                    }
                    Ok(())
                }
                b"service_uri" => {
                    service_uri = Some(value.ascii_into()?);
                    Ok(())
                }
                b"publisher_handle" => {
                    publisher_handle = Some(value.ascii_into()?);
                    Ok(())
                }
                b"sia_base" => {
                    sia_base = Some(value.ascii_into()?);
                    Ok(())
                }
                b"rrdp_notification_uri" => {
                    rrdp_notification_uri = Some(value.ascii_into()?);
                    Ok(())
                }
                b"tag" => {
                    tag = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => {
                    debug!(
                        "Ignoring attribute in <parent_response />: {:?}",
                        from_utf8(name).unwrap_or("can't parse attr!?")
                    );
                    Ok(())
                }
            })
        })?;

        // Check mandatory attributes
        let service_uri = service_uri.ok_or(XmlError::Malformed)?;
        let publisher_handle = publisher_handle.ok_or(XmlError::Malformed)?;
        let sia_base = sia_base.ok_or(XmlError::Malformed)?;

        // We expect a single element 'child_bpki_ta' to be present which
        // will contain the child id_cert.
        let mut content = outer.take_element(&mut reader, |element| match element.name() {
            REPOSITORY_BPKI_TA => Ok(()),
            _ => Err(XmlError::Malformed),
        })?;

        // Do base64 decoding of the certificate to ensure that it CAN be
        // decoded.
        let bytes = content.take_text(
            &mut reader, |text| text.base64_decode()
        )?;

        // Then re-encode as Base64 for keeping this data.
        let id_cert = Base64::from_content(bytes.as_slice());

        content.take_end(&mut reader)?;

        outer.take_end(&mut reader)?;

        reader.end()?;

        let repo_info = RepoInfo::new(sia_base, rrdp_notification_uri);

        Ok(RepositoryResponse {
            tag,
            publisher_handle,
            id_cert,
            service_uri,
            repo_info
        })
    }

    /// Writes the RepositoryResponse's XML representation.
    pub fn write_xml(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);

        writer
            .element(REPOSITORY_RESPONSE.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("publisher_handle", self.publisher_handle())?
            .attr("service_uri", self.service_uri())?
            .attr("sia_base", self.sia_base())?
            .attr_opt("rrdp_notification_uri", self.rrdp_notification_uri())?
            .attr_opt("tag", self.tag())?
            .content(|content| {
                content
                    .element(REPOSITORY_BPKI_TA.into_unqualified())?
                    .content(|content| content.raw(&self.id_cert))?;
                Ok(())
            })?;
        writer.done()
    }

    /// Validates and return the IdCert if it is correct and valid.
    pub fn validate(&self) -> Result<IdCert, Error> {
        self.validate_at(Time::now())
    }

    fn validate_at(&self, when: Time) -> Result<IdCert, Error> {
        validate_idcert_at(&self.id_cert, when)
    }

    /// Writes the RepositoryResponse's XML representation to a new Vec<u8>.
    pub fn to_xml_vec(&self) -> Vec<u8> {
        let mut vec = vec![];
        self.write_xml(&mut vec).unwrap(); // safe
        vec
    }

    /// Writes the RepositoryResponse's XML representation to a new String.
    pub fn to_xml_string(&self) -> String {
        let vec = self.to_xml_vec();
        let xml = from_utf8(vec.as_slice()).unwrap(); // safe

        xml.to_string()
    }
}

//--- Display

impl fmt::Display for RepositoryResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_xml_string())
    }
}

//------------ RepoInfo ------------------------------------------------------

/// Contains the rsync and RRDP base URIs for a repository,
/// or publisher inside a repository.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepoInfo {
    #[serde(alias = "base_uri")]
    sia_base: uri::Rsync,

    #[serde(alias = "rpki_notify")]
    rrdp_notification_uri: Option<uri::Https>,
}

impl RepoInfo {
    pub fn new(sia_base: uri::Rsync, rrdp_notification_uri: Option<uri::Https>) -> Self {
        RepoInfo { sia_base, rrdp_notification_uri }
    }

    pub fn base_uri(&self) -> &uri::Rsync {
        &self.sia_base
    }

    /// Returns the ca repository uri for this RepoInfo and a given namespace.
    /// If the namespace is an empty str, it is omitted from the path.
    pub fn ca_repository(&self, name_space: &str) -> uri::Rsync {
        match name_space {
            "" => self.sia_base.clone(),
            _ => self.sia_base.join(name_space.as_ref()).unwrap(),
        }
    }

    /// Returns the rpki notify uri if set.
    ///
    /// Note:
    /// - Krill will always include this, but some publication servers may not
    /// - This is the same for all namespaces
    pub fn rpki_notify(&self) -> Option<&uri::Https> {
        self.rrdp_notification_uri.as_ref()
    }

    /// Resolves the specific rsync URI for a given filename and namespace
    /// under the sia_base.
    pub fn resolve(&self, name_space: &str, file_name: &str) -> uri::Rsync {
        self.ca_repository(name_space).join(file_name.as_ref()).unwrap()
    }
}


//------------ IdCert XML parsing --------------------------------------------

/// Parses an IdCert for the given XML element name
/// and validates that it's a validly signed TA certificate
/// valid on the given time. Normally the 'time' would be
/// 'now' - but we need to allow overriding this to support
/// testing.
pub fn validate_idcert_at(
    base64: &Base64,
    when: Time,
) -> Result<IdCert, Error> {
    let bytes = base64.to_bytes();
    let id_cert = IdCert::decode(bytes.as_ref())?;
    id_cert.validate_ta_at(when)?;

    Ok(id_cert)
}

//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    InvalidXml(xml::decode::Error),
    InvalidVersion,
    InvalidHandle,
    InvalidTaBase64(base64::DecodeError),
    InvalidTaCertEncoding(bcder::decode::Error),
    InvalidTaCert,
    InvalidUri(uri::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidXml(e) => e.fmt(f),
            Error::InvalidVersion => write!(f, "Invalid version"),
            Error::InvalidHandle => write!(f, "Invalid handle"),
            Error::InvalidTaBase64(e) => e.fmt(f),
            Error::InvalidTaCertEncoding(e) => {
                write!(f, "Cannot decode TA cert: {}", e)
            }
            Error::InvalidTaCert => write!(f, "Invalid TA cert"),
            &Error::InvalidUri(e) => e.fmt(f),
        }
    }
}

impl From<xml::decode::Error> for Error {
    fn from(e: xml::decode::Error) -> Self {
        Error::InvalidXml(e)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::InvalidTaBase64(e)
    }
}

impl From<bcder::decode::Error> for Error {
    fn from(e: bcder::decode::Error) -> Self {
        Error::InvalidTaCertEncoding(e)
    }
}

impl From<ValidationError> for Error {
    fn from(_e: ValidationError) -> Self {
        Error::InvalidTaCert
    }
}

impl From<uri::Error> for Error {
    fn from(e: uri::Error) -> Self {
        Error::InvalidUri(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn child_request_codec() {
        let xml = include_str!("../../test-data/ca/rfc8183/rpkid-child-id.xml");
        let req = ChildRequest::parse(xml.as_bytes()).unwrap();

        assert_eq!(&Handle::from_str("Carol").unwrap(), req.child_handle());
        assert_eq!(None, req.tag());

        let re_encoded_xml = req.to_xml_string();
        let re_decoded = ChildRequest::parse(re_encoded_xml.as_bytes()).unwrap();

        assert_eq!(req, re_decoded);
    }

    #[test]
    fn parent_response_codec() {
        let xml = include_str!("../../test-data/ca/rfc8183/apnic-parent-response.xml");
        let req = ParentResponse::parse(xml.as_bytes()).unwrap();

        let re_encoded_xml = req.to_xml_string();
        let re_decoded =
            ParentResponse::parse(re_encoded_xml.as_bytes()).unwrap();

        assert_eq!(req, re_decoded);
    }

    #[test]
    fn parent_response_parse_rpkid_referral() {
        let xml = include_str!("../../test-data/ca/rfc8183/rpkid-parent-response-referral.xml");
        let _req = ParentResponse::parse(xml.as_bytes()).unwrap();
    }

    #[test]
    fn parent_response_parse_rpkid_offer() {
        let xml = include_str!("../../test-data/ca/rfc8183/rpkid-parent-response-offer.xml");
        let _req = ParentResponse::parse(xml.as_bytes()).unwrap();
    }

    #[test]
    fn publisher_request_codec() {
        let xml = include_str!("../../test-data/ca/rfc8183/rpkid-publisher-request.xml");
        let req = PublisherRequest::parse(xml.as_bytes()).unwrap();

        let re_encoded_xml = req.to_xml_string();
        let re_decoded = 
            PublisherRequest::parse(re_encoded_xml.as_bytes()).unwrap();

        assert_eq!(req, re_decoded);
    }

    #[test]
    fn repository_response_codec() {
        let xml = include_str!("../../test-data/ca/rfc8183/apnic-repository-response.xml");
        let req = RepositoryResponse::parse(xml.as_bytes()).unwrap();

        let re_encoded_xml = req.to_xml_string();
        let re_decoded =
            RepositoryResponse::parse(re_encoded_xml.as_bytes()).unwrap();

        assert_eq!(req, re_decoded);
    }
}
