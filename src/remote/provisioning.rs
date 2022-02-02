//! Support RFC 6492 Provisioning Protocol (aka up-down)

use std::convert::TryFrom;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::{io, fmt};
use chrono::{DateTime, Utc, SecondsFormat};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer
};

use crate::repository::x509::Time;
use crate::repository::{Csr, Cert};
use crate::repository::crypto::KeyIdentifier;
use crate::repository::resources::{AsBlocks, Ipv4Blocks, Ipv6Blocks};
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
const KEY: &[u8] = b"key";
const CLASS: &[u8] = b"class";
const CERTIFICATE: &[u8] = b"certificate";
const ISSUER: &[u8] = b"issuer";

const PAYLOAD_TYPE_LIST: &str = "list";
const PAYLOAD_TYPE_ISSUE: &str = "issue";
const PAYLOAD_TYPE_REVOKE: &str = "revoke";

const PAYLOAD_TYPE_LIST_RESPONSE: &str = "list_response";
const PAYLOAD_TYPE_ISSUE_RESPONSE: &str = "issue_response";
const PAYLOAD_TYPE_REVOKE_RESPONSE: &str = "revoke_response";


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
    Issue(IssuanceRequest),
    Revoke(RevocationRequest),
    ListResponse(ResourceClassListResponse),
    IssueResponse(IssuanceResponse),
    RevokeResponse(RevocationResponse),
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
                IssuanceRequest::decode(content, reader)
                                        .map(Payload::Issue)
            }
            PAYLOAD_TYPE_REVOKE => {
                RevocationRequest::decode(content, reader)
                                        .map(Payload::Revoke)
            }
            PAYLOAD_TYPE_LIST_RESPONSE => {
                ResourceClassListResponse::decode(content, reader)
                                        .map(Payload::ListResponse)
            }
            PAYLOAD_TYPE_ISSUE_RESPONSE => {
                IssuanceResponse::decode(content, reader)
                                        .map(Payload::IssueResponse)
            }
            PAYLOAD_TYPE_REVOKE_RESPONSE => {
                RevocationResponse::decode(content, reader)
                                        .map(Payload::RevokeResponse)   
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
            Payload::ListResponse(_) => PAYLOAD_TYPE_LIST_RESPONSE,
            Payload::Issue(_) => PAYLOAD_TYPE_ISSUE,
            Payload::IssueResponse(_) => PAYLOAD_TYPE_ISSUE_RESPONSE,
            Payload::Revoke(_) => PAYLOAD_TYPE_REVOKE,
            Payload::RevokeResponse(_) => PAYLOAD_TYPE_REVOKE_RESPONSE,
        }
    }

    /// Encode payload content
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        match self {
            Payload::List => Ok(()), // nothing to write
            Payload::ListResponse(list) => list.write_xml(content),
            Payload::Issue(issue) => issue.write_xml(content),
            Payload::IssueResponse(response) => response.write_xml(content),
            Payload::Revoke(revoke) => revoke.write_xml(content),
            Payload::RevokeResponse(response) => response.write_xml(content),
        }
    }
}



//------------ IssuanceRequest -----------------------------------------------

/// This type reflects the content of a Certificate Issuance Request
/// defined in section 3.4.1 of RFC6492.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuanceRequest {
    class_name: ResourceClassName,
    limit: ResourceSet,
    csr: Csr,
}

/// # Data
/// 
impl IssuanceRequest {
    pub fn new(
        class_name: ResourceClassName,
        limit: ResourceSet,
        csr: Csr
    ) -> Self {
        IssuanceRequest { class_name, limit, csr }
    }

    pub fn unpack(self) -> (ResourceClassName, ResourceSet, Csr) {
        (self.class_name, self.limit, self.csr)
    }

    pub fn class_name(&self) -> &ResourceClassName {
        &self.class_name
    }
    pub fn limit(&self) -> &ResourceSet {
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
        let mut limit = ResourceSet::default();

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
                        .map_err(|e| Error::InvalidCsrSyntax(e.to_string()))?;

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
            .opt_attr("req_resource_set_ipv4", self.limit().ipv4_opt())?
            .opt_attr("req_resource_set_ipv6", self.limit().ipv6_opt())?
            .content(|c| c.base64(self.csr().to_captured().as_slice()))?;

        Ok(())
    }
}

impl PartialEq for IssuanceRequest {
    fn eq(&self, oth: &IssuanceRequest) -> bool {
        self.class_name == oth.class_name &&
        self.limit == oth.limit &&
        self.csr.to_captured().as_slice() == oth.csr.to_captured().as_slice()
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


//------------ IssuanceResponse ----------------------------------------------

/// A Certificate Issuance Response equivalent to the one defined in
/// section 3.4.2 of RFC6492.
///
/// Note that this is like a single [`ResourceClassEntitlements`] found in the
/// section 3.4.1 Resource Class List Response, except that it MUsT include
/// the ONE certificate which has just been issued only. So we can wrap here
/// and add some guards.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssuanceResponse(ResourceClassEntitlements);

/// # Encode to XML
/// 
impl IssuanceResponse {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        self.0.write_xml(content)
    }
}

/// # Decode from XML
/// 
impl IssuanceResponse {
    /// Decodes an RFC 6492 section 3.4.2 issuance response.
    fn decode<R: io::BufRead>(
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        let entitlements = ResourceClassEntitlements::decode_opt(
            content, reader
        )?
        .ok_or(XmlError::Malformed)?; // We MUST have 1

        if entitlements.issued_certs.len() != 1 {
            Err(Error::XmlError(XmlError::Malformed))
        } else {
            Ok(IssuanceResponse(entitlements))
        }
    }
}


//------------ ResourceSet ---------------------------------------------------

/// A set of ASN, IPv4 and IPv6 resources. In the context of resource
/// certificates this type can be used to include all resources found on the
/// certificate. In the context of an [`IssuanceRequest`] this type represents
/// the set of (optional) limits when requesting a certificate - where an
/// empty set of any resource type means that ALL eligible resources are
/// wanted. In the context of [`ResourceClassEntitlements`] this type
/// represents the full set of resource entitlements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceSet {
    asn: AsBlocks,
    ipv4: Ipv4Blocks,
    ipv6: Ipv6Blocks,
}

impl ResourceSet {
    pub fn new() -> ResourceSet {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.asn.is_empty() && self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    pub fn set_asn(&mut self, asn: AsBlocks) {
        self.asn = asn;
    }

    pub fn set_ipv4(&mut self, ipv4: Ipv4Blocks) {
        self.ipv4 = ipv4;
    }

    pub fn set_ipv6(&mut self, ipv6: Ipv6Blocks) {
        self.ipv6 = ipv6;
    }

    pub fn asn(&self) -> &AsBlocks {
        &self.asn
    }
    
    pub fn ipv4(&self) -> &Ipv4Blocks {
        &self.ipv4
    }
    
    pub fn ipv6(&self) -> &Ipv6Blocks {
        &self.ipv6
    }

    /// Returns None if there are no ASNs in this ResourceSet.
    pub fn asn_opt(&self) -> Option<&AsBlocks> {
        if self.asn.is_empty() {
            None
        } else {
            Some(&self.asn)
        }
    }

    /// Returns None if there is no IPv4 in this ResourceSet.
    pub fn ipv4_opt(&self) -> Option<&Ipv4Blocks> {
        if self.ipv4.is_empty() {
            None
        } else {
            Some(&self.ipv4)
        }
    }

    /// Returns None if there is no IPv6 in this ResourceSet.
    pub fn ipv6_opt(&self) -> Option<&Ipv6Blocks> {
        if self.ipv6.is_empty() {
            None
        } else {
            Some(&self.ipv6)
        }
    }
}

impl Default for ResourceSet {
    fn default() -> Self {
        ResourceSet {
            asn: AsBlocks::empty(),
            ipv4: Ipv4Blocks::empty(),
            ipv6: Ipv6Blocks::empty(),
        }
    }
}


//--- Display

impl fmt::Display for ResourceSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_empty() {
            write!(f, "none")
        } else {
            let mut space_needed = false;
            if !self.asn.is_empty() {
                write!(f, "asn: {}", self.asn)?;
                space_needed = true;
            }
            if !self.ipv4.is_empty() {
                if space_needed {
                    write!(f, " ")?;
                }
                write!(f, "ipv4: {}", self.ipv4)?;
                space_needed = true;
            }
            if !self.ipv6.is_empty() {
                if space_needed {
                    write!(f, " ")?;
                }
                write!(f, "ipv6: {}", self.ipv6)?;
            }

            Ok(())
        }
    }
}


//------------ RevocationRequest ---------------------------------------------

/// This type represents a Certificate Revocation Request as
/// defined in section 3.5.1 of RFC6492.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationRequest(KeyElement);

impl RevocationRequest {
    pub fn new(class_name: ResourceClassName, key: KeyIdentifier) -> Self {
        RevocationRequest(KeyElement { class_name, key })
    } 

    pub fn unpack(self) -> (ResourceClassName, KeyIdentifier) {
        (self.0.class_name, self.0.key)
    }
}

/// # XML Support
/// 
impl RevocationRequest {
    fn decode<R: io::BufRead>(
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        KeyElement::decode(content, reader).map(RevocationRequest)
    }
}

impl Deref for RevocationRequest {
    type Target = KeyElement;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}


//------------ RevocationResponse --------------------------------------------

/// This type represents a Certificate Revocation Response as
/// defined in section 3.5.2 of RFC6492.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationResponse(KeyElement);

/// # XML Support
/// 
impl RevocationResponse {
    fn decode<R: io::BufRead>(
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        KeyElement::decode(content, reader).map(RevocationResponse)
    }
}

impl Deref for RevocationResponse {
    type Target = KeyElement;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}


//------------ KeyElement ----------------------------------------------------

/// This type represents a <key /> element as used in both the Certificate
/// Revocation Request and Response, sections 3.5.1 and 3.5.2 respectively,
/// of RFC6492.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyElement {
    class_name: ResourceClassName,
    key: KeyIdentifier,
}

/// # Data Access
/// 
impl KeyElement {
    pub fn class_name(&self) -> &ResourceClassName {
        &self.class_name
    }
    pub fn key(&self) -> &KeyIdentifier {
        &self.key
    }
}

/// # Decode from XML
///
impl KeyElement {
    /// Decodes an RFC 6492 section 3.5.1 certificate revocation request.
    ///
    /// Requests have the following format:
    /// <key class_name="class name"
    ///      ski="[encoded hash of the subject public key]" />
    fn decode<R: io::BufRead>(
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        let mut class_name = None;
        let mut key = None;

        content.take_element(reader, |element|{
            if element.name().local() != KEY {
                return Err(XmlError::Malformed);
            }

            element.attributes(|name, value| match name {
                b"class_name" => {
                    class_name = Some(value.ascii_into()?);
                    Ok(())
                }
                b"ski" => {
                    let base64_str: String = value.ascii_into()?;
                    let bytes = base64::decode_config(
                        base64_str,
                        base64::URL_SAFE_NO_PAD
                    ).map_err(|_| XmlError::Malformed)?;
                    
                    let ski = KeyIdentifier::try_from(
                        bytes.as_slice()
                    ).map_err(|_| XmlError::Malformed)?;

                    key = Some(ski);
                    Ok(())
                }
                _ => {
                    Err(XmlError::Malformed)
                }
            })
        })?;

        let class_name = class_name.ok_or(XmlError::Malformed)?;
        let key = key.ok_or(XmlError::Malformed)?;

        Ok(KeyElement { class_name, key })
    }
}


/// # Encode to XML
/// 
impl KeyElement {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        let ski = base64::encode_config(
            self.key().as_slice(),
            // it's not 100% clear from the RFC whether padding is used.
            // using no-pad makes this most likely to be accepted.
            base64::URL_SAFE_NO_PAD
        );
        content
            .element(KEY.into())?
            .attr("class_name", self.class_name())?
            .attr("ski", &ski)?;

        Ok(())
    }
}


impl fmt::Display for KeyElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "class name '{}' key '{}'", self.class_name, self.key)
    }
}


//------------ ResourceClassListResponse -------------------------------------

/// This structure is what is called the "Resource Class List Response"
/// in section 3.3.2 of RFC6492.
/// 
/// This response can have 0 or more <class /> elements containing the
/// entitlements for 0 or more corresponding resource classes, which we will
/// call [`Entitlement`]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClassListResponse {
    classes: Vec<ResourceClassEntitlements>,
}

/// # Decode from XML
/// 
impl ResourceClassListResponse {
    fn decode<R: io::BufRead>(
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        let mut classes = vec![];
        
        while let Some(entitlement) = ResourceClassEntitlements::decode_opt(
            content,
            reader
        )? {
            classes.push(entitlement);
        }
        
        Ok(ResourceClassListResponse { classes })
    }
}

/// # Encode to XML
/// 
impl ResourceClassListResponse {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        for class in &self.classes {
            class.write_xml(content)?;
        }
        Ok(())
    }
}

//------------ ResourceClassEntitlements -------------------------------------

/// The entitlements for one of possibly multiple resource classes included in
/// an RFC 6492 "Resource Class List Response".
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClassEntitlements {
    class_name: ResourceClassName,
    resource_set: ResourceSet,
    not_after: Time,
    issued_certs: Vec<IssuedCert>,
    signing_cert: SigningCert,
}

/// # Decode from XML
/// 
impl ResourceClassEntitlements {
    /// Decodes an optional nested <class /> element.
    // 
    // Schema defined in section 3.3.2 of RFC 6492:
    //
    // <class class_name="class name"
    //        cert_url="url"
    //        resource_set_as="as resource set"
    //        resource_set_ipv4="ipv4 resource set"
    //        resource_set_ipv6="ipv6 resource set"
    //        resource_set_notafter="datetime"
    //
    //        suggested_sia_head="[directory uri]" >
    //
    //             ^^^^^ this is optional and replaced by sia_base in RFC8183
    //                   it is unused and can simply be skipped when parsing
    // 
    //    <certificate cert_url="url"
    //                 req_resource_set_as="as resource set"
    //                 req_resource_set_ipv4="ipv4 resource set"
    //                 req_resource_set_ipv6="ipv6 resource set" >
    //
    //       [base64 encoded certificate]
    //
    //    </certificate>
    //    ...
    // 
    //    (repeated for each current certificate where the client
    //     is the certificate's subject)
    // 
    //    <issuer>[issuer's certificate]</issuer>
    // </class>
    fn decode_opt<R: io::BufRead>(
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Option<Self>, Error> {

        // The following values are found as attributes
        let mut class_name: Option<ResourceClassName> = None;
        let mut cert_url: Option<uri::Rsync> = None;
        let mut resources = ResourceSet::default();
        let mut not_after: Option<Time> = None;

        let class_element = content.take_opt_element(reader, |element| {
            if element.name().local() != CLASS {
                return Err(XmlError::Malformed)
            }

            element.attributes(|name, value| match name {
                b"class_name" => {
                    class_name = Some(value.ascii_into()?);
                    Ok(())
                },
                b"cert_url" => {
                    cert_url = Some(value.ascii_into()?);
                    Ok(())
                },
                b"resource_set_as" => {
                    resources.set_asn(value.ascii_into()?);
                    Ok(())
                }
                b"resource_set_ipv4" => {
                    resources.set_ipv4(value.ascii_into()?);
                    Ok(())
                }
                b"resource_set_ipv6" => {
                    resources.set_ipv6(value.ascii_into()?);
                    Ok(())
                }
                b"resource_set_notafter" => {
                    let date_time: DateTime::<Utc> = value.ascii_into()?;
                    not_after = Some(Time::new(date_time));
                    Ok(())
                }
                b"suggested_sia_head" => {
                    // safe to ignore - optional and replaced by 'sia_base'
                    // in the RFC 8183 Repository Response.
                    Ok(())
                }
                _ => {
                    Err(XmlError::Malformed)
                }
            })
        })?;

        let mut class_element = match class_element {
            None => return Ok(None),
            Some(inner) => inner
        };

        // Make sure all required attributes were set
        let class_name = class_name.ok_or(XmlError::Malformed)?;
        let issuer_url = cert_url.ok_or(XmlError::Malformed)?;
        let not_after = not_after.ok_or(XmlError::Malformed)?;

        let mut issued_certs: Vec<IssuedCert> = vec![];
        let mut issuer: Option<Cert> = None;

        // We should find zero or more received (issued) certificates and
        // exactly one issuer CA certificates nested in this response.
        //
        // Since we will need to parse the element attributes, the content,
        // and close each element, and the order may or may not obey the
        // RFC XML schema (issuer should be last) - it's best that we do a
        // careful loop now, parse what we find and break if there are no
        // more elements.
        loop {
            let mut was_issuer = false; // can only be certificate OR issuer

            let mut url: Option<uri::Rsync> = None;
            let mut req_limit = ResourceSet::default();

            let cert_el = class_element.take_opt_element(reader, |el| {
                match el.name().local() {
                    CERTIFICATE => {
                        el.attributes(|name, value| match name {
                            b"cert_url" => {
                                url = Some(value.ascii_into()?);
                                Ok(())
                            },
                            b"req_resource_set_as" => {
                                req_limit.set_asn(value.ascii_into()?);
                                Ok(())
                            }
                            b"req_resource_set_ipv4" => {
                                req_limit.set_ipv4(value.ascii_into()?);
                                Ok(())
                            }
                            b"req_resource_set_ipv6" => {
                                req_limit.set_ipv6(value.ascii_into()?);
                                Ok(())
                            }
                            _ => Err(XmlError::Malformed)
                        })
                    },
                    ISSUER => {
                        was_issuer = true;
                        Ok(())
                    }
                    _ => Err(XmlError::Malformed)
                }
            })?;

            let mut cert_el = match cert_el {
                None => break,
                Some(inner) => inner
            };

            // no matter whether this was an issued *received* certificate or
            // the signing 'issuer' certificate.. we expect a base64 encoded
            // certificate inside this element.
            let bytes = cert_el.take_text(reader, |txt| txt.base64_decode())?;
            let cert = Cert::decode(bytes.as_ref())
                              .map_err(|e| Error::CertSyntax(e.to_string()))?;

            if was_issuer {
                issuer = Some(cert);
            } else {
                let url = url.ok_or(XmlError::Malformed)?;

                issued_certs.push(
                    IssuedCert { url, req_limit, cert }
                );
            }

            cert_el.take_end(reader)?;
        }


        let issuer = issuer.ok_or(XmlError::Malformed)?;

        let signing_cert = SigningCert { cert: issuer, url: issuer_url };

        class_element.take_end(reader)?;

        Ok(Some(ResourceClassEntitlements {
            class_name, resource_set: resources, not_after, issued_certs, signing_cert
        }))
    }
}
    
/// # Encode to XML
/// 
impl ResourceClassEntitlements {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {

        let not_after = self.not_after
                                .to_rfc3339_opts(SecondsFormat::Secs, true);

        content
            .element(CLASS.into())?
            .attr("class_name", &self.class_name)?
            .attr("cert_url", &self.signing_cert.url)?
            .opt_attr("resource_set_as", self.resource_set.asn_opt())?
            .opt_attr("resource_set_ipv4", self.resource_set.ipv4_opt())?
            .opt_attr("resource_set_ipv6", self.resource_set.ipv6_opt())?
            .attr("resource_set_notafter", &not_after)?
            .content(|nested|{
                for issued in &self.issued_certs {
                    issued.write_xml(nested)?;
                }
                
                nested
                    .element(ISSUER.into())?
                    .content(|inner| {
                        inner.base64(
                            self.signing_cert.cert.to_captured().as_slice()
                        )}
                    )?;

                Ok(())
            })?;

        Ok(())
    }
}


//------------ IssuedCert ----------------------------------------------------

/// Represents an existing certificate issued to a child.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuedCert {
    url: uri::Rsync,
    req_limit: ResourceSet,
    cert: Cert
}

/// # Encode to XML
/// 
impl IssuedCert {
    fn write_xml<W: io::Write>(
        &self,
        content: &mut encode::Content<W>
    ) -> Result<(), io::Error> {
        content
            .element(CERTIFICATE.into())?
            .attr("cert_url", &self.url)?
            .opt_attr("req_resource_set_as", self.req_limit.asn_opt())?
            .opt_attr("req_resource_set_ipv4", self.req_limit.ipv4_opt())?
            .opt_attr("req_resource_set_ipv6", self.req_limit.ipv6_opt())?
            .content(|inside| {
                inside.base64(self.cert.to_captured().as_slice())
            })?;

        Ok(())
    }
}

//--- PartialEq and Eq

impl PartialEq for IssuedCert {
    fn eq(&self, o: &Self) -> bool {
        self.url == o.url &&
        self.req_limit == o.req_limit &&
        self.cert.to_captured().as_slice() == o.cert.to_captured().as_slice()
    }
}

impl Eq for IssuedCert {}


//------------ SigningCert ---------------------------------------------------

/// Represents the parent CA certificate used to sign child certificates in
/// a given resource class.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningCert {
    url: uri::Rsync,
    cert: Cert,
}

//--- PartialEq and Eq

impl PartialEq for SigningCert {
    fn eq(&self, o: &Self) -> bool {
        self.url == o.url &&
        self.cert.to_captured().as_slice() == o.cert.to_captured().as_slice()
    }
}

impl Eq for SigningCert {}


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
    InvalidCsrSyntax(String),
    CertSyntax(String),
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
            Error::InvalidCsrSyntax(msg) => {
                write!(f, "Could not decode CSR: {}", msg)
            }
            Error::CertSyntax(msg) => {
                write!(f, "Could not decode certificate: {}", msg)
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
        let xml = extract_xml(include_bytes!("../../test-data/remote/rfc6492/list.der"));
        let list = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(list);
    }

    #[test]
    fn parse_and_encode_list_response() {
        let xml = extract_xml(include_bytes!("../../test-data/remote/rfc6492/list-response.ber"));
        let list_response = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(list_response);
    }

    #[test]
    fn parse_and_encode_issue() {
        let xml = extract_xml(include_bytes!("../../test-data/remote/rfc6492/issue.der"));
        let issue = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(issue);
    }

    #[test]
    fn parse_and_encode_issue_response() {
        let xml = extract_xml(include_bytes!("../../test-data/remote/rfc6492/issue-response.der"));
        let issue_response = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(issue_response);
    }

    #[test]
    fn parse_and_encode_revoke() {
        let xml = include_str!("../../test-data/remote/rfc6492/revoke-req.xml");
        let revoke = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(revoke);
    }

    #[test]
    fn parse_and_encode_revoke_response() {
        let xml = include_str!("../../test-data/remote/rfc6492/revoke-response.xml");
        let revoke_response = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(revoke_response);
    }

}