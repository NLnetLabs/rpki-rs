//! Support RFC 6492 Provisioning Protocol (aka up-down)

use std::convert::TryFrom;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::{fmt, io};

use bytes::Bytes;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::repository::crypto::KeyIdentifier;
use crate::repository::crypto::PublicKey;
use crate::repository::crypto::Signer;
use crate::repository::crypto::SigningError;
use crate::repository::resources::{
    AsBlocks, Ipv4Blocks, Ipv6Blocks, ResourceSet
};
use crate::repository::x509::Time;
use crate::repository::x509::ValidationError;
use crate::repository::x509::Validity;
use crate::repository::{Cert, Csr};
use crate::uri;
use crate::xml;
use crate::xml::decode::{Content, Error as XmlError};
use crate::xml::encode;

use super::idcert::IdCert;
use super::idexchange::RecipientHandle;
use super::idexchange::SenderHandle;
use super::sigmsg::SignedMessage;

// Constants for the RFC 6492 XML
const VERSION: &str = "1";
const NS: &[u8] = b"http://www.apnic.net/specs/rescerts/up-down/";

// Content-type for HTTP(s) exchanges
pub const CONTENT_TYPE: &str = "application/rpki-updown";

//------------ ProvisioningCms -----------------------------------------------

// This type represents a created, or parsed, RFC 6492 CMS object.
#[derive(Clone, Debug)]
pub struct ProvisioningCms {
    signed_msg: SignedMessage,
    message: Message,
}

impl ProvisioningCms {
    /// Creates a publication CMS for the given content and signing (ID) key.
    /// This will use a validity time of five minutes before and after 'now'
    /// in order to allow for some NTP drift as well as processing delay
    /// between generating this CMS, sending it, and letting the receiver
    /// validate it.
    pub fn create<S: Signer>(
        message: Message,
        signing_key: &S::KeyId,
        signer: &S,
    ) -> Result<Self, SigningError<S::Error>> {
        let data = message.to_xml_bytes();
        let validity = Validity::new(Time::five_minutes_ago(), Time::five_minutes_from_now());

        let signed_msg = SignedMessage::create(data, validity, signing_key, signer)?;

        Ok(ProvisioningCms {
            signed_msg,
            message,
        })
    }

    /// Unpack into its SignedMessage and Message
    pub fn unpack(self) -> (SignedMessage, Message) {
        (self.signed_msg, self.message)
    }

    pub fn message(&self) -> &Message {
        &self.message
    }

    pub fn into_message(self) -> Message {
        self.message
    }

    /// Encode this to Bytes
    pub fn to_bytes(&self) -> Bytes {
        self.signed_msg.to_captured().into_bytes()
    }

    /// Decodes the CMS and enclosed publication Message from the source.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let signed_msg =
            SignedMessage::decode(bytes, false).map_err(|e| Error::CmsDecode(e.to_string()))?;

        let content = signed_msg.content().to_bytes();
        let message = Message::decode(content.as_ref())?;

        Ok(ProvisioningCms {
            signed_msg,
            message,
        })
    }

    pub fn validate(&self, issuer: &IdCert) -> Result<(), Error> {
        self.signed_msg.validate(issuer).map_err(|e| e.into())
    }

    pub fn validate_at(&self, issuer: &IdCert, when: Time) -> Result<(), Error> {
        self.signed_msg
            .validate_at(issuer, when)
            .map_err(|e| e.into())
    }
}

//------------ Message -------------------------------------------------------

/// This type represents all Provisioning Messages defined in RFC 6492.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    sender: SenderHandle,
    recipient: RecipientHandle,
    payload: Payload,
}

/// # Data Access
///
impl Message {
    pub fn unpack(self) -> (SenderHandle, RecipientHandle, Payload) {
        (self.sender, self.recipient, self.payload)
    }

    pub fn sender(&self) -> &SenderHandle {
        &self.sender
    }

    pub fn recipient(&self) -> &RecipientHandle {
        &self.recipient
    }

    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    pub fn into_payload(self) -> Payload {
        self.payload
    }

    pub fn is_list_response(&self) -> bool {
        matches!(&self.payload, Payload::ListResponse(_))
    }
}

/// # Constructing
///
impl Message {
    pub fn list(sender: SenderHandle, recipient: RecipientHandle) -> Self {
        Message {
            sender,
            recipient,
            payload: Payload::List,
        }
    }

    pub fn list_response(
        sender: SenderHandle,
        recipient: RecipientHandle,
        resource_class_list_response: ResourceClassListResponse,
    ) -> Self {
        Message {
            sender,
            recipient,
            payload: Payload::ListResponse(resource_class_list_response),
        }
    }

    pub fn issue(sender: SenderHandle, recipient: RecipientHandle, issuance_request: IssuanceRequest) -> Self {
        Message {
            sender,
            recipient,
            payload: Payload::Issue(issuance_request),
        }
    }

    pub fn issue_response(
        sender: SenderHandle,
        recipient: RecipientHandle,
        issuance_response: IssuanceResponse,
    ) -> Self {
        Message {
            sender,
            recipient,
            payload: Payload::IssueResponse(issuance_response),
        }
    }

    pub fn revoke(
        sender: SenderHandle,
        recipient: RecipientHandle,
        revocation_request: RevocationRequest,
    ) -> Self {
        Message {
            sender,
            recipient,
            payload: Payload::Revoke(revocation_request),
        }
    }

    pub fn revoke_response(
        sender: SenderHandle,
        recipient: RecipientHandle,
        revocation_response: RevocationResponse,
    ) -> Self {
        Message {
            sender,
            recipient,
            payload: Payload::RevokeResponse(revocation_response),
        }
    }

    pub fn not_performed_response(
        sender: SenderHandle,
        recipient: RecipientHandle,
        not_performed_response: NotPerformedResponse,
    ) -> Result<Self, Error> {
        Ok(Message {
            sender,
            recipient,
            payload: Payload::ErrorResponse(not_performed_response),
        })
    }
}

/// # Encoding to XML
///
impl Message {
    /// Writes the Message's XML representation.
    pub fn write_xml(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);

        writer
            .element("message".into())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("sender", &self.sender)?
            .attr("recipient", &self.recipient)?
            .attr("type", self.payload.payload_type().as_ref())?
            .content(|content| self.payload.write_xml(content))?;

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
    /// Parses an RFC 6492 <message />
    pub fn decode<R: io::BufRead>(reader: R) -> Result<Self, Error> {
        let mut reader = xml::decode::Reader::new(reader);

        let mut sender: Option<SenderHandle> = None;
        let mut recipient: Option<RecipientHandle> = None;
        let mut payload_type: Option<PayloadType> = None;

        let mut outer = reader.start(|element| {
            if element.name().local() != b"message" {
                return Err(XmlError::Malformed);
            }

            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<String>()? != VERSION {
                        return Err(XmlError::Malformed);
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
                _ => Err(XmlError::Malformed),
            })
        })?;

        // Get required attributes - return error if anything is missing.
        let sender = sender.ok_or(XmlError::Malformed)?;
        let recipient = recipient.ok_or(XmlError::Malformed)?;
        let payload_type = payload_type.ok_or(XmlError::Malformed)?;

        // Parse the nested payload
        let payload = Payload::decode(payload_type, &mut outer, &mut reader)?;

        // Check that there is no additional stuff
        outer.take_end(&mut reader)?;
        reader.end()?;

        Ok(Message {
            sender,
            recipient,
            payload,
        })
    }
}

//------------ Payload -------------------------------------------------------

/// Contains the query or reply payload of the message.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Payload {
    List,
    ListResponse(ResourceClassListResponse),
    Issue(IssuanceRequest),
    IssueResponse(IssuanceResponse),
    Revoke(RevocationRequest),
    RevokeResponse(RevocationResponse),
    ErrorResponse(NotPerformedResponse),
}

/// # Decoding from XML
///
impl Payload {
    /// Decodes the nested payload, needs to be given the value of the 'type'
    /// attribute from the outer <message /> element so it can delegate to the
    /// proper enclosed payload variant.
    fn decode<R: io::BufRead>(
        payload_type: PayloadType,
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        match payload_type {
            PayloadType::List => Ok(Payload::List),
            PayloadType::ListResponse => {
                ResourceClassListResponse::decode(content, reader).map(Payload::ListResponse)
            }
            PayloadType::Issue => IssuanceRequest::decode(content, reader).map(Payload::Issue),
            PayloadType::IssueResponse => {
                IssuanceResponse::decode(content, reader).map(Payload::IssueResponse)
            }
            PayloadType::Revoke => RevocationRequest::decode(content, reader).map(Payload::Revoke),
            PayloadType::RevokeResponse => {
                RevocationResponse::decode(content, reader).map(Payload::RevokeResponse)
            }
            PayloadType::ErrorResponse => {
                NotPerformedResponse::decode(content, reader).map(Payload::ErrorResponse)
            }
        }
    }
}

/// # Encoding to XML
///
impl Payload {
    /// Value for the type attribute in the <message /> element.
    pub fn payload_type(&self) -> PayloadType {
        match self {
            Payload::List => PayloadType::List,
            Payload::ListResponse(_) => PayloadType::ListResponse,
            Payload::Issue(_) => PayloadType::Issue,
            Payload::IssueResponse(_) => PayloadType::IssueResponse,
            Payload::Revoke(_) => PayloadType::Revoke,
            Payload::RevokeResponse(_) => PayloadType::RevokeResponse,
            Payload::ErrorResponse(_) => PayloadType::ErrorResponse,
        }
    }

    /// Encode payload content
    fn write_xml<W: io::Write>(&self, content: &mut encode::Content<W>) -> Result<(), io::Error> {
        match self {
            Payload::List => Ok(()), // nothing to write
            Payload::ListResponse(list) => list.write_xml(content),
            Payload::Issue(issue) => issue.write_xml(content),
            Payload::IssueResponse(response) => response.write_xml(content),
            Payload::Revoke(revoke) => revoke.write_xml(content),
            Payload::RevokeResponse(response) => response.write_xml(content),
            Payload::ErrorResponse(res) => res.write_xml(content),
        }
    }
}

//------------ PayloadType ---------------------------------------------------

/// They type of payload for contexts where we care about the type
/// rather than the actual content of the payload. E.g. for reporting
/// or use in the XML attribute.
pub enum PayloadType {
    List,
    ListResponse,
    Issue,
    IssueResponse,
    Revoke,
    RevokeResponse,
    ErrorResponse,
}

impl AsRef<str> for PayloadType {
    fn as_ref(&self) -> &str {
        match self {
            PayloadType::List => "list",
            PayloadType::ListResponse => "list_response",
            PayloadType::Issue => "issue",
            PayloadType::IssueResponse => "issue_response",
            PayloadType::Revoke => "revoke",
            PayloadType::RevokeResponse => "revoke_response",
            PayloadType::ErrorResponse => "error_response",
        }
    }
}

impl FromStr for PayloadType {
    type Err = PayloadTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "list" => Ok(PayloadType::List),
            "list_response" => Ok(PayloadType::ListResponse),
            "issue" => Ok(PayloadType::Issue),
            "issue_response" => Ok(PayloadType::IssueResponse),
            "revoke" => Ok(PayloadType::Revoke),
            "revoke_response" => Ok(PayloadType::RevokeResponse),
            "error_response" => Ok(PayloadType::ErrorResponse),
            _ => Err(PayloadTypeError(s.to_string())),
        }
    }
}

impl fmt::Display for PayloadType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

#[derive(Debug)]
pub struct PayloadTypeError(String);

impl fmt::Display for PayloadTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid payload type: {}", self.0)
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
    pub fn new(class_name: ResourceClassName, limit: RequestResourceLimit, csr: Csr) -> Self {
        IssuanceRequest {
            class_name,
            limit,
            csr,
        }
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
            if element.name().local() != b"request" {
                return Err(XmlError::Malformed);
            }

            element.attributes(|name, value| match name {
                b"class_name" => {
                    class_name = Some(value.ascii_into()?);
                    Ok(())
                }
                b"req_resource_set_as" => {
                    limit.with_asn(value.ascii_into()?);
                    Ok(())
                }
                b"req_resource_set_ipv4" => {
                    limit.with_ipv4(value.ascii_into()?);
                    Ok(())
                }
                b"req_resource_set_ipv6" => {
                    limit.with_ipv6(value.ascii_into()?);
                    Ok(())
                }
                _ => Err(XmlError::Malformed),
            })
        })?;

        let class_name = class_name.ok_or(XmlError::Malformed)?;

        let csr_bytes = request_el.take_text(reader, |text| text.base64_decode())?;

        let csr =
            Csr::decode(csr_bytes.as_ref()).map_err(|e| Error::InvalidCsrSyntax(e.to_string()))?;

        request_el.take_end(reader)?;

        Ok(IssuanceRequest {
            class_name,
            limit,
            csr,
        })
    }
}

/// # Encode to XML
///
impl IssuanceRequest {
    fn write_xml<W: io::Write>(&self, content: &mut encode::Content<W>) -> Result<(), io::Error> {
        content
            .element("request".into())?
            .attr("class_name", self.class_name())?
            .attr_opt("req_resource_set_as", self.limit().asn())?
            .attr_opt("req_resource_set_ipv4", self.limit().ipv4())?
            .attr_opt("req_resource_set_ipv6", self.limit().ipv6())?
            .content(|c| c.base64(self.csr().to_captured().as_slice()))?;

        Ok(())
    }
}

impl PartialEq for IssuanceRequest {
    fn eq(&self, oth: &IssuanceRequest) -> bool {
        self.class_name == oth.class_name
            && self.limit == oth.limit
            && self.csr.to_captured().as_slice() == oth.csr.to_captured().as_slice()
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
/// section 3.4.1 Resource Class List Response, except that it MUST include
/// the ONE certificate which has just been issued only. So we can wrap here
/// and add some guards.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssuanceResponse {
    class_name: ResourceClassName,
    resource_set: ResourceSet,
    not_after: Time,
    issued_cert: IssuedCert,
    signing_cert: SigningCert,
}

/// # Data and Access
///
impl IssuanceResponse {
    pub fn new(
        class_name: ResourceClassName,
        resource_set: ResourceSet,
        not_after: Time,
        issued_cert: IssuedCert,
        signing_cert: SigningCert,
    ) -> Self {
        IssuanceResponse {
            class_name,
            resource_set,
            not_after,
            issued_cert,
            signing_cert,
        }
    }

    pub fn into_issued(self) -> IssuedCert {
        self.issued_cert
    }
}

/// # Encode to XML
///
impl IssuanceResponse {
    fn write_xml<W: io::Write>(&self, content: &mut encode::Content<W>) -> Result<(), io::Error> {
        // Some cloning, but.. it saves us re-implementing the XML
        // writing here.
        ResourceClassEntitlements::new(
            self.class_name.clone(),
            self.resource_set.clone(),
            self.not_after,
            vec![self.issued_cert.clone()],
            self.signing_cert.clone(),
        )
        .write_xml(content)
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
        let mut entitlements =
            ResourceClassEntitlements::decode_opt(content, reader)?.ok_or(XmlError::Malformed)?; // We MUST have 1

        if entitlements.issued_certs.len() != 1 {
            Err(Error::XmlError(XmlError::Malformed))
        } else {
            Ok(IssuanceResponse {
                class_name: entitlements.class_name,
                resource_set: entitlements.resource_set,
                not_after: entitlements.not_after,
                issued_cert: entitlements.issued_certs.pop().unwrap(),
                signing_cert: entitlements.signing_cert,
            })
        }
    }
}

//------------ RequestResourceLimit ------------------------------------------

/// The scope of resources that a child CA wants to have certified. By default
/// there are no limits, i.e. all the child wants all resources the parent is
/// willing to give. Only if some values are specified for certain resource
/// types will the scope be limited for that type only.
///
/// In other words it is possible to have no limit for a resource type using
/// [`None`], but it's also possible to ask for an empty set of resources for
/// one of the types.
///
/// Note that the IssuanceRequest will be rejected by the parent, if the limit
/// exceeds the child's entitlements.
///
/// See: https://tools.ietf.org/html/rfc6492#section-3.4.1
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestResourceLimit {
    #[serde(
        deserialize_with = "RequestResourceLimit::deserialize_asn",
        skip_serializing_if = "Option::is_none",
        default 
    )]
    asn: Option<AsBlocks>,

    #[serde(
        alias = "v4",
        deserialize_with = "RequestResourceLimit::deserialize_ipv4",
        skip_serializing_if = "Option::is_none",
        default 
    )]
    ipv4: Option<Ipv4Blocks>,

    #[serde(
        alias = "v6",
        deserialize_with = "RequestResourceLimit::deserialize_ipv6",
        skip_serializing_if = "Option::is_none",
        default 
    )]
    ipv6: Option<Ipv6Blocks>,
}

impl RequestResourceLimit {
    pub fn new() -> RequestResourceLimit {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.asn == None && self.ipv4 == None && self.ipv6 == None
    }

    pub fn with_asn(&mut self, asn: AsBlocks) {
        self.asn = Some(asn);
    }

    pub fn with_ipv4(&mut self, ipv4: Ipv4Blocks) {
        self.ipv4 = Some(ipv4);
    }

    pub fn with_ipv6(&mut self, ipv6: Ipv6Blocks) {
        self.ipv6 = Some(ipv6);
    }

    pub fn asn(&self) -> Option<&AsBlocks> {
        self.asn.as_ref()
    }

    pub fn ipv4(&self) -> Option<&Ipv4Blocks> {
        self.ipv4.as_ref()
    }

    pub fn ipv6(&self) -> Option<&Ipv6Blocks> {
        self.ipv6.as_ref()
    }

    /// Apply this limit to the given set, returns a new set.
    ///
    /// will return an error in case the limit exceeds the set.
    pub fn apply_to(&self, set: &ResourceSet) -> Result<ResourceSet, Error> {
        if self.is_empty() {
            return Ok(set.clone());
        }

        let asn = {
            match &self.asn {
                None => set.asn().clone(),
                Some(asn) => {
                    if set.asn().contains(asn) {
                        asn.clone()
                    } else {
                        return Err(Error::limit(set, self));
                    }
                }
            }
        };

        let ipv4 = {
            match &self.ipv4 {
                None => set.ipv4().clone(),
                Some(ipv4) => {
                    if set.ipv4().contains(ipv4) {
                        ipv4.clone()
                    } else {
                        return Err(Error::limit(set, self));
                    }
                }
            }
        };

        let ipv6 = {
            match &self.ipv6 {
                None => set.ipv6().clone(),
                Some(ipv6) => {
                    if set.ipv6().contains(ipv6) {
                        ipv6.clone()
                    } else {
                        return Err(Error::limit(set, self));
                    }
                }
            }
        };

        Ok(ResourceSet::new(asn, ipv4, ipv6))
    }
}

// Support legacy deserialization for custom format used by Krill
// where the string "none" was used for None values, instead of null.
impl RequestResourceLimit {
    
    fn deserialize_asn<'de, D>(d: D) -> Result<Option<AsBlocks>, D::Error>
    where
    D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        if string.as_str() == "none" {
            Ok(None)
        } else {
            AsBlocks::from_str(string.as_str())
                .map(Some)
                .map_err(de::Error::custom)
        }
        
    }

    fn deserialize_ipv4<'de, D>(d: D) -> Result<Option<Ipv4Blocks>, D::Error>
    where
    D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        if string.as_str() == "none" {
            Ok(None)
        } else {
            Ipv4Blocks::from_str(string.as_str())
                .map(Some)
                .map_err(de::Error::custom)
        }
    }

    fn deserialize_ipv6<'de, D>(d: D) -> Result<Option<Ipv6Blocks>, D::Error>
    where
    D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        if string.as_str() == "none" {
            Ok(None)
        } else {
            Ipv6Blocks::from_str(string.as_str())
                .map(Some)
                .map_err(de::Error::custom)
        }
    }
}

//--- Display

impl fmt::Display for RequestResourceLimit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_empty() {
            write!(f, "none")
        } else {
            let mut space_needed = false;
            if let Some(asn) = &self.asn {
                write!(f, "asn: {}", asn)?;
                space_needed = true;
            }
            if let Some(ipv4) = self.ipv4() {
                if space_needed {
                    write!(f, " ")?;
                }
                write!(f, "ipv4: {}", ipv4)?;
                space_needed = true;
            }

            if let Some(ipv6) = self.ipv6() {
                if space_needed {
                    write!(f, " ")?;
                }
                write!(f, "ipv6: {}", ipv6)?;
            }

            Ok(())
        }
    }
}

//------------ RevocationRequest ---------------------------------------------

/// This type represents a Certificate Revocation Request as
/// defined in section 3.5.1 of RFC6492.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RevocationRequest(KeyElement);

impl RevocationRequest {
    pub fn new(class_name: ResourceClassName, key: KeyIdentifier) -> Self {
        RevocationRequest(KeyElement { class_name, key })
    }

    pub fn unpack(self) -> (ResourceClassName, KeyIdentifier) {
        (self.0.class_name, self.0.key)
    }

    pub fn key(&self) -> KeyIdentifier {
        *self.0.key()
    }

    pub fn class_name(&self) -> &ResourceClassName {
        self.0.class_name()
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

impl RevocationResponse {
    pub fn new(key: KeyElement) -> Self {
        RevocationResponse(key)
    }
}

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

impl From<&RevocationRequest> for RevocationResponse {
    fn from(req: &RevocationRequest) -> Self {
        RevocationResponse(req.0.clone())
    }
}

//------------ KeyElement ----------------------------------------------------

/// This type represents a <key /> element as used in both the Certificate
/// Revocation Request and Response, sections 3.5.1 and 3.5.2 respectively,
/// of RFC6492.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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

        content.take_element(reader, |element| {
            if element.name().local() != b"key" {
                return Err(XmlError::Malformed);
            }

            element.attributes(|name, value| match name {
                b"class_name" => {
                    class_name = Some(value.ascii_into()?);
                    Ok(())
                }
                b"ski" => {
                    let base64_str: String = value.ascii_into()?;
                    let bytes = base64::decode_config(base64_str, base64::URL_SAFE_NO_PAD)
                        .map_err(|_| XmlError::Malformed)?;

                    let ski = KeyIdentifier::try_from(bytes.as_slice())
                        .map_err(|_| XmlError::Malformed)?;

                    key = Some(ski);
                    Ok(())
                }
                _ => Err(XmlError::Malformed),
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
    fn write_xml<W: io::Write>(&self, content: &mut encode::Content<W>) -> Result<(), io::Error> {
        let ski = base64::encode_config(
            self.key().as_slice(),
            // it's not 100% clear from the RFC whether padding is used.
            // using no-pad makes this most likely to be accepted.
            base64::URL_SAFE_NO_PAD,
        );
        content
            .element("key".into())?
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
/// entitlements for 0 or more corresponding resource classes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClassListResponse {
    classes: Vec<ResourceClassEntitlements>,
}

impl ResourceClassListResponse {
    pub fn new(
        classes: Vec<ResourceClassEntitlements>
    ) -> Self {
        ResourceClassListResponse { classes }
    }

    pub fn classes(&self) -> &Vec<ResourceClassEntitlements> {
        &self.classes
    }
}

/// # Decode from XML
///
impl ResourceClassListResponse {
    fn decode<R: io::BufRead>(
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        let mut classes = vec![];

        while let Some(entitlement) = ResourceClassEntitlements::decode_opt(content, reader)? {
            classes.push(entitlement);
        }

        Ok(ResourceClassListResponse { classes })
    }
}

/// # Encode to XML
///
impl ResourceClassListResponse {
    fn write_xml<W: io::Write>(&self, content: &mut encode::Content<W>) -> Result<(), io::Error> {
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

/// # Data and Access
///
impl ResourceClassEntitlements {
    pub fn new(
        class_name: ResourceClassName,
        resource_set: ResourceSet,
        not_after: Time,
        issued_certs: Vec<IssuedCert>,
        signing_cert: SigningCert,
    ) -> Self {
        ResourceClassEntitlements {
            class_name,
            resource_set,
            not_after,
            issued_certs,
            signing_cert,
        }
    }

    pub fn class_name(&self) -> &ResourceClassName {
        &self.class_name
    }

    pub fn resource_set(&self) -> &ResourceSet {
        &self.resource_set
    }

    pub fn not_after(&self) -> Time {
        self.not_after
    }

    pub fn issued_certs(&self) -> &Vec<IssuedCert> {
        &self.issued_certs
    }

    pub fn signing_cert(&self) -> &SigningCert {
        &self.signing_cert
    }

    /// Converts this into an IssuanceResponse for the given key. I.e. includes
    /// the issued certificate matching the given public key only. Returns a
    /// None if no match is found.
    pub fn into_issuance_response(self, key: &PublicKey) -> Option<IssuanceResponse> {
        let (class_name, resource_set, not_after, issued_certs, signing_cert) = (
            self.class_name,
            self.resource_set,
            self.not_after,
            self.issued_certs,
            self.signing_cert,
        );

        issued_certs
            .into_iter()
            .find(|issued| issued.cert().subject_public_key_info() == key)
            .map(|issued| {
                IssuanceResponse::new(class_name, resource_set, not_after, issued, signing_cert)
            })
    }
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
        let mut resource_set = ResourceSet::default();
        let mut not_after: Option<Time> = None;

        let class_element = content.take_opt_element(reader, |element| {
            if element.name().local() != b"class" {
                return Err(XmlError::Malformed);
            }

            element.attributes(|name, value| match name {
                b"class_name" => {
                    class_name = Some(value.ascii_into()?);
                    Ok(())
                }
                b"cert_url" => {
                    cert_url = Some(value.ascii_into()?);
                    Ok(())
                }
                b"resource_set_as" => {
                    resource_set.set_asn(value.ascii_into()?);
                    Ok(())
                }
                b"resource_set_ipv4" => {
                    resource_set.set_ipv4(value.ascii_into()?);
                    Ok(())
                }
                b"resource_set_ipv6" => {
                    resource_set.set_ipv6(value.ascii_into()?);
                    Ok(())
                }
                b"resource_set_notafter" => {
                    let date_time: DateTime<Utc> = value.ascii_into()?;
                    not_after = Some(Time::new(date_time));
                    Ok(())
                }
                b"suggested_sia_head" => {
                    // safe to ignore - optional and replaced by 'sia_base'
                    // in the RFC 8183 Repository Response.
                    Ok(())
                }
                _ => Err(XmlError::Malformed),
            })
        })?;

        let mut class_element = match class_element {
            None => return Ok(None),
            Some(inner) => inner,
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
            let mut req_limit = RequestResourceLimit::default();

            let cert_el = class_element.take_opt_element(reader, |el| match el.name().local() {
                b"certificate" => el.attributes(|name, value| match name {
                    b"cert_url" => {
                        url = Some(value.ascii_into()?);
                        Ok(())
                    }
                    b"req_resource_set_as" => {
                        req_limit.with_asn(value.ascii_into()?);
                        Ok(())
                    }
                    b"req_resource_set_ipv4" => {
                        req_limit.with_ipv4(value.ascii_into()?);
                        Ok(())
                    }
                    b"req_resource_set_ipv6" => {
                        req_limit.with_ipv6(value.ascii_into()?);
                        Ok(())
                    }
                    _ => Err(XmlError::Malformed),
                }),
                b"issuer" => {
                    was_issuer = true;
                    Ok(())
                }
                _ => Err(XmlError::Malformed),
            })?;

            let mut cert_el = match cert_el {
                None => break,
                Some(inner) => inner,
            };

            // no matter whether this was an issued *received* certificate or
            // the signing 'issuer' certificate.. we expect a base64 encoded
            // certificate inside this element.
            let bytes = cert_el.take_text(reader, |txt| txt.base64_decode())?;
            let cert =
                Cert::decode(bytes.as_ref()).map_err(|e| Error::CertSyntax(e.to_string()))?;

            if was_issuer {
                issuer = Some(cert);
            } else {
                let url = url.ok_or(XmlError::Malformed)?;

                issued_certs.push(IssuedCert {
                    uri: url,
                    req_limit,
                    cert,
                });
            }

            cert_el.take_end(reader)?;
        }

        let issuer = issuer.ok_or(XmlError::Malformed)?;

        let signing_cert = SigningCert {
            cert: issuer,
            url: issuer_url,
        };

        class_element.take_end(reader)?;

        Ok(Some(ResourceClassEntitlements {
            class_name,
            resource_set,
            not_after,
            issued_certs,
            signing_cert,
        }))
    }
}

/// # Encode to XML
///
impl ResourceClassEntitlements {
    fn write_xml<W: io::Write>(&self, content: &mut encode::Content<W>) -> Result<(), io::Error> {
        let not_after = self.not_after.to_rfc3339_opts(SecondsFormat::Secs, true);

        content
            .element("class".into())?
            .attr("class_name", &self.class_name)?
            .attr("cert_url", &self.signing_cert.url)?
            .attr_opt("resource_set_as", self.resource_set.asn_opt())?
            .attr_opt("resource_set_ipv4", self.resource_set.ipv4_opt())?
            .attr_opt("resource_set_ipv6", self.resource_set.ipv6_opt())?
            .attr("resource_set_notafter", &not_after)?
            .content(|nested| {
                for issued in &self.issued_certs {
                    issued.write_xml(nested)?;
                }

                nested.element("issuer".into())?.content(|inner| {
                    inner.base64(self.signing_cert.cert.to_captured().as_slice())
                })?;

                Ok(())
            })?;

        Ok(())
    }
}

//------------ NotPerformedResponse ------------------------------------------

/// This type describes the Not-performed responses defined in section 3.6
/// of RFC 6492.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotPerformedResponse {
    status: u64,
    description: Option<String>,
}

impl NotPerformedResponse {
    pub fn status(&self) -> u64 {
        self.status
    }

    pub fn description(&self) -> Option<&String> {
        self.description.as_ref()
    }

    /// Private.. use the public err_* functions instead!
    fn new(status: u64, txt: &str) -> Self {
        NotPerformedResponse {
            status,
            description: Some(txt.to_string()),
        }
    }

    /// Already processing
    pub fn err_1101() -> Self {
        Self::new(1101, "already processing request")
    }

    /// Version number error
    pub fn err_1102() -> Self {
        Self::new(1102, "version number error")
    }

    /// Unrecognized request type
    pub fn err_1103() -> Self {
        Self::new(1103, "unrecognized request type")
    }

    /// Request scheduled for processing
    pub fn err_1104() -> Self {
        Self::new(1104, "request scheduled for processing")
    }

    /// No such resource class
    pub fn err_1201() -> Self {
        Self::new(1201, "request - no such resource class")
    }

    /// No resources in resource class
    pub fn err_1202() -> Self {
        Self::new(1202, "request - no resources allocated in resource class")
    }

    /// Badly formed certificate request
    pub fn err_1203() -> Self {
        Self::new(1203, "request - badly formed certificate request")
    }

    /// Key re-use detected
    pub fn err_1204() -> Self {
        Self::new(1204, "request - already used key in request")
    }

    /// No such resource class
    pub fn err_1301() -> Self {
        Self::new(1301, "revoke - no such resource class")
    }

    /// No such key
    pub fn err_1302() -> Self {
        Self::new(1302, "revoke - no such key")
    }

    /// Internal server error
    pub fn err_2001() -> Self {
        Self::new(2001, "Internal Server Error - Request not performed")
    }
}

/// XML Support
///
impl NotPerformedResponse {
    /// Decodes an RFC 6492 section 3.6 Request-Not-Performed-Response.
    ///
    /// XML format of the content is:
    ///   <status>[Code]</status>
    ///   <description xml:lang="en-US">[Readable text]</description>
    ///
    /// Note that 'xml:lang="en-US"' MUST be present if the optional
    /// <description /> element is present and cannot have any other
    /// value.
    fn decode<R: io::BufRead>(
        content: &mut Content,
        reader: &mut xml::decode::Reader<R>,
    ) -> Result<Self, Error> {
        let mut status_element = content.take_element(reader, |element| {
            if element.name().local() != b"status" {
                Err(XmlError::Malformed)
            } else {
                Ok(())
            }
        })?;

        let status = status_element.take_text(reader, |text| {
            u64::from_str(&text.to_ascii()?).map_err(|_| XmlError::Malformed)
        })?;

        status_element.take_end(reader)?;

        let mut description = None;
        if let Some(mut element) = content.take_opt_element(reader, |element| {
            if element.name().local() != b"description" {
                Err(XmlError::Malformed)
            } else {
                Ok(())
            }
        })? {
            description =
                Some(element.take_text(reader, |text| text.to_ascii().map(|d| d.to_string()))?);

            element.take_end(reader)?;
        }

        Ok(NotPerformedResponse {
            status,
            description,
        })
    }

    fn write_xml<W: io::Write>(&self, content: &mut encode::Content<W>) -> Result<(), io::Error> {
        content
            .element("status".into())?
            .content(|status| status.raw(&self.status.to_string()))?;

        content.element_opt(
            self.description.as_ref(),
            "description".into(),
            |description, el| {
                el.content(|content| content.raw(description))?;
                Ok(())
            },
        )
    }
}

impl fmt::Display for NotPerformedResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.description {
            None => write!(f, "{}", self.status),
            Some(d) => write!(f, "{} - {}", self.status, d),
        }
    }
}

//------------ IssuedCert ----------------------------------------------------

/// Represents an existing certificate issued to a child.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuedCert {
    uri: uri::Rsync,
    req_limit: RequestResourceLimit,
    cert: Cert,
}

/// # Data and Access
///
impl IssuedCert {
    pub fn new(uri: uri::Rsync, req_limit: RequestResourceLimit, cert: Cert) -> Self {
        IssuedCert {
            uri,
            req_limit,
            cert,
        }
    }

    pub fn unpack(self) -> (uri::Rsync, RequestResourceLimit, Cert) {
        (self.uri, self.req_limit, self.cert)
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn req_limit(&self) -> &RequestResourceLimit {
        &self.req_limit
    }

    pub fn cert(&self) -> &Cert {
        &self.cert
    }
}

/// # Encode to XML
///
impl IssuedCert {
    fn write_xml<W: io::Write>(&self, content: &mut encode::Content<W>) -> Result<(), io::Error> {
        content
            .element("certificate".into())?
            .attr("cert_url", &self.uri)?
            .attr_opt("req_resource_set_as", self.req_limit.asn())?
            .attr_opt("req_resource_set_ipv4", self.req_limit.ipv4())?
            .attr_opt("req_resource_set_ipv6", self.req_limit.ipv6())?
            .content(|inside| inside.base64(self.cert.to_captured().as_slice()))?;

        Ok(())
    }
}

//--- PartialEq and Eq

impl PartialEq for IssuedCert {
    fn eq(&self, o: &Self) -> bool {
        self.uri == o.uri
            && self.req_limit == o.req_limit
            && self.cert.to_captured().as_slice() == o.cert.to_captured().as_slice()
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

impl SigningCert {
    pub fn new(url: uri::Rsync, cert: Cert) -> Self {
        SigningCert { url, cert }
    }

    pub fn url(&self) -> &uri::Rsync {
        &self.url
    }

    pub fn cert(&self) -> &Cert {
        &self.cert
    }
}

//--- PartialEq and Eq

impl PartialEq for SigningCert {
    fn eq(&self, o: &Self) -> bool {
        self.url == o.url && self.cert.to_captured().as_slice() == o.cert.to_captured().as_slice()
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
        ResourceClassName {
            name: nr.to_string().into(),
        }
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
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ResourceClassName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<ResourceClassName, D::Error> {
        let string = String::deserialize(deserializer)?;
        Ok(ResourceClassName::from(string))
    }
}

//------------ ProvisioningMessageError --------------------------------------

#[derive(Debug)]
pub enum Error {
    InvalidVersion,
    XmlError(XmlError),
    InvalidPayloadType(PayloadTypeError),
    InvalidCsrSyntax(String),
    CertSyntax(String),
    CmsDecode(String),
    Validation(ValidationError),
    Limit(ResourceSet, RequestResourceLimit),
}

impl Error {
    fn limit(set: &ResourceSet, limit: &RequestResourceLimit) -> Self {
        Error::Limit(set.clone(), limit.clone())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidVersion => write!(f, "Invalid protocol version, MUST be 1"),
            Error::XmlError(e) => e.fmt(f),
            Error::InvalidPayloadType(e) => e.fmt(f),
            Error::InvalidCsrSyntax(msg) => {
                write!(f, "Could not decode CSR: {}", msg)
            }
            Error::CertSyntax(msg) => {
                write!(f, "Could not decode certificate: {}", msg)
            }
            Error::CmsDecode(msg) => {
                write!(f, "Could not decode CMS: {}", msg)
            }
            Error::Validation(e) => {
                write!(f, "CMS is not valid: {}", e)
            }
            Error::Limit(set, limit) => {
                write!(
                    f,
                    "Limit '{}' contains resources not held in set '{}'",
                    limit, set
                )
            }
        }
    }
}

impl From<XmlError> for Error {
    fn from(e: XmlError) -> Self {
        Error::XmlError(e)
    }
}

impl From<PayloadTypeError> for Error {
    fn from(e: PayloadTypeError) -> Self {
        Error::InvalidPayloadType(e)
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

    use crate::ca::sigmsg::SignedMessage;
    use std::str::from_utf8_unchecked;

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
        let xml = extract_xml(include_bytes!("../../test-data/ca/rfc6492/list.der"));
        let list = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(list);
    }

    #[test]
    fn parse_and_encode_list_response() {
        let xml = extract_xml(include_bytes!(
            "../../test-data/ca/rfc6492/list-response.ber"
        ));
        let list_response = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(list_response);
    }

    #[test]
    fn parse_and_encode_issue() {
        let xml = extract_xml(include_bytes!("../../test-data/ca/rfc6492/issue.der"));
        let issue = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(issue);
    }

    #[test]
    fn parse_and_encode_issue_response() {
        let xml = extract_xml(include_bytes!(
            "../../test-data/ca/rfc6492/issue-response.der"
        ));
        let issue_response = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(issue_response);
    }

    #[test]
    fn parse_and_encode_revoke() {
        let xml = include_str!("../../test-data/ca/rfc6492/revoke-req.xml");
        let revoke = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(revoke);
    }

    #[test]
    fn parse_and_encode_revoke_response() {
        let xml = include_str!("../../test-data/ca/rfc6492/revoke-response.xml");
        let revoke_response = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(revoke_response);
    }

    #[test]
    fn parse_and_encode_not_performed_response() {
        let xml = include_str!("../../test-data/ca/rfc6492/not-performed-response.xml");
        let not_performed_response = Message::decode(xml.as_bytes()).unwrap();
        assert_re_encode_equals(not_performed_response);
    }
}

#[cfg(all(test, feature = "softkeys"))]
mod signer_test {

    use super::*;

    use crate::{
        ca::idcert::IdCert,
        repository::crypto::{
            softsigner::{KeyId, OpenSslSigner},
            PublicKeyFormat,
        },
    };

    fn sign_and_validate_msg(
        signer: &OpenSslSigner,
        ta_key: KeyId,
        ta_cert: &IdCert,
        message: Message,
    ) {
        let cms = ProvisioningCms::create(message.clone(), &ta_key, signer).unwrap();

        let bytes = cms.to_bytes();

        let decoded = ProvisioningCms::decode(&bytes).unwrap();
        decoded.validate(ta_cert).unwrap();

        let decoded_message = decoded.into_message();

        assert_eq!(message, decoded_message);
    }

    #[test]
    fn sign_and_validate() {
        let signer = OpenSslSigner::new();

        let key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
        let cert = IdCert::new_ta(Validity::from_secs(60), &key, &signer).unwrap();

        let child = SenderHandle::from_str("child").unwrap();
        let parent = RecipientHandle::from_str("parent").unwrap();

        let list = Message::list(child, parent);

        sign_and_validate_msg(&signer, key, &cert, list);
    }

    #[test]
    fn deserialize_legacy_request_resource_limit() {
        let krill_legacy_json = 
                "{ \"asn\": \"none\", \"v4\": \"none\", \"v6\": \"none\" }";
        let _: RequestResourceLimit = serde_json::from_str(krill_legacy_json)
            .unwrap();

        let json = 
                "{ \"v4\": \"10.0.0.0/8\", \"v6\": \"none\" }";
        let _: RequestResourceLimit = serde_json::from_str(json)
            .unwrap();
    }
}
