//! Parsing and processing of RRDP responses.
//!
//! This module provides the scaffolding for client-side processing of the
//! RPKI Repository Delta Protocol (RRDP) as defined in [RFC 8182].
//!
//! Processing is done in two parts. The RRDP notification file is parsed into
//! a value of type [`NotificationFile`]. Processing of snapshot and delta
//! files is done incrementally via the [`ProcessSnapshot`] and
//! [`ProcessDelta`] traits since these files can become rather big.
//!
//! The module does not provide an HTTP client. Rather, it relies on the
//! `std::io::Read` trait for processing. As such, it is also not compatible
//! with async processing.
//!
//! A note on terminology: to avoid confusion, the term ‘file’ refers to the
//! RRDP data itself, i.e., the notification, snapshot, and delta files. The
//! repository’s content synchronized using RRDP also consists of a set of
//! files, which we will refer to as ‘objects.’
//!
//! [RFC 8182]: https://tools.ietf.org/html/rfc8182

#![cfg(feature = "rrdp")]

use std::{error, fmt, hash, io, str};
use std::io::Read;
use std::ops::Deref;
use bytes::Bytes;
use log::info;
use ring::digest;
use uuid::Uuid;
use crate::{uri, xml};
use crate::util::base64;
use crate::xml::decode::{Content, Error as XmlError, Reader, Name};

#[cfg(feature = "serde")] use std::str::FromStr;
#[cfg(feature = "serde")] use serde::{
    Deserialize, Deserializer, Serialize, Serializer
};


//------------ NotificationFile ----------------------------------------------

/// The RRDP Update Notification File.
///
/// This type represents the decoded content of the RRDP Update Notification
/// File. It can be read from a reader via the [`parse`][Self::parse]
/// function. All elements are accessible as attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationFile {
    /// The identifier of the current session of the server.
    session_id: Uuid,

    /// The serial number of the most recent update.
    serial: u64,

    /// Information about the most recent snapshot.
    snapshot: SnapshotInfo,

    /// The list of available delta updates.
    ///
    /// If parsing the list fails for a “soft” reason, this is set to the
    /// error variant.
    deltas: Result<Vec<DeltaInfo>, DeltaListError>,
}

/// # Data Access
///
impl NotificationFile {
    /// Creates a new notification file from the given components.
    pub fn new(
        session_id: Uuid,
        serial: u64,
        snapshot: UriAndHash,
        deltas: Vec<DeltaInfo>,
    ) -> Self {
        NotificationFile {
            session_id,
            serial,
            snapshot,
            deltas: Ok(deltas),
        }
    }

    /// Returns the identifier of the current session of the server.
    ///
    /// Delta updates can only be used if the session ID of the last processed
    /// update matches this value.
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Returns the serial number of the most recent update.
    ///
    /// Serial numbers increase by one between each update.
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// Returns information about the most recent snapshot.
    ///
    /// The snapshot contains a complete set of all data published via the
    /// repository. It can be processed using the [`ProcessSnapshot`] trait.
    pub fn snapshot(&self) -> &SnapshotInfo {
        &self.snapshot
    }

    /// Returns the list of available delta updates.
    ///
    /// Deltas can be processed using the [`ProcessDelta`] trait.
    ///
    /// If `delta_status` returns an error, this list will be empty.
    pub fn deltas(&self) -> &[DeltaInfo] {
        match self.deltas {
            Ok(ref deltas) => deltas.as_slice(),
            Err(_) => &[]
        }
    }

    /// Returns the status of the delta list.
    pub fn delta_status(&self) -> Result<(), DeltaListError> {
        match self.deltas {
            Ok(_) => Ok(()),
            Err(err) => Err(err)
        }
    }

    /// Sorts the deltas by increasing serial numbers.
    ///
    /// In other words, the delta with the smallest serial number will
    /// appear at the beginning of the sequence.
    pub fn sort_deltas(&mut self) {
        if let Ok(ref mut deltas) = self.deltas {
            deltas.sort_by_key(|delta| delta.serial());
        }
    }

    /// Sorts the deltas by decreasing serial numbers.
    ///
    /// In other words, the delta with the largest serial number will
    /// appear at the beginning of the sequence.
    pub fn reverse_sort_deltas(&mut self) {
        if let Ok(ref mut deltas) = self.deltas {
            deltas.sort_by(|a,b| b.serial.cmp(&a.serial));
        }
    }

    /// Sorts, verifies, and optionally limits the list of deltas.
    ///
    /// Sorts the deltas by increasing serial number. If `limit` is given,
    /// it then retains at most that many of the newest deltas.
    ///
    /// Returns whether there are no gaps in the retained deltas.
    pub fn sort_and_verify_deltas(&mut self, limit: Option<usize>) -> bool {
        if let Ok(ref mut deltas) = self.deltas {
            if !deltas.is_empty() {
                deltas.sort_by_key(|delta| delta.serial());

                if let Some(limit) = limit {
                    if limit < deltas.len() {
                        let offset = deltas.len() - limit;
                        deltas.drain(..offset);
                    }
                }

                let mut last_seen = deltas[0].serial();
                for delta in &deltas[1..] {
                    if last_seen + 1 != delta.serial() {
                        return false;
                    } else {
                        last_seen = delta.serial()
                    }
                }
            }
        }

        true
    }

    /// Returns whether all URIs have the same origin as the given URI.
    pub fn has_matching_origins(&self, base: &uri::Https) -> bool {
        if !base.eq_authority(self.snapshot().uri()) {
            return false
        }
        if let Ok(ref deltas) = self.deltas {
            if deltas.iter().any(|delta| !base.eq_authority(delta.uri())) {
                return false
            }
        }
        true
    }
}

/// # XML support
///
impl NotificationFile {
    /// Parses the notification file from its XML representation.
    pub fn parse<R: io::BufRead>(
        reader: R,
    ) -> Result<Self, XmlError> {
        Self::_parse(reader, None)
    }

    /// Parses the notification file with a limit on the delta_list.
    ///
    /// If there are more delta entries than the given limit, the list of the
    /// returned value will be empty and [`Self::delta_status`] will return
    /// an error.
    pub fn parse_limited<R: io::BufRead>(
        reader: R,
        delta_limit: usize,
    ) -> Result<Self, XmlError> {
        Self::_parse(reader, Some(delta_limit))
    }

    pub fn _parse<R: io::BufRead>(
        reader: R,
        delta_limit: Option<usize>,
    ) -> Result<Self, XmlError> {
        let mut reader = Reader::new(reader);
        
        let mut session_id = None;
        let mut serial = None;
        let mut outer = reader.start_with_limit(|element| {
            if element.name() != NOTIFICATION {
                return Err(XmlError::Malformed)
            }

            element.attributes(|name, value| {
                match name {
                    b"version" => {
                        if value.ascii_into::<u8>()? != 1 {
                            return Err(XmlError::Malformed)
                        }
                        Ok(())
                    }
                    b"session_id" => {
                        session_id = Some(value.ascii_into()?);
                        Ok(())
                    }
                    b"serial" => {
                        serial = Some(value.ascii_into()?);
                        Ok(())
                    }
                    _ => Err(XmlError::Malformed)
                }
        })
        }, 100_000_000)?;

        let mut snapshot = None;

        let mut deltas = Ok(vec![]);

        while let Some(mut content) = outer.take_opt_element_with_limit(&mut reader,
                                                             |element| {
            match element.name() {
                SNAPSHOT => {
                    if snapshot.is_some() {
                        return Err(XmlError::Malformed)
                    }
                    let mut uri = None;
                    let mut hash = None;
                    element.attributes(|name, value| match name {
                        b"uri" => {
                            uri = Some(value.ascii_into()?);
                            Ok(())
                        }
                        b"hash" => {
                            hash = Some(value.ascii_into()?);
                            Ok(())
                        }
                        _ => Err(XmlError::Malformed)
                    })?;
                    match (uri, hash) {
                        (Some(uri), Some(hash)) => {
                            snapshot = Some(UriAndHash::new(uri, hash));
                            Ok(())
                        }
                        _ => Err(XmlError::Malformed)
                    }
                }
                DELTA => {
                    let mut serial = None;
                    let mut uri = None;
                    let mut hash = None;
                    element.attributes(|name, value| match name {
                        b"serial" => {
                            serial = Some(value.ascii_into()?);
                            Ok(())
                        }
                        b"uri" => {
                            uri = Some(value.ascii_into()?);
                            Ok(())
                        }
                        b"hash" => {
                            hash = Some(value.ascii_into()?);
                            Ok(())
                        }
                        _ => Err(XmlError::Malformed)
                    })?;
                    let (serial, uri, hash) = match (serial, uri, hash) {
                        (Some(serial), Some(uri), Some(hash)) =>  {
                            (serial, uri, hash)
                        }
                        _ => return Err(XmlError::Malformed)
                    };
                    if let Some(limit) = delta_limit {
                        let len = deltas.as_ref().map(|deltas| {
                            deltas.len()
                        }).unwrap_or(0);
                        if len >= limit {
                            deltas = Err(DeltaListError::Oversized);
                        }
                    }
                    if let Ok(ref mut deltas) = deltas {
                        deltas.push(DeltaInfo::new(serial, uri, hash))
                    }
                    Ok(())
                }
                _ => Err(XmlError::Malformed)
            }
        }, 100_000_000)? {
            content.take_end(&mut reader)?;
        }

        outer.take_end(&mut reader)?;
        reader.end()?;

        match (session_id, serial, snapshot) {
            (Some(session_id), Some(serial), Some(snapshot)) => {
                Ok(NotificationFile { session_id, serial, snapshot, deltas })
            }
            _ => Err(XmlError::Malformed)
        }
    }

    /// Writes the notification file as RFC 8182 XML.
    pub fn write_xml(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);
        writer.element(NOTIFICATION.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", "1")?
            .attr("session_id", &self.session_id)?
            .attr("serial", &self.serial)?
            .content(|content| {
                // add snapshot
                content.element(SNAPSHOT.into_unqualified())?
                    .attr("uri", self.snapshot.uri())?
                    .attr("hash", &self.snapshot.hash())?
                ;

                // add deltas
                for delta in self.deltas() {
                    content.element(DELTA.into_unqualified())?
                        .attr("serial", &delta.serial())?
                        .attr("uri", delta.uri())?
                        .attr("hash", &delta.hash())?
                    ;
                }

                Ok(())
            })?;
        writer.done()
    }
}


//------------ PublishElement ------------------------------------------------

/// Am RPKI object to be published for the first time.
///
/// This type defines an RRDP publish element as found in RRDP Snapshots and
/// Deltas. See [`UpdateElement`] for the related element that replaces a
/// previous element for the same uri.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishElement {
    /// The URI of the object to be published.
    uri: uri::Rsync,

    /// The content of the object to be published.
    ///
    /// This is the raw content. It is _not_ Base64 encoded.
    data: Bytes,
}

impl PublishElement {
    /// Creates a new publish element from the object URI and content.
    ///
    /// The content provided via `data` is the raw content and must not yet
    /// be Base64 encoded.
    pub fn new(
        uri: uri::Rsync,
        data: Bytes,
    ) -> Self {
        PublishElement { uri, data }
    }
    
    /// Returns the published object’s URI.
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    /// Returns the published object’s content.
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Converts `self` into the object’s URI and content.
    pub fn unpack(self) -> (uri::Rsync, Bytes) {
        (self.uri, self.data)
    }

    /// Writes the publish element’s XML.
    fn write_xml(
        &self,
        content: &mut xml::encode::Content<impl io::Write>
    ) -> Result<(), io::Error> {
        content.element(PUBLISH.into_unqualified())?
            .attr("uri", &self.uri)?
            .content(|content| {
                content.base64(self.data.as_ref())
            })?;
        Ok(())
    }
}


//------------ UpdateElement -------------------------------------------------

/// An RPKI object to be updated with new content.
///
/// This type defines an RRDP update element as found in RRDP deltas. It is
/// like a [`PublishElement`] except that it replaces an existing object for
/// a URI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateElement {
    /// The URI of the object to be updated.
    uri: uri::Rsync,

    /// The SHA-256 hash of the previous content of the object.
    hash: Hash,

    /// The new content of the object.
    ///
    /// This is the raw content. It is _not_ Base64 encoded.
    data: Bytes,
}

impl UpdateElement {
    /// Creates a new update element from its components.
    pub fn new(uri: uri::Rsync, hash: Hash, data: Bytes) -> Self {
        UpdateElement { uri, hash, data }
    }

    /// Returns the URI of the object to update.
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    /// Returns the hash of the previous content.
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Returns the new content of the object.
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Unpacks the update element into its components.
    pub fn unpack(self) -> (uri::Rsync, Hash, Bytes) {
        (self.uri, self.hash, self.data)
    }
}

impl UpdateElement {
    /// Writes the update element’s XML.
    fn write_xml(
        &self,
        content: &mut xml::encode::Content<impl io::Write>
    ) -> Result<(), io::Error> {
        content.element(PUBLISH.into_unqualified())?
            .attr("uri", &self.uri)?
            .attr("hash", &self.hash)?
            .content(|content| {
                content.base64(self.data.as_ref())
            })?;
        Ok(())
    }
}


//------------ WithdrawElement -----------------------------------------------

/// An RPKI object is to be delete.
///
/// This type defines an RRDP update element as found in RRDP deltas.  It is
/// like a [`PublishElement`] except that it removes an existing object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawElement {
    /// The URI of the object to be deleted.
    uri: uri::Rsync,

    /// The SHA-256 hash of the content of the object to be deleted.
    hash: Hash,
}

impl WithdrawElement {
    /// Creates a new withdraw element from a URI and content hash.
    pub fn new(uri: uri::Rsync, hash: Hash) -> Self {
        WithdrawElement { uri, hash }
    }

    /// Returns the URI of the object to be deleted.
    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
    
    /// Returns the hash over the content of the object to be deleted.
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Converts the withdraw element into its URI and hash.
    pub fn unpack(self) -> (uri::Rsync, Hash) {
        (self.uri, self.hash)
    }
}

impl WithdrawElement {
    /// Writes the withdraw element’s XML.
    fn write_xml(
        &self,
        content: &mut xml::encode::Content<impl io::Write>
    ) -> Result<(), io::Error> {
        content.element(WITHDRAW.into_unqualified())?
            .attr("uri", &self.uri)?
            .attr("hash", &self.hash)?;
        Ok(())
    }
}


//------------ DeltaElement --------------------------------------------------

/// A single element of a RRDP delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeltaElement {
    /// The element publishes a new object.
    Publish(PublishElement),

    /// The element updates an existing object.
    Update(UpdateElement),

    /// The element deletes an existing object.
    Withdraw(WithdrawElement)
}

impl DeltaElement {
    /// Writes the element’s XML.
    fn write_xml(
        &self,
        content: &mut xml::encode::Content<impl io::Write>
    ) -> Result<(), io::Error> {
        match self {
            DeltaElement::Publish(p) => p.write_xml(content),
            DeltaElement::Update(u) => u.write_xml(content),
            DeltaElement::Withdraw(w) => w.write_xml(content)
        }
    }
}

///--- From

impl From<PublishElement> for DeltaElement {
    fn from(src: PublishElement) -> Self {
        DeltaElement::Publish(src)
    }
}

impl From<UpdateElement> for DeltaElement {
    fn from(src: UpdateElement) -> Self {
        DeltaElement::Update(src)
    }
}

impl From<WithdrawElement> for DeltaElement {
    fn from(src: WithdrawElement) -> Self {
        DeltaElement::Withdraw(src)
    }
}


//------------ Snapshot ------------------------------------------------------

/// An RRDP snapshot.
///
/// This type represents an owned RRDP snapshot containing the RRDP session
/// ID, serial number and all published elements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// The RRDP session of this snapshot.
    session_id: Uuid,

    /// The serial number of the update of this snapshot.
    serial: u64,

    /// The objects published through this snapshot.
    elements: Vec<PublishElement>,
}

impl Snapshot {
    /// Creates a new snapshot from its components.
    pub fn new(
        session_id: Uuid,
        serial: u64,
        elements: Vec<PublishElement>,
    ) -> Self {
        Snapshot { session_id, serial, elements }
    }

    /// Returns the session ID of this snapshot.
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Returns the serial number of the update represented by this snapshot.
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// Returns the list of objects published by the snapshot.
    pub fn elements(&self) -> &[PublishElement] {
        &self.elements
    }

    /// Converts the snapshots into its elements.
    pub fn into_elements(self) -> Vec<PublishElement> {
        self.elements
    }
}

/// # XML Support
///
impl Snapshot {
    /// Parses the snapshot from its XML representation.
    pub fn parse<R: io::BufRead>(
        reader: R
    ) -> Result<Self, ProcessError> {
        let mut builder = SnapshotBuilder {
            session_id: None,
            serial: None,
            elements: vec![]
        };

        builder.process(reader)?;
        builder.try_into()
    }

    /// Writes the snapshot’s XML representation.
    pub fn write_xml(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);
        writer.element(SNAPSHOT.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", "1")?
            .attr("session_id", &self.session_id)?
            .attr("serial", &self.serial)?
            .content(|content| {
                for el in &self.elements {
                    el.write_xml(content)?;
                }
                Ok(())
            })?;
        writer.done()
    }
}


//------------ SnapshotBuilder -----------------------------------------------

struct SnapshotBuilder {
    session_id: Option<Uuid>,
    serial: Option<u64>,
    elements: Vec<PublishElement>,
}

impl ProcessSnapshot for SnapshotBuilder {
    type Err = ProcessError;

    fn meta(&mut self, session_id: Uuid, serial: u64) -> Result<(), Self::Err> {
        self.session_id = Some(session_id);
        self.serial = Some(serial);
        Ok(())
    }

    fn publish(&mut self, uri: uri::Rsync, data: &mut ObjectReader) -> Result<(), Self::Err> {
        let mut buf = Vec::new();
        data.read_to_end(&mut buf)?;
        let data = Bytes::from(buf);
        let element = PublishElement { uri, data };
        self.elements.push(element);
        Ok(())
    }
}

impl TryFrom<SnapshotBuilder> for Snapshot {
    type Error = ProcessError;

    fn try_from(builder: SnapshotBuilder) -> Result<Self, Self::Error> {
        let session_id = builder.session_id.ok_or(
            ProcessError::Xml(XmlError::Malformed)
        )?;

        let serial = builder.serial.ok_or(
            ProcessError::Xml(XmlError::Malformed)
        )?;

        Ok(Snapshot { session_id, serial, elements: builder.elements })
    }
}


//------------ ProcessSnapshot -----------------------------------------------

/// A type that can process an RRDP snapshot.
///
/// The trait contains two required methods: [`meta`][Self::meta] is called
/// once at the beginning of the snapshot and gives the processor a chance to
/// check if the session ID and serial number are as expected. Then,
/// [`publish`][Self::publish] is called for each published object.
/// The processor can abort at any time by returning an error.
///
/// The provided method [`process`][Self::process] drives the actual
/// processing and should thus be called when using a type that implements
/// this trait.
pub trait ProcessSnapshot {
    /// The error type returned by the processor.
    type Err: From<ProcessError>;

    /// Processes the snapshot meta data.
    ///
    /// The method is called before any other method and is passed the
    /// session ID and serial number encountered in the outermost tag of the
    /// snapshot file’s XML. If they don’t match the expected values, the
    /// processor should abort processing by returning an error.
    fn meta(
        &mut self,
        session_id: Uuid,
        serial: u64,
    ) -> Result<(), Self::Err>;

    /// Processes a published object.
    ///
    /// The object is identified by the provided rsync URI. The object’s data
    /// is provided via a reader.
    fn publish(
        &mut self,
        uri: uri::Rsync,
        data: &mut ObjectReader,
    ) -> Result<(), Self::Err>;

    /// Processes a snapshot file.
    ///
    /// The file’s content is read from `reader`. The two required methods
    /// are called as appropriate. If the reader fails, parsing fails, or the
    /// methods return an error, processing is aborted and an error is
    /// returned.
    fn process<R: io::BufRead>(
        &mut self,
        reader: R
    ) -> Result<(), Self::Err> {
        let mut reader = Reader::new(reader);
        
        let mut session_id = None;
        let mut serial = None;
        let mut outer = reader.start_with_limit(|element| {
            if element.name() != SNAPSHOT {
                info!("Bad outer: not snapshot, but {:?}", element.name());
                return Err(XmlError::Malformed)
            }
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<u8>()? != 1 {
                        info!("Bad version");
                        return Err(XmlError::Malformed)
                    }
                    Ok(())
                }
                b"session_id" => {
                    session_id = Some(value.ascii_into()?);
                    Ok(())
                }
                b"serial" => {
                    serial = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => {
                    info!("Bad attribute on snapshot.");
                    Err(XmlError::Malformed)
                }
            })
        }, 100_000_000).map_err(Into::into)?;

        match (session_id, serial) {
            (Some(session_id), Some(serial)) => {
                self.meta(session_id, serial)?;
            }
            _ => {
                info!("Missing session or serial");
                return Err(ProcessError::malformed().into())
            }
        }

        loop {
            let mut uri = None;
            let inner = outer.take_opt_element_with_limit(&mut reader, |element| {
                if element.name() != PUBLISH {
                info!("Bad inner: not publish");
                    return Err(ProcessError::malformed())
                }
                element.attributes(|name, value| match name {
                    b"uri" => {
                        uri = Some(value.ascii_into()?);
                        Ok(())
                    }
                    _ => {
                        info!("Bad attribute on publish.");
                        Err(ProcessError::malformed())
                    }
                })
            },100_000_000)?;
            let mut inner = match inner {
                Some(inner) => inner,
                None => break
            };
            let uri = match uri {
                Some(uri) => uri,
                None => return Err(ProcessError::malformed().into())
            };
            ObjectReader::process(&mut inner, &mut reader, |reader| {
                self.publish(uri, reader)
            })?;
        }

        outer.take_end(&mut reader).map_err(Into::into)?;
        reader.end().map_err(Into::into)?;
        Ok(())
    }
}


//------------ Delta ---------------------------------------------------------

/// An RRDP delta.
///
/// This type represents an owned RRDP snapshot containing the RRDP session
/// ID, serial number and all its elements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delta {
    /// The RRDP session ID of the delta.
    session_id: Uuid,

    /// The serial number of this delta.
    serial: u64,

    /// The objects changed by this delta.
    elements: Vec<DeltaElement>
}

/// # Data Access
///
impl Delta {
    /// Creates a new delta from session ID, serial number, and elements.
    pub fn new(
        session_id: Uuid,
        serial: u64,
        elements: Vec<DeltaElement>
    ) -> Self {
        Delta { session_id, serial, elements }
    }

    /// Returns the session ID of the RRDP session this delta is part of.
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Returns the serial number of this delta.
    ///
    /// The serial number is identical to that of the snapshot this delta
    /// updates _to._
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// The list of objects changed by this delta.
    pub fn elements(&self) -> &[DeltaElement] {
        &self.elements
    }

    /// Converts the delta into its elements.
    pub fn into_elements(self) -> Vec<DeltaElement> {
        self.elements
    }
}

/// # Decoding and Encoding XML
///
impl Delta {
    /// Parses the delta from its XML representation.
    pub fn parse<R: io::BufRead>(
        reader: R
    ) -> Result<Self, ProcessError> {
        let mut builder = DeltaBuilder {
            session_id: None,
            serial: None,
            elements: vec![]
        };

        builder.process(reader)?;
        builder.try_into()
    }

    /// Write the delta’s XML representation.
    pub fn write_xml(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);
        writer.element(DELTA.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", "1")?
            .attr("session_id", &self.session_id)?
            .attr("serial", &self.serial)?
            .content(|content| {
                for el in &self.elements {
                    el.write_xml(content)?;
                }
                Ok(())
            })?;
        writer.done()
    }
}


//------------ DeltaBuilder --------------------------------------------------

struct DeltaBuilder {
    session_id: Option<Uuid>,
    serial: Option<u64>,
    elements: Vec<DeltaElement>
}

impl ProcessDelta for DeltaBuilder {
    type Err = ProcessError;

    fn meta(
        &mut self,
        session_id: Uuid,
        serial: u64,
    ) -> Result<(), Self::Err> {
        self.session_id = Some(session_id);
        self.serial = Some(serial);
        Ok(())
    }

    fn publish(
        &mut self,
        uri: uri::Rsync,
        hash_opt: Option<Hash>,
        data: &mut ObjectReader,
    ) -> Result<(), Self::Err> {
        let mut buf = Vec::new();
        data.read_to_end(&mut buf)?;
        let data = Bytes::from(buf);
        match hash_opt {
            Some(hash) => {
                let update = UpdateElement { uri, hash, data};
                self.elements.push(DeltaElement::Update(update));
            },
            None => {
                let publish = PublishElement { uri, data};
                self.elements.push(DeltaElement::Publish(publish));
            }
        }
        Ok(())
    }

    fn withdraw(
        &mut self,
        uri: uri::Rsync,
        hash: Hash,
    ) -> Result<(), Self::Err> {
        let withdraw = WithdrawElement { uri, hash };
        self.elements.push(DeltaElement::Withdraw(withdraw));
        Ok(())
    }
}

impl TryFrom<DeltaBuilder> for Delta {
    type Error = ProcessError;

    fn try_from(builder: DeltaBuilder) -> Result<Self, Self::Error> {
        let session_id = builder.session_id.ok_or(
            ProcessError::Xml(XmlError::Malformed)
        )?;

        let serial = builder.serial.ok_or(
            ProcessError::Xml(XmlError::Malformed)
        )?;

        Ok(Delta { session_id, serial, elements: builder.elements })

    }
}

//------------ ProcessDelta --------------------------------------------------

/// A type that can process an RRDP delta.
///
/// The trait contains three required methods: [`meta`][Self::meta] is called
/// once at the beginning of the snapshot and gives the processor a chance to
/// check if the session ID and serial number are as expected. Then,
/// [`publish`][Self::publish] is called for each newly published or
/// updated object and [`withdraw`][Self::withdraw] is called for each
/// deleted object. The processor can abort at any time by returning an error.
///
/// The provided method [`process`][Self::process] drives the actual
/// processing and should thus be called when using a type that implements
/// this trait.
pub trait ProcessDelta {
    /// The error type returned by the processor.
    type Err: From<ProcessError>;

    /// Processes the delta meta data.
    ///
    /// The method is called before any other method and is passed the
    /// session ID and serial number encountered in the outermost tag of the
    /// delta file’s XML. If they don’t match the expected values, the
    /// processor should abort processing by returning an error.
    fn meta(
        &mut self,
        session_id: Uuid,
        serial: u64,
    ) -> Result<(), Self::Err>;

    /// Processes a published object.
    ///
    /// The object is identified by the rsync URI provided in `uri`. If the
    /// object is updated, the hash over the previous content of the object
    /// is given in `hash`. If the object is newly published, `hash` will be
    /// `None`. The (new) content of the object is provided via the reader in
    /// `data`.
    fn publish(
        &mut self,
        uri: uri::Rsync,
        hash: Option<Hash>,
        data: &mut ObjectReader,
    ) -> Result<(), Self::Err>;

    /// Processes a withdrawn object.
    ///
    /// The object is identified by the rsync URI provided in `uri`. The hash
    /// over the expected content of the object to be deleted is given in
    /// `hash`.
    fn withdraw(
        &mut self,
        uri: uri::Rsync,
        hash: Hash,
    ) -> Result<(), Self::Err>;


    /// Processes a delta file.
    ///
    /// The file’s content is taken from `reader`. The content is parsed and
    /// the three required methods are called as required.
    ///
    /// If the reader fails, parsing fails, or the methods return an error,
    /// processing is aborted and an error is returned.
    fn process<R: io::BufRead>(
        &mut self,
        reader: R
    ) -> Result<(), Self::Err> {
        let mut reader = Reader::new(reader);
        
        let mut session_id = None;
        let mut serial = None;
        let mut outer = reader.start(|element| {
            if element.name() != DELTA {
                return Err(ProcessError::malformed())
            }
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<u8>()? != 1 {
                        return Err(ProcessError::malformed())
                    }
                    Ok(())
                }
                b"session_id" => {
                    session_id = Some(value.ascii_into()?);
                    Ok(())
                }
                b"serial" => {
                    serial = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => Err(ProcessError::malformed())
            })
        })?;

        match (session_id, serial) {
            (Some(session_id), Some(serial)) => {
                self.meta(session_id, serial)?;
            }
            _ => return Err(ProcessError::malformed().into())
        }

        loop {
            let mut action = None;
            let mut uri = None;
            let mut hash = None;
            let inner = outer.take_opt_element(&mut reader, |element| {
                match element.name() {
                    PUBLISH => action = Some(Action::Publish),
                    WITHDRAW => action = Some(Action::Withdraw),
                    _ => return Err(ProcessError::malformed()),
                };
                element.attributes(|name, value| match name {
                    b"uri" => {
                        uri = Some(value.ascii_into()?);
                        Ok(())
                    }
                    b"hash" => {
                        hash = Some(value.ascii_into()?);
                        Ok(())
                    }
                    _ => Err(ProcessError::malformed())
                })
            })?;
            let mut inner = match inner {
                Some(inner) => inner,
                None => break
            };
            let uri = match uri {
                Some(uri) => uri,
                None => return Err(ProcessError::malformed().into())
            };
            match action.unwrap() { // Or we'd have exited already.
                Action::Publish => {
                    ObjectReader::process(
                        &mut inner, &mut reader,
                        |reader| self.publish(uri, hash, reader)
                    )?;
                }
                Action::Withdraw => {
                    let hash = match hash {
                        Some(hash) => hash,
                        None => return Err(ProcessError::malformed().into())
                    };
                    self.withdraw(uri, hash)?;
                    inner.take_end(&mut reader).map_err(Into::into)?;
                }
            }
        }
        outer.take_end(&mut reader).map_err(Into::into)?;
        reader.end().map_err(Into::into)?;
        Ok(())
    }

}


//------------ SnapshotInfo --------------------------------------------------

/// The URI and HASH of the current snapshot for a [`NotificationFile`].
pub type SnapshotInfo = UriAndHash;


//------------ DeltaInfo -----------------------------------------------------

/// The serial, URI and HASH of a delta in a [`NotificationFile`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeltaInfo {
    serial: u64,
    uri_and_hash: UriAndHash
}

impl DeltaInfo {
    /// Creates a new info from its components.
    pub fn new(serial: u64, uri: uri::Https, hash: Hash) -> Self {
        DeltaInfo {
            serial,
            uri_and_hash: UriAndHash::new(uri, hash)
        }
    }

    /// Returns the serial number of this delta.
    pub fn serial(&self) -> u64 {
        self.serial
    }
}

impl Deref for DeltaInfo {
    type Target = UriAndHash;

    fn deref(&self) -> &Self::Target {
        &self.uri_and_hash
    }
}

//------------ UriAndHash ----------------------------------------------------

/// The URI of an RRDP file and a SHA-256 hash over its content.
///
/// In order to detect accidental or malicious modifications of the data
/// all references to RRDP files are given with a SHA-256 hash over the
/// expected content of that file, allowing a client to verify they got the
/// right file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UriAndHash {
    /// The URI of the RRDP file.
    uri: uri::Https,

    /// The expected SHA-256 hash over the file’s content.
    hash: Hash,
}

impl UriAndHash {
    /// Creates a new URI-and-hash pair.
    pub fn new(uri: uri::Https, hash: Hash) -> Self {
        UriAndHash { uri, hash }
    }

    /// Returns a reference to the URI.
    pub fn uri(&self) -> &uri::Https {
        &self.uri
    }

    /// Returns the expected SHA-256 hash.
    pub fn hash(&self) -> Hash {
        self.hash
    }

    /// Converts the pair into just the URI.
    pub fn into_uri(self) -> uri::Https {
        self.uri
    }

    /// Converts `self` into a pair of URI and hash.
    pub fn into_pair(self) -> (uri::Https, Hash) {
        (self.uri, self.hash)
    }
}


//------------ Hash ----------------------------------------------------------

/// A hash over RRDP data.
///
/// This hash is used both for verifying the correctness of RRDP files as well
/// as update or deletion of the right objects.
///
/// RRDP exclusively uses SHA-256 and provides no means of choosing a different
/// algorithm. Consequently, this type is a wrapper around a 32 byte array
/// holding SHA-256 output.
#[derive(Clone, Copy, Eq, hash::Hash, PartialEq)]
#[repr(transparent)] // ensure that size_of::<Hash>() == 32.
pub struct Hash([u8; 32]);

impl Hash {
    /// Returns a reference to the octets as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Returns a new Hash from the provided data
    pub fn from_data(data: &[u8]) -> Self {
        let digest = digest::digest(&digest::SHA256, data);
        Self::try_from(digest.as_ref()).unwrap()
    }

    /// Returns whether this hash matches the provided data
    pub fn matches(&self, data: &[u8]) -> bool {
        let data_hash = Self::from_data(data);
        *self == data_hash
    }
}


//--- From, TryFrom, and FromStr

impl From<[u8;32]> for Hash {
    fn from(value: [u8;32]) -> Hash {
        Hash(value)
    }
}

impl From<Hash> for [u8; 32] {
    fn from(src: Hash) -> Self {
        src.0
    }
}

impl<'a> TryFrom<&'a [u8]> for Hash {
    type Error = std::array::TryFromSliceError;

    fn try_from(src: &'a [u8]) -> Result<Self, Self::Error> {
        TryFrom::try_from(src).map(Hash)
    }
}

impl TryFrom<digest::Digest> for Hash {
    type Error = AlgorithmError;

    fn try_from(digest: digest::Digest) -> Result<Self, Self::Error> {
        // XXX This doesn’t properly check the algorithm.
        TryFrom::try_from(
            digest.as_ref()
        ).map(Hash).map_err(|_| AlgorithmError(()))
    }
}

impl str::FromStr for Hash {
    type Err = ParseHashError;

    /// Parses a string into a hash.
    ///
    /// The string must consist of exactly 64 hexadecimal digits and nothing
    /// else.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(ParseHashError::BAD_LENGTH)
        }
        let mut res = [0u8; 32];
        let mut s = s.chars();
        for octet in &mut res {
            let first = s.next().ok_or(
                ParseHashError::BAD_LENGTH
            )?.to_digit(16).ok_or(
                ParseHashError::BAD_CHARS
            )?;
            let second = s.next().ok_or(
                ParseHashError::BAD_LENGTH
            )?.to_digit(16).ok_or(
                ParseHashError::BAD_CHARS
            )?;
            *octet = (first << 4 | second) as u8;
        }
        Ok(Hash(res))
    }
}


//--- AsRef

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}


//--- PartialEq
//
// PartialEq<Self> and Eq are derived.

impl PartialEq<digest::Digest> for Hash {
    fn eq(&self, other: &digest::Digest) -> bool {
        // XXX This doesn’t properly check the algorithm.
        self.0.as_ref() == other.as_ref()
    }
}


//--- Display and Debug

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.as_slice() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Hash({})", self)
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        self.to_string().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let hex_str = String::deserialize(deserializer)?;
        Hash::from_str(&hex_str).map_err(serde::de::Error::custom)
    }
}


//------------ Action --------------------------------------------------------

/// The choice of actions in a delta file.
enum Action {
    /// An object is to be inserted or updated.
    ///
    /// The object is to be updated, if a hash is given. Otherwise it is
    /// to be inserted.
    Publish,

    /// An object is to be deleted.
    Withdraw,
}


//------------ ObjectReader --------------------------------------------------

/// A reader providing the content of an object.
///
/// The content is included in base64 encoding in the RRDP’s XML. This reader
/// provides access to the decoded data via the standard `Read` trait.
pub struct ObjectReader<'a>(
    /// The base64 encoded data.
    base64::XmlDecoderReader<'a>
);

impl<'a> ObjectReader<'a> {
    /// Processes an element with optional XML PCDATA as object content.
    ///
    /// An object reader is created and passed to the closure `op` for
    /// actual processing.
    ///
    /// This method expects the next XML event to either be text or the end
    /// of an element. It will process both.
    fn process<R, T, E, F> (
        content: &mut Content,
        reader: &mut Reader<R>,
        op: F
    ) -> Result<T, E>
    where
        R: io::BufRead,
        E: From<ProcessError>,
        F: FnOnce(&mut ObjectReader) -> Result<T, E>
    {
        // We need this extra error type to fulfil the trait bounds of the
        // error type of the closure passed to take_opt_final_text. Or, as
        // the German saying goes: „Von hinten durch die Brust ins Auge.“
        enum Error<E> {
            Xml(XmlError),
            User(E),
        }

        impl<E> From<XmlError> for Error<E> {
            fn from(err: XmlError) -> Self {
                Error::Xml(err)
            }
        }

        content.take_opt_final_text(reader, |text| {
            let b64 = match text.as_ref() {
                Some(text) => text.to_ascii()?,
                None => Default::default(),
            };
            op(
                &mut ObjectReader(base64::Xml.decode_reader(b64.as_ref()))
            ).map_err(Error::User)
        }).map_err(|err| match err {
            Error::Xml(err) => ProcessError::Xml(err).into(),
            Error::User(err) => err
        })
    }
}

impl<'a> io::Read for ObjectReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.0.read(buf)
    }
}


//------------ XML Names -----------------------------------------------------

const NS: &[u8] = b"http://www.ripe.net/rpki/rrdp";
const NOTIFICATION: Name = Name::qualified(NS, b"notification");
const SNAPSHOT: Name = Name::qualified(NS, b"snapshot");
const DELTA: Name = Name::qualified(NS, b"delta");
const PUBLISH: Name = Name::qualified(NS, b"publish");
const WITHDRAW: Name = Name::qualified(NS, b"withdraw");


//============ Errors ========================================================

//------------ AlgorithmError ------------------------------------------------

/// A digest was of the wrong algorithm.
#[derive(Clone, Copy, Debug)]
pub struct AlgorithmError(());

impl fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("algorithm mismatch")
    }
}

impl error::Error for AlgorithmError { }


//------------ ParseHashError ------------------------------------------------

/// An error happened while parsing a hash.
#[derive(Clone, Copy, Debug)]
pub struct ParseHashError(&'static str);

impl ParseHashError {
    /// The error when the hash value was of the wrong length.
    const BAD_LENGTH: Self = ParseHashError("invalid length");

    /// The error when the hash value contained illegal characters.
    const BAD_CHARS: Self = ParseHashError("invalid characters");
}

impl fmt::Display for ParseHashError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl error::Error for ParseHashError { }


//------------ DeltaListError ------------------------------------------------

/// An error happened when parsing the delta list of a notification file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeltaListError {
    /// The delta list was larger than a given limit.
    Oversized,
}

impl fmt::Display for DeltaListError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Oversized => write!(f, "excessively large delta list")
        }
    }
}

impl error::Error for DeltaListError { }


//------------ ProcessError --------------------------------------------------

/// An error occurred while processing RRDP data.
#[derive(Debug)]
pub enum ProcessError {
    /// An IO error happened.
    Io(io::Error),

    /// The XML was not correctly formed.
    Xml(XmlError),
}

impl ProcessError {
    /// Creates an error when the XML was malformed.
    fn malformed() -> Self {
        ProcessError::Xml(XmlError::Malformed)
    }
}

impl From<io::Error> for ProcessError {
    fn from(err: io::Error) -> Self {
        ProcessError::Io(err)
    }
}

impl From<XmlError> for ProcessError {
    fn from(err: XmlError) -> Self {
        ProcessError::Xml(err)
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProcessError::Io(ref inner) => inner.fmt(f),
            ProcessError::Xml(ref inner) => inner.fmt(f),
        }
    }
}

impl error::Error for ProcessError { }


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use std::str::from_utf8_unchecked;
    use std::str::FromStr;

    use super::*;

    pub struct Test;

    impl ProcessSnapshot for Test {
        type Err = ProcessError;

        fn meta(
            &mut self,
            _session_id: Uuid,
            _serial: u64,
        ) -> Result<(), Self::Err> {
            Ok(())
        }

        fn publish(
            &mut self,
            _uri: uri::Rsync,
            _data: &mut ObjectReader,
        ) -> Result<(), Self::Err> {
            Ok(())
        }
    }

    impl ProcessDelta for Test {
        type Err = ProcessError;

        fn meta(
            &mut self,
            _session_id: Uuid,
            _serial: u64,
        ) -> Result<(), Self::Err> {
            Ok(())
        }

        fn publish(
            &mut self,
            _uri: uri::Rsync,
            _hash: Option<Hash>,
            _data: &mut ObjectReader,
        ) -> Result<(), Self::Err> {
            Ok(())
        }

        fn withdraw(
            &mut self,
            _uri: uri::Rsync,
            _hash: Hash,
        ) -> Result<(), Self::Err> {
            Ok(())
        }
    }

    #[test]
    fn ripe_notification() {
        NotificationFile::parse(
            include_bytes!(
                "../test-data/rrdp/ripe-notification.xml"
            ).as_ref()
        ).unwrap();
    }

    #[test]
    fn lolz_notification() {
        assert!(
            NotificationFile::parse(
                include_bytes!(
                    "../test-data/rrdp/lolz-notification.xml"
                ).as_ref()
            ).is_err()
        );
    }

    #[test]
    fn gaps_notification() {
        let mut notification_without_gaps =  NotificationFile::parse(
            include_bytes!("../test-data/rrdp/ripe-notification.xml").as_ref()
        ).unwrap();
        assert!(notification_without_gaps.sort_and_verify_deltas(None));

        let mut notification_with_gaps =  NotificationFile::parse(
            include_bytes!(
                "../test-data/rrdp/ripe-notification-with-gaps.xml"
            ).as_ref()
        ).unwrap();
        assert!(!notification_with_gaps.sort_and_verify_deltas(None));
    }

    #[test]
    fn limit_notification_deltas() {
        let mut notification_without_gaps =  NotificationFile::parse(
            include_bytes!("../test-data/rrdp/ripe-notification.xml").as_ref()
        ).unwrap();
        assert!(notification_without_gaps.sort_and_verify_deltas(Some(2)));

        assert_eq!(2, notification_without_gaps.deltas().len());
        assert_eq!(
            notification_without_gaps.deltas().first().unwrap().serial(),
            notification_without_gaps.serial() - 1
        );
        assert_eq!(
            notification_without_gaps.deltas().last().unwrap().serial(),
            notification_without_gaps.serial()
        );
    }

    #[test]
    fn unsorted_notification() {
        let mut from_sorted = NotificationFile::parse(
            include_bytes!("../test-data/rrdp/ripe-notification.xml").as_ref()
        ).unwrap();

        let mut from_unsorted = NotificationFile::parse(
            include_bytes!(
                "../test-data/rrdp/ripe-notification-unsorted.xml"
            ).as_ref()
        ).unwrap();
        
        assert_ne!(from_sorted, from_unsorted);

        from_unsorted.reverse_sort_deltas();
        assert_eq!(from_sorted, from_unsorted);
        
        from_unsorted.sort_deltas();
        assert_ne!(from_sorted, from_unsorted);
                
        from_sorted.sort_deltas();
        assert_eq!(from_sorted, from_unsorted);
    }

    #[test]
    fn notification_parse_limited() {
        let bytes = include_bytes!(
            "../test-data/rrdp/ripe-notification.xml"
        ).as_ref();
        let full = NotificationFile::parse(bytes).unwrap();
        assert!(!full.deltas().is_empty());
        
        let limited = NotificationFile::parse_limited(
            bytes, full.deltas().len()
        ).unwrap();
        assert_eq!(limited.deltas().len(), full.deltas().len());
        assert!(limited.delta_status().is_ok());

        let limited = NotificationFile::parse_limited(
            bytes, full.deltas().len() - 1
        ).unwrap();
        assert_eq!(limited.deltas().len(), 0);
        assert!(limited.delta_status().is_err());
    }

    #[test]
    fn ripe_snapshot() {
        <Test as ProcessSnapshot>::process(
            &mut Test,
            include_bytes!("../test-data/rrdp/ripe-snapshot.xml").as_ref()
        ).unwrap();
    }

    #[test]
    fn ripe_delta() {
        <Test as ProcessDelta>::process(
            &mut Test,
            include_bytes!("../test-data/rrdp/ripe-delta.xml").as_ref()
        ).unwrap();
    }

    #[test]
    fn hash_to_hash() {
        use std::str::FromStr;

        let string = "this is a test";
        let sha256 =
            "2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c";
        let hash = Hash::from_str(sha256).unwrap();
        let hash_from_data = Hash::from_data(string.as_bytes());
        assert_eq!(hash, hash_from_data);
        assert!(hash.matches(string.as_bytes()));
    }

    #[test]
    fn notification_from_to_xml() {
        let notification = NotificationFile::parse(
            include_bytes!("../test-data/rrdp/ripe-notification.xml").as_ref()
        ).unwrap();

        let mut vec = vec![];
        notification.write_xml(&mut vec).unwrap();

        let xml = unsafe {
            from_utf8_unchecked(vec.as_ref())
        };

        let notification_parsed = NotificationFile::parse(xml.as_bytes()).unwrap();

        assert_eq!(notification, notification_parsed);
    }

    #[test]
    fn snapshot_from_to_xml() {
        let data = include_bytes!("../test-data/rrdp/ripe-snapshot.xml");
        let snapshot = Snapshot::parse(data.as_ref()).unwrap();

        let mut vec = vec![];
        snapshot.write_xml(&mut vec).unwrap();

        let xml = unsafe {
            from_utf8_unchecked(vec.as_ref())
        };

        let snapshot_parsed = Snapshot::parse(xml.as_bytes()).unwrap();

        assert_eq!(snapshot, snapshot_parsed);
    }

    #[test]
    fn delta_from_to_xml() {
        let data = include_bytes!("../test-data/rrdp/ripe-delta.xml");
        let delta = Delta::parse(data.as_ref()).unwrap();

        let mut vec = vec![];
        delta.write_xml(&mut vec).unwrap();

        let xml = unsafe {
            from_utf8_unchecked(vec.as_ref())
        };

        let delta_parsed = Delta::parse(xml.as_bytes()).unwrap();

        assert_eq!(delta, delta_parsed);
    }

    #[test]
    fn snapshot_content() {
        const CONTENT: &[u8] = b"foo bar\n";
        let snapshot = br#"
            <snapshot version="1"
                session_id="a2d845c4-5b91-4015-a2b7-988c03ce232a"
                serial="1742"
                xmlns="http://www.ripe.net/rpki/rrdp"
            >
                <publish
                    uri="rsync://example.com/some/path"
                >
                    Zm9vIGJhcgo=
                </publish>
                <publish
                    uri="rsync://example.com/some/other"
                />
                <publish
                    uri="rsync://example.com/some/third"
                ></publish>
            </snapshot>
        "#;

        let snapshot = Snapshot::parse(&mut snapshot.as_ref()).unwrap();
        assert_eq!(snapshot.elements.len(), 3);
        assert_eq!(
            snapshot.elements[0],
            PublishElement::new(
                uri::Rsync::from_str("rsync://example.com/some/path").unwrap(),
                Bytes::copy_from_slice(CONTENT)
            )
        );
        assert_eq!(
            snapshot.elements[1],
            PublishElement::new(
                uri::Rsync::from_str("rsync://example.com/some/other").unwrap(),
                Bytes::new()
            )
        );
        assert_eq!(
            snapshot.elements[2],
            PublishElement::new(
                uri::Rsync::from_str("rsync://example.com/some/third").unwrap(),
                Bytes::new()
            )
        );
    }

    #[test]
    fn has_matching_origins() {
        fn check<const N: usize>(
            snapshot: &str, deltas: [&str; N]
        ) -> bool {
            let hash = Hash::from_data(b"12");
            NotificationFile::new(
                Uuid::nil(), 0,
                SnapshotInfo::new(
                    uri::Https::from_str(snapshot).unwrap(), hash
                ),
                deltas.iter().map(|uri| {
                    DeltaInfo::new(
                        0, uri::Https::from_str(uri).unwrap(), hash
                    )
                }).collect()
            ).has_matching_origins(
                &uri::Https::from_str("https://foo.bar/n/o").unwrap()
            )
        }

        assert!(check(
            "https://foo.bar/1/2/3",
            ["https://foo.bar/", "https://foo.bar/4", "https://foo.bar/7/8"],
        ));

        assert!(!check(
            "https://foo.bar/1/2/3",
            ["https://foo.bar/", "https://foo.local/4"],
        ));
    }
}
