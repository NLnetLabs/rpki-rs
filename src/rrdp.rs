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
//!

#![cfg(feature = "rrdp")]

use std::{error, fmt, hash, io, str};
use std::io::Read;
use std::convert::TryFrom;
use std::convert::TryInto;
use bytes::Bytes;
use log::info;
use ring::digest;
use uuid::Uuid;
use crate::uri;
use crate::xml::decode::{Content, Error as XmlError, Reader, Name};


//------------ RrdpState -----------------------------------------------------

/// The complete RRDP state, including the last snapshot and a vec
/// of deltas (which may be an empty).
pub struct RrdpState {
    snapshot: Snapshot
}

//------------ NotificationFile ----------------------------------------------

/// The RRDP Update Notification File.
///
/// This type represents the decoded content of the RRDP Update Notification
/// File. It can be read from a reader via the [`parse`][Self::parse]
/// function. All elements are accessible as attributes.
pub struct NotificationFile {
    /// The identifier of the current session of the server.
    ///
    /// Delta updates can only be used if the session ID of the last processed
    /// update matches this value.
    pub session_id: Uuid,

    /// The serial number of the most recent update provided by the server.
    ///
    /// Serial numbers increase by one between each update.
    pub serial: u64,

    /// The URI and hash value of the most recent snapshot.
    ///
    /// The snapshot contains a complete set of all data published via the
    /// repository. It can be processed using the [`ProcessSnapshot`] trait.
    pub snapshot: UriAndHash,

    /// The list of available delta updates.
    ///
    /// The first element of the vec’s items is the serial number of the
    /// delta and the second element is the URI of the location of the delta
    /// and its hash. Deltas can be processed using the [`ProcessDelta`]
    /// trait.
    ///
    /// Note that after parsing, the list will be in the order as received
    /// from the server. That is, it may not be ordered by serial numbers.
    pub deltas: Vec<(u64, UriAndHash)>,
}

impl NotificationFile {
    /// Parses the notification file from its XML representation.
    pub fn parse<R: io::BufRead>(reader: R) -> Result<Self, XmlError> {
        let mut reader = Reader::new(reader);

        let mut session_id = None;
        let mut serial = None;
        let mut outer = reader.start(|element| {
            if element.name() != NOTIFICATION {
                return Err(XmlError::Malformed)
            }

            element.attributes(|name, value| match name {
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
            })
        })?;

        let mut snapshot = None;
        let mut deltas = Vec::new();
        while let Some(mut content) = outer.take_opt_element(&mut reader,
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
                    match (serial, uri, hash) {
                        (Some(serial), Some(uri), Some(hash)) => {
                            deltas.push((serial, UriAndHash::new(uri, hash)));
                            Ok(())
                        }
                        _ => Err(XmlError::Malformed)
                    }
                }
                _ => Err(XmlError::Malformed)
            }
        })? {
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
}

//------------ PublishElement ------------------------------------------------

/// This type defines an RRDP publish element as found in RRDP Snapshots and
/// Deltas. See [`UpdateElement`] for the related element that replaces a
/// previous element for the same uri.
#[derive(Clone, Debug)]
pub struct PublishElement {
    uri: uri::Rsync,
    data: Bytes,
}



//------------ Snapshot ------------------------------------------------------

/// This type represents an owned RRDP Snapshot containing the RRDP session id,
/// serial and all published elements.
#[derive(Clone, Debug)]
pub struct Snapshot {
    session_id: Uuid,
    serial: u64,
    elements: Vec<PublishElement>,
}

impl Snapshot {
    /// Parse 
    pub fn parse<R: io::BufRead>(
        reader: R
    ) -> Result<Self, RrdpProcessError> {
        let mut builder = SnapshotBuilder {
            session_id: None,
            serial: None,
            elements: vec![]
        };

        builder.process(reader)?;
        builder.try_into()
    }
}

//------------ SnapshotBuilder -----------------------------------------------

struct SnapshotBuilder {
    session_id: Option<Uuid>,
    serial: Option<u64>,
    elements: Vec<PublishElement>,
}

impl ProcessSnapshot for SnapshotBuilder {
    type Err = RrdpProcessError;

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
    type Error = RrdpProcessError;

    fn try_from(builder: SnapshotBuilder) -> Result<Self, Self::Error> {
        let session_id = builder.session_id.ok_or_else(||
            RrdpProcessError::Xml(XmlError::Malformed)
        )?;

        let serial = builder.serial.ok_or_else(||
            RrdpProcessError::Xml(XmlError::Malformed)
        )?;

        Ok(Snapshot { session_id, serial, elements: builder.elements })
    }
}

//------------ RrdpProcessError ----------------------------------------------

#[derive(Debug)]
pub enum RrdpProcessError {
    Xml(XmlError),
    ProcessError(ProcessError),
}

impl From<XmlError> for RrdpProcessError {
    fn from(err: XmlError) -> Self {
        RrdpProcessError::Xml(err)
    }
}

impl From<ProcessError> for RrdpProcessError {
    fn from(err: ProcessError) -> Self {
        RrdpProcessError::ProcessError(err)
    }
}

impl From<io::Error> for RrdpProcessError {
    fn from(err: io::Error) -> Self {
        RrdpProcessError::ProcessError(ProcessError::from(err))
    }
}

impl fmt::Display for RrdpProcessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RrdpProcessError::Xml(ref err) => err.fmt(f),
            RrdpProcessError::ProcessError(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for RrdpProcessError { }


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
        let mut outer = reader.start(|element| {
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
        }).map_err(Into::into)?;

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
            let inner = outer.take_opt_element(&mut reader, |element| {
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
            })?;
            let mut inner = match inner {
                Some(inner) => inner,
                None => break
            };
            let uri = match uri {
                Some(uri) => uri,
                None => return Err(ProcessError::malformed().into())
            };
            ObjectReader::process_text(&mut inner, &mut reader, |reader| {
                self.publish(uri, reader)
            })?;
            inner.take_end(&mut reader).map_err(Into::into)?;
        }

        outer.take_end(&mut reader).map_err(Into::into)?;
        reader.end().map_err(Into::into)?;
        Ok(())
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
                    ObjectReader::process_text(
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
                }
            }
            inner.take_end(&mut reader).map_err(Into::into)?;
        }
        outer.take_end(&mut reader).map_err(Into::into)?;
        reader.end().map_err(Into::into)?;
        Ok(())
    }

}


//------------ UriAndHash ----------------------------------------------------

/// The URI of an RRDP file and a SHA-256 hash over its content.
///
/// In order to detect accidental or malicious modifications of the data
/// all references to RRDP files are given with a SHA-256 hash over the
/// expected content of that file, allowing a client to verify they got the
/// right file.
#[derive(Clone, Debug)]
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
/// RRDP exclusively uses SHA-256 and provides no means of chosing a different
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
    base64::read::DecoderReader<'a, &'a [u8]>
);

impl<'a> ObjectReader<'a> {
    /// Processes XML PCDATA as object content.
    ///
    /// An object reader is created and passed to the closure `op` for
    /// actual processing.
    fn process_text<R, T, E, F> (
        content: &mut Content,
        reader: &mut Reader<R>,
        op: F
    ) -> Result<T, E>
    where
        R: io::BufRead,
        E: From<ProcessError>,
        F: FnOnce(&mut ObjectReader) -> Result<T, E>
    {
        // XXX This could probably do with a bit of optimization.
        let data_b64: Vec<_> = content.take_text(reader,  |text| {
            // The text is supposed to be xsd:base64Binary which only allows
            // the base64 characters plus whitespace.
            Ok(text.to_ascii()?.as_bytes().iter().filter_map(|b| {
                    if b.is_ascii_whitespace() { None }
                    else { Some(*b) }
            }).collect())
        })?;
        let mut data_b64 = data_b64.as_slice();
        op(
            &mut ObjectReader(base64::read::DecoderReader::new(
                &mut data_b64, base64::STANDARD
            ))
        )
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
            ProcessError::Xml(ref inner) => inner.fmt(f)
        }
    }
}

impl error::Error for ProcessError { }


//============ Tests =========================================================

#[cfg(test)]
mod test {
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
            include_bytes!("../test-data/ripe-notification.xml").as_ref()
        ).unwrap();
    }

    #[test]
    fn lolz_notification() {
        assert!(
            NotificationFile::parse(
                include_bytes!("../test-data/lolz-notification.xml").as_ref()
            ).is_err()
        );
    }

    #[test]
    fn ripe_snapshot() {
        <Test as ProcessSnapshot>::process(
            &mut Test,
            include_bytes!("../test-data/ripe-snapshot.xml").as_ref()
        ).unwrap();
    }

    #[test]
    fn ripe_delta() {
        <Test as ProcessDelta>::process(
            &mut Test,
            include_bytes!("../test-data/ripe-delta.xml").as_ref()
        ).unwrap();
    }

    #[test]
    fn hash_to_hash() {
        use std::str::FromStr;

        let string = "this is a test";
        let sha256 = "2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c";
        let hash = Hash::from_str(sha256).unwrap();
        let hash_from_data = Hash::from_data(string.as_bytes());
        assert_eq!(hash, hash_from_data);
        assert!(hash.matches(string.as_bytes()));
    }

    #[test]
    fn snapshot_from_to_xml() {
        let data = include_bytes!("../test-data/ripe-snapshot.xml");
        let _snapshot = Snapshot::parse(data.as_ref()).unwrap();
    }
}
