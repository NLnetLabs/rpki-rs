
use std::{error, fmt, io, str};
use std::borrow::Cow;
use bytes::Bytes;
use quick_xml::events::{BytesStart, Event};
use quick_xml::events::attributes::AttrError;
use quick_xml::name::Namespace;
use crate::util::base64;


//------------ Reader --------------------------------------------------------

/// An XML reader.
///
/// This struct holds all state necessary for parsing an XML document.
pub struct Reader<R: io::BufRead> {
    reader: quick_xml::NsReader<BufReadCounter<R>>,
    buf: Vec<u8>,
}

impl<R: io::BufRead> Reader<R> {
    /// Creates a new reader from an underlying reader.
    pub fn new(reader: R) -> Self {
        let reader = BufReadCounter::new(reader);
        let mut reader = quick_xml::NsReader::from_reader(reader);
        reader.trim_text(true);
        Reader {
            reader,
            buf: Vec::new(),
        }
    }

    pub fn reset_and_limit(&mut self, limit: u64) {
        self.reader.get_mut().reset();
        self.reader.get_mut().limit(limit);
    }

    /// Parse the start of the document.
    ///
    /// This is like `Content::take_element` except that it also happily
    /// skips over XML and doctype declarations.
    pub fn start<F, E>(&mut self, op: F) -> Result<Content, E>
    where F: FnOnce(Element) -> Result<(), E>, E: From<Error> {
        loop {
            self.buf.clear();
            let (ns, event) = self.reader.read_resolved_event_into(
                &mut self.buf,
            ).map_err(Into::into)?;
            let ns = ns.try_into().map_err(Into::into)?;
            match event {
                Event::Start(start) => {
                    op(Element::new(start, ns))?;
                    return Ok(
                        Content { empty: false }
                    )
                }
                Event::Empty(start) => {
                    op(Element::new(start, ns))?;
                    return Ok(
                        Content { empty: true }
                    )
                }
                Event::Comment(_) | Event::Decl(_) | Event::DocType(_) => { }
                _ => return Err(Error::Malformed.into())
            }
        }
    }

    pub fn start_with_limit<F, E>(
        &mut self, op: F, limit: u64) -> Result<Content, E>
    where F: FnOnce(Element) -> Result<(), E>, E: From<Error> {
        self.reset_and_limit(limit);
        self.start(op)
    }

    /// Parse the end of the document.
    ///
    /// This checks that the next non-comment event to be the end of file.
    pub fn end(&mut self) -> Result<(), Error> {
        loop {
            self.buf.clear();
            match self.reader.read_event_into(&mut self.buf)? {
                Event::Eof => return Ok(()),
                Event::Comment(_) => { }
                _ => return Err(Error::Malformed)
            }
        }
    }
}


//------------ Element -------------------------------------------------------

/// The start of an element.
pub struct Element<'b, 'n> {
    start: BytesStart<'b>,
    ns: Option<Namespace<'n>>,
}

impl<'b, 'n> Element<'b, 'n> {
    /// Creates a new value from the underlying components.
    fn new(start: BytesStart<'b>, ns: Option<Namespace<'n>>) -> Self {
        Element { start, ns, }
    }

    /// Returns the name of the element.
    pub fn name(&self) -> Name<'_, '_> {
        Name::new(
            self.ns.map(|ns| ns.0),
            self.start.local_name().into_inner()
        )
    }

    /// Processes the attributes of the element.
    ///
    /// We don’t support qualified attributes. Any namespace prefixes in
    /// attribute names will lead to an error.
    pub fn attributes<F, E>(&self, mut op: F) -> Result<(), E>
    where
        F: FnMut(&[u8], AttrValue) -> Result<(), E>,
        E: From<Error>
    {
        for attr in self.start.attributes() {
            let attr = attr.map_err(Into::into)?;
            if attr.key.as_namespace_binding().is_some() {
                continue
            }
            if let Some(prefix) = attr.key.prefix() {
                return Err(E::from(
                    Error::Xml(quick_xml::Error::UnknownPrefix(
                        prefix.as_ref().into()
                    ))
                ))
            }
            op(attr.key.local_name().as_ref(), AttrValue(attr))?;
        }
        Ok(())
    }
}


//------------ Content -------------------------------------------------------

pub struct Content {
    empty: bool
}

impl Content {
    pub fn take_element<R, F, E>(
        &self,
        reader: &mut Reader<R>,
        op: F
    ) -> Result<Content, E>
    where R: io::BufRead, F: FnOnce(Element) -> Result<(), E>, E: From<Error> {
        if self.empty {
            return Err(Error::Malformed.into())
        }

        loop {
            reader.buf.clear();
            let (ns, event) = reader.reader.read_resolved_event_into(
                &mut reader.buf
            ).map_err(Into::into)?;
            let ns = ns.try_into().map_err(Into::into)?;
            match event {
                Event::Start(start) => {
                    op(Element::new(start, ns))?;
                    return Ok(
                        Content { empty: false }
                    )
                }
                Event::Empty(start) => {
                    op(Element::new(start, ns))?;
                    return Ok(
                        Content { empty: false }
                    )
                }
                Event::Comment(_) => { }
                _ => return Err(Error::Malformed.into())
            }
        }
    }

    pub fn take_element_with_limit<R, F, E>(
        &self,
        reader: &mut Reader<R>,
        op: F,
        limit: u64
    ) -> Result<Content, E>
    where R: io::BufRead, F: FnOnce(Element) -> Result<(), E>, E: From<Error> {
        reader.reset_and_limit(limit);

        self.take_element(reader, op)
    }

    pub fn take_opt_element<R, F, E>(
        &mut self,
        reader: &mut Reader<R>,
        op: F
    ) -> Result<Option<Content>, E>
    where
        R: io::BufRead,
        F: FnOnce(Element) -> Result<(), E>,
        E: From<Error>
    {
        if self.empty {
            return Ok(None)
        }

        loop {
            reader.buf.clear();
            let (ns, event) = reader.reader.read_resolved_event_into(
                &mut reader.buf
            ).map_err(Into::into)?;
            let ns = ns.try_into().map_err(Into::into)?;
            match event {
                Event::Start(start) => {
                    op(Element::new(start, ns))?;
                    return Ok(Some(
                        Content { empty: false }
                    ))
                }
                Event::Empty(start) => {
                    op(Element::new(start, ns))?;
                    return Ok(Some(
                        Content { empty: true }
                    ))
                }
                Event::End(_) => {
                    self.empty = true;
                    return Ok(None)
                }
                Event::Comment(_) => { }
                _ => return Err(Error::Malformed.into())
            }
        }
    }

    pub fn take_opt_element_with_limit<R, F, E>(
        &mut self,
        reader: &mut Reader<R>,
        op: F,
        limit: u64
    ) -> Result<Option<Content>, E>
    where
        R: io::BufRead,
        F: FnOnce(Element) -> Result<(), E>,
        E: From<Error>
    {
        reader.reset_and_limit(limit);
        self.take_opt_element(reader, op)
    }

    pub fn take_text<R, F, T, E>(
        &mut self,
        reader: &mut Reader<R>,
        op: F
    ) -> Result<T, E>
    where
        R: io::BufRead,
        F: FnOnce(Text) -> Result<T, E>,
        E: From<Error>
    {
        if self.empty {
            return Err(Error::Malformed.into())
        }

        loop {
            reader.buf.clear();
            let event = reader.reader.read_event_into(
                &mut reader.buf
            ).map_err(Into::into)?;
            match event {
                Event::Text(text) => {
                    return op(Text(text))
                }
                Event::Comment(_) => { }
                _ => return Err(Error::Malformed.into())
            }
        }
    }

    pub fn take_text_with_limit<R, F, T, E>(
        &mut self,
        reader: &mut Reader<R>,
        op: F,
        limit: u64
    ) -> Result<T, E>
    where
        R: io::BufRead,
        F: FnOnce(Text) -> Result<T, E>,
        E: From<Error>
    {
        reader.reset_and_limit(limit);
        self.take_text(reader, op)
    }

    pub fn take_end<R: io::BufRead>(
        &mut self,
        reader: &mut Reader<R>
    ) -> Result<(), Error> {
        if self.empty {
            return Ok(())
        }

        loop {
            reader.buf.clear();
            match reader.reader.read_event_into(&mut reader.buf)? {
                Event::End(_) => {
                    self.empty = true;
                    return Ok(())
                }
                Event::Comment(_) => { }
                _ => return Err(Error::Malformed)
            }
        }
    }

    pub fn take_opt_final_text<R, F, T, E>(
        &mut self,
        reader: &mut Reader<R>,
        op: F
    ) -> Result<T, E>
    where
        R: io::BufRead,
        F: FnOnce(Option<Text>) -> Result<T, E>,
        E: From<Error>
    {
        if self.empty {
            return op(None)
        }

        loop {
            reader.buf.clear();
            let event = reader.reader.read_event_into(
                &mut reader.buf
            ).map_err(Into::into)?;
            match event {
                Event::Text(text) => {
                    let res = op(Some(Text(text)))?;
                    self.take_end(reader)?;
                    return Ok(res)
                }
                Event::End(_) => {
                    self.empty = true;
                    return op(None)
                }
                Event::Comment(_) => { }
                _ => return Err(Error::Malformed.into())
            }
        }
    }

    /// Skips an optional text element inside the reader.
    pub fn skip_opt_text<R>(
        &mut self,
        reader: &mut Reader<R>
    ) -> Result<(), Error>
    where
        R: io::BufRead,
    {
        if self.empty {
            return Ok(())
        }

        loop {
            reader.buf.clear();
            let event = reader.reader.read_event_into(
                &mut reader.buf
            )?;
            match event {
                Event::Text(_text) => {
                    self.take_end(reader)?;
                    return Ok(())
                }
                Event::End(_) => {
                    self.empty = true;
                    return Ok(())
                }
                Event::Comment(_) => { }
                _ => return Err(Error::Malformed)
            }
        }
    }
}


//------------ Name ----------------------------------------------------------

/// The name of a tag or attribute.
#[derive(Clone, Copy,Eq, Hash, PartialEq)]
pub struct Name<'n, 'l> {
    namespace: Option<&'n [u8]>,
    local: &'l [u8],
}

impl<'n, 'l> Name<'n, 'l> {
    /// Creates a new name from its components.
    fn new(namespace: Option<&'n [u8]>, local: &'l [u8]) -> Self {
        Name { namespace, local }
    }

    /// Creates a qualified name from a namespace and a local name.
    pub const fn qualified(namespace: &'n [u8], local: &'l [u8]) -> Self {
        Name {
            namespace: Some(namespace),
            local
        }
    }

    /// Creates an unqualified name from only a local name.
    pub const fn unqualified(local: &'l [u8]) -> Self {
        Name {
            namespace: None,
            local
        }
    }

    pub fn namespace(&self) -> Option<&[u8]> {
        self.namespace
    }

    pub fn local(&self) -> &[u8] {
        self.local
    }

    pub const fn into_unqualified(self) -> Name<'static, 'l> {
        Name::unqualified(self.local)
    }
}

impl fmt::Debug for Name<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Name(")?;
        if let Some(ns) = self.namespace {
            write!(f, "{}:", String::from_utf8_lossy(ns))?;
        }
        write!(f, "{}", String::from_utf8_lossy(self.local))
    }
}

impl<'l> From<&'l [u8]> for Name<'_, 'l> {
    fn from(local: &'l [u8]) -> Self {
        Name::unqualified(local)
    }
}

impl<'l> From<&'l str> for Name<'_, 'l> {
    fn from(local: &'l str) -> Self {
        Name::unqualified(local.as_bytes())
    }
}

impl<'n, 'l> From<(&'n [u8], &'l [u8])> for Name<'n, 'l> {
    fn from((namespace, local): (&'n [u8], &'l [u8])) -> Self {
        Name::qualified(namespace, local)
    }
}

impl<'n, 'l> From<(&'n str, &'l str)> for Name<'n, 'l> {
    fn from((namespace, local): (&'n str, &'l str)) -> Self {
        Name::qualified(namespace.as_bytes(), local.as_bytes())
    }
}


//------------ AttrValue -----------------------------------------------------

/// The value of an attribute.
#[derive(Clone)]
pub struct AttrValue<'a>(quick_xml::events::attributes::Attribute<'a>);

impl AttrValue<'_> {
    pub fn ascii_into<T: str::FromStr>(self) -> Result<T, Error> {
        let s = self.0.unescape_value()?;
        if !s.is_ascii() {
            return Err(Error::Malformed)
        }
        T::from_str(s.as_ref()).map_err(|_| Error::Malformed)
    }

    pub fn into_ascii_bytes(self) -> Result<Bytes, Error> {
        let s = self.0.unescape_value()?;
        if !s.is_ascii() {
            return Err(Error::Malformed)
        }
        Ok(s.into_owned().into())
    }
}


//------------ Text ----------------------------------------------------------

pub struct Text<'a>(quick_xml::events::BytesText<'a>);

impl Text<'_> {
    pub fn to_utf8(&self) -> Result<Cow<'_, str>, Error> {
        Ok(self.0.unescape()?)
    }

    pub fn to_ascii(&self) -> Result<Cow<'_, str>, Error> {
        // XXX Shouldn’t this reject non-ASCII Unicode?
        Ok(self.0.unescape()?)
    }

    pub fn base64_decode(&self) -> Result<Vec<u8>, Error> {
        base64::Xml.decode(
            self.to_utf8()?.as_ref()
        ).map_err(|_| Error::Malformed)
    }
}


//------------ BufReadCounter ------------------------------------------------

/// A simple BufRead passthrough proxy that acts as a "trip computer"
/// 
/// It keeps track of the amount of bytes read since it was last reset.
/// If a limit is set, it will return an IO error when attempting to read
/// past that limit.
struct BufReadCounter<R: io::BufRead> {
    reader: R,
    trip: u64,
    limit: u64,
}

impl<R: io::BufRead> BufReadCounter<R> {
    /// Create a new trip computer (resetting counter) for a BufRead.
    ///
    /// Acts transparently to the implementation of a BufRead below.
    pub fn new(reader: R) -> Self {
        BufReadCounter {
            reader,
            trip: 0,
            limit: 0
        }
    }

    /// Reset the amount of bytes read back to 0
    pub fn reset(&mut self) {
        self.trip = 0;
    }

    /// Set a limit or pass 0 to disable the limit to the maximum bytes to 
    /// read. This overrides the previous limit.
    pub fn limit(&mut self, limit: u64) {
        self.limit = limit;
    }
}

impl<R: io::BufRead> io::Read for BufReadCounter<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R: io::BufRead> io::BufRead for BufReadCounter<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.limit > 0 && self.trip > self.limit {
            return Err(
                io::Error::other(
                    format!("Trip is over limit ({:?}/{:?})", 
                        &self.trip, &self.limit))
            );
        }
        self.reader.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.trip = self.trip.saturating_add(
            u64::try_from(amt).unwrap_or_default()
        );
        self.reader.consume(amt)
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    Xml(quick_xml::Error),
    XmlAttr(AttrError),
    Malformed,
}

impl From<quick_xml::Error> for Error {
    fn from(err: quick_xml::Error) -> Self {
        Error::Xml(err)
    }
}

impl From<AttrError> for Error {
    fn from(err: AttrError) -> Self {
        Error::XmlAttr(err)
    }
}

impl From<base64::XmlDecodeError> for Error {
    fn from(_: base64::XmlDecodeError) -> Self {
        Self::Malformed
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Xml(ref err) => err.fmt(f),
            Error::XmlAttr(ref err) => err.fmt(f),
            Error::Malformed => f.write_str("malformed XML"),
        }
    }
}

impl error::Error for Error { } 
