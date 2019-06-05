
use std::{fmt, io, str};
use std::borrow::Cow;
use bytes::Bytes;
use derive_more::{Display, From};
use quick_xml::events::{BytesStart, Event};

/// An XML reader.
///
/// This struct holds all state necessary for parsing an XML documnet.
pub struct Reader<R: io::BufRead> {
    reader: quick_xml::Reader<R>,
    buf: Vec<u8>,
    ns_buf: Vec<u8>,
}

impl<R: io::BufRead> Reader<R> {
    /// Creates a new reader from an underlying reader.
    pub fn new(reader: R) -> Self {
        let mut reader = quick_xml::Reader::from_reader(reader);
        reader.trim_text(true);
        Reader {
            reader,
            buf: Vec::new(),
            ns_buf: Vec::new(),
        }
    }

    /// Parse the start of the document.
    ///
    /// This is like `Content::take_element` except that it also happily
    /// skips over XML and doctype declarations.
    pub fn start<F, E>(&mut self, op: F) -> Result<Content, E>
    where F: FnOnce(Element) -> Result<(), E>, E: From<Error> {
        loop {
            self.buf.clear();
            let (ns, event) = self.reader.read_namespaced_event(
                &mut self.buf, &mut self.ns_buf
            ).map_err(Into::into)?;
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

    /// Parse the end of the document.
    ///
    /// This checks that the next non-comment event to be the end of file.
    pub fn end(&mut self) -> Result<(), Error> {
        loop {
            self.buf.clear();
            match self.reader.read_event(&mut self.buf)? {
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
    ns: Option<&'n [u8]>,
}

impl<'b, 'n> Element<'b, 'n> {
    /// Creates a new value from the underlying components.
    fn new(start: BytesStart<'b>, ns: Option<&'n [u8]>) -> Self {
        Element { start, ns, }
    }

    /// Returns the name of the element.
    pub fn name(&self) -> Name {
        Name::new(self.ns, self.start.local_name())
    }

    /// Processes the attributes of the element.
    ///
    /// We don’t support qualified attributes. We will also not check for
    /// those.
    pub fn attributes<F, E>(&self, mut op: F) -> Result<(), E>
    where F: FnMut(&[u8], AttrValue) -> Result<(), E>, E: From<Error> {
        for attr in self.start.attributes() {
            let attr = attr.map_err(Into::into)?;
            if attr.key == b"xmlns" {
                continue
            }
            op(attr.key, AttrValue(attr))?;
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
            let (ns, event) = reader.reader.read_namespaced_event(
                &mut reader.buf, &mut reader.ns_buf
            ).map_err(Into::into)?;
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

    pub fn take_opt_element<R, F, E>(
        &mut self,
        reader: &mut Reader<R>,
        op: F
    ) -> Result<Option<Content>, E>
    where R: io::BufRead, F: FnOnce(Element) -> Result<(), E>, E: From<Error> {
        if self.empty {
            return Ok(None)
        }

        loop {
            reader.buf.clear();
            let (ns, event) = reader.reader.read_namespaced_event(
                &mut reader.buf, &mut reader.ns_buf
            ).map_err(Into::into)?;
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

    pub fn take_text<R, F, T, E>(
        &mut self,
        reader: &mut Reader<R>,
        op: F
    ) -> Result<T, E>
    where R: io::BufRead, F: FnOnce(Text) -> Result<T, E>, E: From<Error> {
        if self.empty {
            return Err(Error::Malformed.into())
        }

        loop {
            reader.buf.clear();
            let event = reader.reader.read_event(
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

    pub fn take_end<R: io::BufRead>(
        &mut self,
        reader: &mut Reader<R>
    ) -> Result<(), Error> {
        if self.empty {
            return Ok(())
        }

        loop {
            reader.buf.clear();
            match reader.reader.read_event(&mut reader.buf)? {
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
}

impl<'n, 'l> fmt::Debug for Name<'n, 'l> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Name(")?;
        if let Some(ns) = self.namespace {
            write!(f, "{}:", String::from_utf8_lossy(ns))?;
        }
        write!(f, "{}", String::from_utf8_lossy(self.local))
    }
}


//------------ AttrValue -----------------------------------------------------

/// The value of an attribute.
#[derive(Clone)]
pub struct AttrValue<'a>(quick_xml::events::attributes::Attribute<'a>);

impl<'a> AttrValue<'a> {
    pub fn ascii_into<T: str::FromStr>(self) -> Result<T, Error> {
        let s = self.0.unescaped_value()?;
        if !s.is_ascii() {
            return Err(Error::Malformed)
        }
        let s = unsafe { str::from_utf8_unchecked(s.as_ref()) };
        T::from_str(s).map_err(|_| Error::Malformed)
    }

    pub fn into_ascii_bytes(self) -> Result<Bytes, Error> {
        let s = self.0.unescaped_value()?;
        if !s.is_ascii() {
            return Err(Error::Malformed)
        }
        Ok(Bytes::from(unsafe { str::from_utf8_unchecked(s.as_ref()) }))
    }
}


//------------ Text ----------------------------------------------------------

pub struct Text<'a>(quick_xml::events::BytesText<'a>);

impl<'a> Text<'a> {
    pub fn to_ascii(&self) -> Result<Cow<str>, Error> {
        match self.0.unescaped()? {
            Cow::Borrowed(s) => {
                Ok(Cow::Borrowed(
                    unsafe { str::from_utf8_unchecked(s) }
                ))
            }
            Cow::Owned(s) => {
                Ok(Cow::Owned(unsafe { String::from_utf8_unchecked(s) }))
            }
        }
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display, From)]
pub enum Error {
    #[display(fmt="{}", _0)]
    Xml(quick_xml::Error),

    #[display(fmt="Malformed XML")]
    Malformed,
}

