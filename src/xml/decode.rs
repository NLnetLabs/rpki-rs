
use std::str::from_utf8;
use std::{error, fmt, io, str};
use std::borrow::Cow;
use bytes::Bytes;
use quick_xml::events::{BytesStart, Event};

/// An XML reader.
///
/// This struct holds all state necessary for parsing an XML document.
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
    where
        F: FnMut(&[u8], AttrValue) -> Result<(), E>,
        E: From<Error>
    {
        for attr in self.start.attributes() {
            let attr = attr.map_err(Into::into)?;
            if attr.key == b"xmlns" || attr.key.starts_with(b"xmlns:") {
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
    pub fn empty() -> Self {
        Content { empty: true }
    }

    pub fn filled() -> Self {
        Content { empty: false }
    }

    pub fn is_empty(&self) -> bool {
        self.empty
    }
    
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

    pub fn take_opt_final_text<R, F, T, E>(
        &mut self,
        reader: &mut Reader<R>,
        op: F
    ) -> Result<Option<T>, E>
    where
        R: io::BufRead,
        F: FnOnce(Text) -> Result<T, E>,
        E: From<Error>
    {
        if self.empty {
            return Ok(None)
        }

        loop {
            reader.buf.clear();
            let event = reader.reader.read_event(
                &mut reader.buf
            ).map_err(Into::into)?;
            match event {
                Event::Text(text) => {
                    let res = op(Text(text))?;
                    self.take_end(reader)?;
                    return Ok(Some(res))
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
            let event = reader.reader.read_event(
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

    /// Just read the entire content until the specified end element and
    /// return anything found as a new string.
    pub fn read_to_end<R, K: AsRef<[u8]>>(
        &self,
        end: K,
        reader: &mut Reader<R>
    ) -> Result<String, Error>
    where
        R: io::BufRead,
    {
        reader.buf.clear();
        reader.reader.read_to_end(end, &mut reader.buf)?;

        let s = from_utf8(&reader.buf).map_err(|_| Error::Malformed)?;

        Ok(s.to_string())
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

impl<'n, 'l> fmt::Debug for Name<'n, 'l> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Name(")?;
        if let Some(ns) = self.namespace {
            write!(f, "{}:", String::from_utf8_lossy(ns))?;
        }
        write!(f, "{}", String::from_utf8_lossy(self.local))
    }
}

impl<'n, 'l> From<&'l [u8]> for Name<'n, 'l> {
    fn from(local: &'l [u8]) -> Self {
        Name::unqualified(local)
    }
}

impl<'n, 'l> From<&'l str> for Name<'n, 'l> {
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
        Ok(s.into_owned().into())
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

    pub fn base64_decode(&self) -> Result<Vec<u8>, Error> {
        // The text is supposed to be xsd:base64Binary which only allows
        // the base64 characters plus whitespace.
        let base64 = self.to_ascii()
            .map(|text| {
                text.as_bytes()
                .iter()
                .filter(|c| **c < 128_u8) // stuff like unicode whitespace
                .filter(|c| !b" \n\t\r\x0b\x0c=".contains(c))
                .copied()
                .collect::<Vec<_>>() 
            })?;
        
        base64::decode_config(base64, base64::STANDARD_NO_PAD)
            .map_err(|_| Error::Malformed)
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    Xml(quick_xml::Error),
    Malformed,
}

impl From<quick_xml::Error> for Error {
    fn from(err: quick_xml::Error) -> Self {
        Error::Xml(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Xml(ref err) => err.fmt(f),
            Error::Malformed => f.write_str("malformed XML"),
        }
    }
}

impl error::Error for Error { } 
