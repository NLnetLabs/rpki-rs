use std::fmt;
use std::io;
use std::io::Write as _;
use std::fmt::Write as _;
use super::decode::Name;

/*
use quick_xml::events::BytesEnd;
use quick_xml::events::BytesStart;
use quick_xml::events::BytesText;
use quick_xml::events::Event;

use super::decode::Name;

const INDENT_SIZE: usize = 2;

//------------ Writer --------------------------------------------------------

/// An XML writer
///
/// This struct holds all state necessary for parsing an XML document.
pub struct Writer<W: io::Write> {
    writer: quick_xml::Writer<W>,
}

impl<W: io::Write> Writer<W> {
    /// Creates a new writer from an underlying io::Write.
    pub fn new(writer: W) -> Self {
        let writer = quick_xml::Writer::new(writer);
        Writer { writer }
    }

    /// Creates a new writer from an underlying io::Write which will use
    /// new lines and indentation for each XML element.
    pub fn new_with_indent(writer: W) -> Self {
        let writer = quick_xml::Writer::new_with_indent(
            writer, 
            b' ',
            INDENT_SIZE
        );
        Writer { writer }
    }

    /// Start a new tag
    pub fn start_with_attributes(
        &mut self,
        name: &Name,
        attributes: &[(&[u8], &[u8])]
    ) -> Result<(), Error> {
        let start = self.make_start_element(name, attributes);

        self.writer.write_event(Event::Start(start))?;

        Ok(())
    }

    /// Create an empty element, i.e. an element that is closed
    /// without content. For example: <element foo="bar" />
    pub fn empty_element_with_attributes(
        &mut self,
        name: &Name,
        attributes: &[(&[u8], &[u8])]
    ) -> Result<(), Error> {
        let start = self.make_start_element(name, attributes);
        
        self.writer.write_event(Event::Empty(start))?;

        Ok(())
    }

    fn make_start_element<'a>(
        &mut self,
        name: &'a Name,
        attributes: &'a [(&[u8], &[u8])]
    ) -> BytesStart<'a> {
      let mut start = BytesStart::borrowed(
            name.local(), 
            name.local().len()
        );

        for attr in attributes {
            start.push_attribute(*attr)
        } 

        start
    }

    /// End a tag
    pub fn end(&mut self, name: &Name) -> Result<(), Error> {
        let end = BytesEnd::borrowed(name.local());
        self.writer.write_event(Event::End(end))?;

        Ok(())
    }

    /// Write bytes as base64 encoded content
    pub fn content_bytes(&mut self, data: &[u8]) -> Result<(), Error> {
        let base64 = base64::encode(data);
        let text = BytesText::from_plain(base64.as_bytes());
        self.writer.write_event(Event::Text(text))?;

        Ok(())
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    Xml(quick_xml::Error),
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
        }
    }
}

impl std::error::Error for Error { }
*/


//------------ Writer --------------------------------------------------------

#[derive(Debug)]
pub struct Writer<W> {
    wrapped: W,

    error: Option<io::Error>,
}

impl<W: io::Write> Writer<W> {
    pub fn new(wrapped: W) -> Self {
        Writer { wrapped, error: None }
    }

    pub fn element<'s>(
        &'s mut self, tag: Name<'static, 'static>,
    ) -> Result<Element<'s, W>, io::Error> {
        Element::start(self, tag)
    }

    pub fn done(mut self) -> Result<(), io::Error> {
        if let Some(err) = self.error.take() {
            Err(err)
        }
        else {
            Ok(())
        }
    }
}

impl<W: io::Write> io::Write for Writer<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        if let Some(err) = self.error.take() {
            return Err(err)
        }
        self.wrapped.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        if let Some(err) = self.error.take() {
            return Err(err)
        }
        self.wrapped.flush()
    }
}


//------------ Element -------------------------------------------------------

#[derive(Debug)]
pub struct Element<'a, W: io::Write> {
    writer: &'a mut Writer<W>,
    tag: Name<'static, 'static>,
    empty: bool,
}

impl<'a, W: io::Write> Element<'a, W> {
    fn start(
        writer: &'a mut Writer<W>, tag: Name<'static, 'static>,
    ) -> Result<Self, io::Error> {
        writer.write_all(b"<")?;
        if let Some(ns) = tag.namespace() {
            writer.write_all(ns)?;
            writer.write_all(b":")?;
        }
        writer.write_all(tag.local())?;
        Ok(Element { writer, tag, empty: true })
    }

    pub fn attr(
        mut self, name: &str, value: &(impl Text + ?Sized),
    ) -> Result<Self, io::Error> {
        self.writer.write_all(b" ")?;
        self.writer.write_all(name.as_bytes())?;
        self.writer.write_all(b"=\"")?;
        value.write_escaped(TextEscape::Attr, &mut self.writer)?;
        self.writer.write_all(b"\"")?;
        Ok(self)
    }

    pub fn content(
        mut self, op: impl FnOnce(&mut Content<W>) -> Result<(), io::Error>
    ) -> Result<Self, io::Error> {
        self.empty = false;
        self.writer.write_all(b">")?;
        op(&mut Content { writer: self.writer })?;
        Ok(self)
    }

    fn end(&mut self) -> Result<(), io::Error> {
        if self.empty {
            self.writer.write_all(b"/>")
        }
        else {
            self.writer.write_all(b"</")?;
            if let Some(ns) = self.tag.namespace() {
                self.writer.write_all(ns)?;
                self.writer.write_all(b":")?;
            }
            self.writer.write_all(self.tag.local())?;
            self.writer.write_all(b">")
        }
    }
}

impl<'a, W: io::Write> Drop for Element<'a, W> {
    fn drop(&mut self) {
        if let Err(err) = self.end() {
            self.writer.error = Some(err)
        }
    }
}


//------------ Content -------------------------------------------------------

#[derive(Debug)]
pub struct Content<'a, W> {
    writer: &'a mut Writer<W>,
}

impl<'a, W: io::Write> Content<'a, W> {
    pub fn element<'s>(
        &'s mut self, tag: Name<'static, 'static>
    ) -> Result<Element<'s, W>, io::Error> {
        Element::start(self.writer, tag)
    }

    pub fn pcdata(
        &mut self, text: &(impl Text + ?Sized)
    ) -> Result<(), io::Error> {
        text.write_escaped(TextEscape::Pcdata, &mut self.writer)
    }

    pub fn raw(
        &mut self, text: &(impl Text + ?Sized)
    ) -> Result<(), io::Error> {
        text.write_raw(&mut self.writer)
    }

    pub fn base64(
        &mut self, data: &(impl Text + ?Sized)
    ) -> Result<(), io::Error> {
        data.write_base64(&mut self.writer)
    }
}


//------------ Text ----------------------------------------------------------

pub trait Text {
    fn write_escaped(
        &self, mode: TextEscape, target: &mut impl io::Write
    ) -> Result<(), io::Error>;

    fn write_raw(
        &self, target: &mut impl io::Write
    ) -> Result<(), io::Error>;

    fn write_base64(
        &self, target: &mut impl io::Write
    ) -> Result<(), io::Error> {
        self.write_raw(
            &mut base64::write::EncoderWriter::new(target, base64::STANDARD)
        )
    }
}

impl Text for [u8] {
    fn write_escaped(
        &self, mode: TextEscape, target: &mut impl io::Write
    ) -> Result<(), io::Error> {
        mode.write_escaped(self, target)
    }

    fn write_raw(
        &self, target: &mut impl io::Write
    ) -> Result<(), io::Error> {
        target.write_all(self)
    }
}

impl Text for str {
    fn write_escaped(
        &self, mode: TextEscape, target: &mut impl io::Write
    ) -> Result<(), io::Error> {
        mode.write_escaped(self.as_bytes(), target)
    }

    fn write_raw(
        &self, target: &mut impl io::Write
    ) -> Result<(), io::Error> {
        target.write_all(self.as_bytes())
    }
}

impl<T: fmt::Display> Text for T {
    fn write_escaped(
        &self, mode: TextEscape, target: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut adaptor = DisplayText::new(target, mode);
        match write!(adaptor, "{}", self) {
            Ok(()) => Ok(()),
            Err(_) => match adaptor.into_result() {
                Ok(()) => {
                    Err(io::Error::new(
                        io::ErrorKind::Other, "formatter error"
                    ))
                }
                Err(err) => Err(err)
            }
        }
    }

    fn write_raw(
        &self, target: &mut impl io::Write
    ) -> Result<(), io::Error> {
        write!(target, "{}", self)
    }
}

/*
impl<'a> Text for fmt::Arguments<'a> {
    fn write_escaped(
        &self, mode: TextEscape, target: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut adaptor = DisplayText::new(target, mode);
        match adaptor.write_fmt(self) {
            Ok(()) => Ok(()),
            Err(_) => match adaptor.into_result() {
                Ok(()) => {
                    Err(io::Error::new(
                        io::ErrorKind::Other, "formatter error"
                    ))
                }
                Err(err) => Err(err)
            }
        }
    }

    fn write_raw(
        &self, target: &mut impl io::Write
    ) -> Result<(), io::Error> {
        target.write_fmt(self)
    }
}
*/


//------------ DisplayText ---------------------------------------------------

struct DisplayText<'a, W> {
    inner: &'a mut W,
    escape: TextEscape,
    error: Result<(), io::Error>,
}

impl<'a, W: io::Write> DisplayText<'a, W> {
    fn new(inner: &'a mut W, escape: TextEscape) -> Self {
        DisplayText {
            inner, escape,
            error: Ok(()),
        }
    }

    fn into_result(self) -> Result<(), io::Error> {
        self.error
    }
}

impl<'a, W: io::Write> fmt::Write for DisplayText<'a, W> {
    fn write_str(&mut  self, s: &str) -> fmt::Result {
        match self.escape.write_escaped(s.as_bytes(), self.inner) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.error = Err(err);
                Err(fmt::Error)
            }
        }
    }
}


//------------ TextEscape ----------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum TextEscape {
    Attr,
    Pcdata,
}

impl TextEscape {
    fn replace_char(self, ch: u8) -> Option<&'static str> {
        match self {
            TextEscape::Attr => {
                match ch {
                    b'<' => Some("&lt;"),
                    b'>' => Some("&gt;"),
                    b'"' => Some("&quot;"),
                    b'\'' => Some("&apos;"),
                    b'&' => Some("&amp;"),
                    _ => None
                }
            }
            TextEscape::Pcdata => {
                match ch {
                    b'<' => Some("&lt;"),
                    b'&' => Some("&amp;"),
                    _ => None
                }
            }
        }
    }

    fn write_escaped(
        self, mut s: &[u8], target: &mut impl io::Write
    ) -> Result<(), io::Error> {
        while !s.is_empty() {
            let mut iter = s.iter().enumerate().map(|(idx, ch)| {
                (idx, self.replace_char(*ch))
            });
            let end = loop {
                match iter.next() {
                    Some((idx, Some(repl))) => {
                        // Write up to index, write replacement string,
                        // break with index.
                        target.write_all(&s[0..idx])?;
                        target.write_all(repl.as_bytes())?;
                        break idx;
                    }
                    Some((_, None)) => { }
                    None => {
                        return target.write_all(s);
                    }
                }
            };
            s = &s[end + 1..];
        }
        Ok(())
    }
}
