use std::fmt;
use std::io;

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
        let writer = quick_xml::Writer::new_with_indent(writer, b' ', INDENT_SIZE);
        Writer { writer }
    }

    /// Start a new tag
    pub fn start(&mut self, name: &Name, attributes: Option<Attributes>) -> Result<(), Error> {
        let mut start = BytesStart::borrowed(name.local(), name.local().len());

        if let Some(attributes) = attributes {
            attributes.write(&mut start);
        }

        self.writer.write_event(Event::Start(start))?;

        Ok(())
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

//------------ Attributes ----------------------------------------------------

pub struct Attributes {
    inner: Vec<(String, String)>
}

impl Attributes {
    pub fn add(&mut self, key: impl fmt::Display, val: impl fmt::Display) {
        self.inner.push((key.to_string(), val.to_string()))
    }

    fn write(&self, start: &mut BytesStart) {
        for (k, v) in &self.inner {
            start.push_attribute((k.as_bytes(), v.as_bytes()))
        }

    }
}

impl Default for Attributes {
    fn default() -> Self {
        Attributes { inner: vec![] }
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
