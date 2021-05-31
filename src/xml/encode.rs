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
