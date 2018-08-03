//! Support for RPKI XML structures.

use std::{fs, io};
use std::path::Path;
use base64;
use bytes::Bytes;
use xml::EventReader;
use xml::ParserConfig;
use xml::reader;
use xml::writer;
use xml::attribute::OwnedAttribute;
use xml::EventWriter;
use xml::EmitterConfig;


//------------ XmlReader -----------------------------------------------------

/// A convenience wrapper for RPKI XML parsing
///
/// This type only exposes things we need for the RPKI XML structures.
pub struct XmlReader<R: io::Read> {
    /// The underlying xml-rs reader
    reader: EventReader<R>
}

/// Basic operations to parse the XML.
///
/// These methods are private because they are used by the higher level
/// closure based methods, defined below, that one should use to parse
/// XML safely.
impl <R: io::Read> XmlReader<R> {
    /// Takes the next element and expects a start of document.
    fn start_document(&mut self) -> Result<(), XmlReaderErr> {
        match self.reader.next() {
            Ok(reader::XmlEvent::StartDocument {..}) => { Ok(())},
            _ => return Err(XmlReaderErr::ExpectedStartDocument)
        }
    }

    /// Takes the next element and expects a start element with the given name.
    fn expect_element(&mut self) -> Result<(Tag, Attributes), XmlReaderErr> {
        match self.reader.next() {
            Ok(reader::XmlEvent::StartElement { name, attributes, ..}) => {
                Ok((Tag{name: name.local_name}, Attributes{attributes}))
            },
            _ => return Err(XmlReaderErr::ExpectedStart)
        }
    }

    /// Takes the next element and expects a close element with the given name.
    fn expect_close(&mut self, tag: Tag) -> Result<(), XmlReaderErr> {
        match self.reader.next() {
            Ok(reader::XmlEvent::EndElement { name, ..}) => {
                if name.local_name == tag.name {
                    Ok(())
                } else {
                    Err(XmlReaderErr::ExpectedClose(tag.name))
                }
            }
            _ => Err(XmlReaderErr::ExpectedClose(tag.name))
        }
    }

    /// Takes the next element and expects the end of document.
    ///
    /// Returns Ok(true) if the element is the end of document, or
    /// an error otherwise.
    fn end_document(&mut self) -> Result<(), XmlReaderErr> {
        match self.reader.next() {
            Ok(reader::XmlEvent::EndDocument) => Ok(()),
            _ => Err(XmlReaderErr::ExpectedEnd)
        }
    }
}

/// Closure based parsing of XML.
///
/// This approach ensures that the consumer can only get opening tags, or
/// content (such as Characters), and process the enclosed content. In
/// particular it ensures that the consumer cannot accidentally get close
/// tags - so it forces that execution returns.
impl <R: io::Read> XmlReader<R> {
    /// Decodes an XML structure
    ///
    /// This method checks that the document starts, then passes a reader
    /// instance to the provided closure, and will return the result from
    /// that after checking that the XML document is fully processed.
    pub fn decode<F, T, E>(source: R, op: F) -> Result<T, E>
    where F: FnOnce(&mut Self) -> Result<T, E>,
          E: From<XmlReaderErr> {
        let mut config = ParserConfig::new();
        config.trim_whitespace = true;
        config.ignore_comments = true;

        let mut xml = XmlReader{reader: config.create_reader(source)};

        xml.start_document()?;
        let res = op(&mut xml)?;
        xml.end_document()?;

        Ok(res)
    }

    /// Takes an element and process it in a closure
    ///
    /// This method checks that the next element is indeed a Start Element,
    /// and passes the Tag and Attributes and this reader to a closure. After
    /// the closure completes it will verify that the next element is the
    /// Close Element for this Tag, and returns the result from the closure.
    pub fn take_element<F, T, E>(&mut self, op: F) -> Result<T, E>
    where F: FnOnce(&Tag, Attributes, &mut Self) -> Result<T, E>,
          E: From<XmlReaderErr> {
        let (tag, attr) = self.expect_element()?;
        let res = op(&tag, attr, self)?;
        self.expect_close(tag)?;
        Ok(res)
    }

    /// Takes a named element and process it in a closure
    ///
    /// Checks that the element has the expected name and passed the closure
    /// to the generic take_element method.
    pub fn take_named_element<F, T, E>(
        &mut self,
        name: &str,
        op: F
    ) -> Result<T, E>
    where
        F: FnOnce(Attributes, &mut Self) -> Result<T, E>,
        E: From<XmlReaderErr>
    {
        self.take_element(|t, a, r| {
            if t.name != name {
                Err(XmlReaderErr::ExpectedNamedStart(name.to_string()).into())
            }
            else {
                op(a, r)
            }
        })
    }

    /// Takes characters.
    ///
    /// Returns Ok(String) containing the value of the characters, or
    /// an error if the next element is any other type.
    pub fn take_characters(&mut self) -> Result<String, XmlReaderErr> {
        match self.reader.next() {
            Ok(reader::XmlEvent::Characters(chars)) => { Ok(chars) }
            _ => return Err(XmlReaderErr::ExpectedCharacters)
        }
    }
}

impl XmlReader<fs::File> {

    /// Opens a file and decodes it as an XML file.
    pub fn open<P, F, T, E>(path: P, op: F) -> Result<T, E>
    where F: FnOnce(&mut Self) -> Result<T, E>,
          P: AsRef<Path>,
          E: From<XmlReaderErr> + From<io::Error> {
        Self::decode(fs::File::open(path)?, op)
    }
}

//------------ XmlReaderErr --------------------------------------------------

#[derive(Debug, Fail)]
pub enum XmlReaderErr {
    #[fail(display = "Expected Start of Document")]
    ExpectedStartDocument,

    #[fail(display = "Expected Start Element")]
    ExpectedStart,

    #[fail(display = "Expected Start Element with name: {}", _0)]
    ExpectedNamedStart(String),

    #[fail(display = "Expected Characters Element")]
    ExpectedCharacters,

    #[fail(display = "Expected Close Element with name: {}", _0)]
    ExpectedClose(String),

    #[fail(display = "Expected End of Document")]
    ExpectedEnd,

    #[fail(display = "Error reading file: {}", _0)]
    IoError(io::Error),

    #[fail(display = "Attributes Error: {}", _0)]
    AttributesError(AttributesError),
}

impl From<io::Error> for XmlReaderErr {
    fn from(e: io::Error) -> XmlReaderErr{
        XmlReaderErr::IoError(e)
    }
}

impl From<AttributesError> for XmlReaderErr {
    fn from(e: AttributesError) -> XmlReaderErr {
        XmlReaderErr::AttributesError(e)
    }
}

//------------ Attributes ----------------------------------------------------

/// A convenient wrapper for XML tag attributes
pub struct Attributes {
    /// The underlying xml-rs structure
    attributes: Vec<OwnedAttribute>
}

impl Attributes {

    /// Takes an optional attribute by name
    pub fn take_opt(&mut self, name: &str) -> Option<String> {
        let i = self.attributes.iter().position(|a| a.name.local_name == name);
        match i {
            Some(i) => {
                let a = self.attributes.swap_remove(i);
                Some(a.value)
            }
            None => None
        }
    }

    /// Takes a required attribute by name
    pub fn take_req(&mut self, name: &str) -> Result<String, AttributesError> {
        self.take_opt(name)
            .ok_or(AttributesError::MissingAttribute(name.to_string()))
    }

    /// Verifies that there are no more attributes
    pub fn exhausted(&self) -> Result<(), AttributesError> {
        if self.attributes.len() > 0 {
            return Err(AttributesError::ExtraAttributes)
        }
        Ok(())
    }


}


//------------ AttributesError -----------------------------------------------

#[derive(Debug, Fail)]
pub enum AttributesError {
    #[fail(display = "Required attribute missing: {}", _0)]
    MissingAttribute(String),

    #[fail(display = "Extra attributes found")]
    ExtraAttributes,
}


//------------ Tag -----------------------------------------------------------

pub struct Tag {
    pub name: String
}


//------------ XmlWriter -----------------------------------------------------

/// A convenience wrapper for RPKI XML generation
///
/// This type only exposes things we need for the RPKI XML structures.
pub struct XmlWriter<W> {
    /// The underlying xml-rs writer
    writer: EventWriter<W>
}


/// Generate the XML.
impl <W: io::Write> XmlWriter<W> {

    /// Private general method called by the pub put_first_element with
    /// Some(namespace) and put_element with None for namespace.
    fn put_some_element<F>(
        &mut self,
        name: &str,
        namespace: Option<&str>,
        op: F) -> Result<(), XmlWriterError>
    where F: FnOnce(&mut Self) -> Result<(), XmlWriterError> {
        let mut start = writer::XmlEvent::start_element(name);

        match namespace {
            Some(ns) => { start = start.ns("", ns); },
            None => {}
        }

        // Attributes

        self.writer.write(start)?;
        op(self)?;
        self.writer.write(writer::XmlEvent::end_element())?;

        Ok(())
    }

    /// Creates the first element for your XML structure. Note that namespace
    /// is required because all the RPKI XML structures have one.
    pub fn put_first_element<F>(
        &mut self,
        name: &str,
        namespace: &str,
        op: F) -> Result<(), XmlWriterError>
        where F: FnOnce(&mut Self) -> Result<(), XmlWriterError> {
        self.put_some_element(name, Some(namespace), op)
    }

    /// Creates a nested element.
    pub fn put_element<F>(
        &mut self,
        name: &str,
        op: F) -> Result<(), XmlWriterError>
        where F: FnOnce(&mut Self) -> Result<(), XmlWriterError> {
        self.put_some_element(name, None, op)
    }

    /// Converts bytes to base64 encoded Characters as the content. Note
    /// that you cannot have both Characters and other included elements.
    /// This would be valid XML, but it's not used by any of the RPKI XML
    /// structures.
    pub fn put_blob(&mut self, bytes: Bytes) -> Result<(), XmlWriterError> {
        let b64 = base64::encode(&bytes);
        self.writer.write(writer::XmlEvent::Characters(b64.as_ref()))?;
        Ok(())
    }

    /// Use this for convenience where empty content is required
    pub fn empty(&mut self) -> Result<(), XmlWriterError> {
        Ok(())
    }

    /// Sets up the writer config and returns a closure that is expected
    /// to add the actual content of the XML.
    ///
    /// This method is private because one should use the pub encode_vec
    /// method, and in future others like it, to set up the writer for a
    /// specific type (Vec<u8>, File, etc.).
    fn encode<F>(w: W, op: F) -> Result<(), XmlWriterError>
    where F: FnOnce(&mut Self) -> Result<(), XmlWriterError> {

        let writer = EmitterConfig::new()
            .write_document_declaration(false)
            .normalize_empty_elements(false)
            .create_writer(w);

        let mut x = XmlWriter { writer };

        op(&mut x)
    }
}


impl XmlWriter<()> {

    pub fn encode_vec<F>(op: F) -> Vec<u8>
        where F: FnOnce(&mut XmlWriter<&mut Vec<u8>>) -> Result<(), XmlWriterError> {
        let mut b = Vec::new();
        XmlWriter::encode(&mut b, op).unwrap();
        b
    }
}


//------------ XmlWriterError ------------------------------------------------

#[derive(Debug, Fail)]
pub enum XmlWriterError {
    #[fail(display = "I/O Error: {}", _0)]
    IoError(io::Error),

    #[fail(display = "Writer (emitter) error: {}", _0)]
    EmitterError(writer::Error),
}

impl From<io::Error> for XmlWriterError {
    fn from(e: io::Error) -> XmlWriterError {
        XmlWriterError::IoError(e)
    }
}

impl From<writer::Error> for XmlWriterError {
    fn from(e: writer::Error) -> XmlWriterError {
        XmlWriterError::EmitterError(e)
    }
}

//------------ Tests ---------------------------------------------------------


#[cfg(test)]
mod tests {

    use super::*;
    use std::str;

    #[test]
    fn should_write_xml() {

        let xml = XmlWriter::encode_vec(|w| {
            w.put_first_element(
                "hello",
                "http://namespace/",
                |w|
                    {
                        w.put_element("world", |w| {
                            w.put_blob(Bytes::from("howdy"))
                        })
                    }
            )
        });

        assert_eq!(
            str::from_utf8(&xml).unwrap(),
            r#"<hello xmlns="http://namespace/"><world>aG93ZHk=</world></hello>"#);
    }
}