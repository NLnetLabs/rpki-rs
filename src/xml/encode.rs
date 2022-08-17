use std::{fmt, io};
use std::io::Write as _;
use std::fmt::Write as _;
use super::decode::Name;


//------------ Writer --------------------------------------------------------

/// Wraps a writer for producing XML.
#[derive(Debug)]
pub struct Writer<W> {
    /// The wrapped writer.
    wrapped: W,

    /// A place to store an error for delayed error handling.
    ///
    /// This is necessary so we can use `Drop` for elements which doesn’t
    /// allow us to return an error.
    error: Option<io::Error>,

    /// The string to add for each level of indentation.
    indent: &'static str,

    /// The current indentation level.
    ///
    /// This is the number of times we should repeat `self.indent` at the
    /// beginning of a line.
    indent_level: usize,
}

impl<W: io::Write> Writer<W> {
    /// Create a new XML writer by wrapping an IO writer.
    ///
    /// The writer will use an indent string of two spaces.
    pub fn new(wrapped: W) -> Self {
        Writer {
            wrapped,
            error: None,
            indent: "  ",
            indent_level: 0,
        }
    }

    /// Change the indent string.
    ///
    /// After calling this method, each line will be started with the provided
    /// string repeated for each indent level.
    pub fn set_indent(&mut self, s: &'static str) {
        self.indent = s
    }

    /// Start an XML element.
    ///
    /// This will write the beginning of the tag to the writer and therefore
    /// may error. Upon success, it returns an [`Element`] which can be used
    /// to add attributes and content. The element is finished when this
    /// element is dropped – which is necessary to regain access to `self` as
    /// well.
    pub fn element<'s>(
        &'s mut self, tag: Name<'static, 'static>,
    ) -> Result<Element<'s, W>, io::Error> {
        Element::start(self, tag)
    }

    /// Concludes writing and returns the writer.
    pub fn into_wrapped(mut self) -> Result<W, io::Error> {
        if let Some(err) = self.error.take() {
            Err(err)
        }
        else {
            Ok(self.wrapped)
        }
    }

    /// Concludes writing and drops the writer.
    pub fn done(mut self) -> Result<(), io::Error> {
        if let Some(err) = self.error.take() {
            Err(err)
        }
        else {
            Ok(())
        }
    }
}

/// # Internal Interface
///
impl<W: io::Write> Writer<W> {
    /// Stores an error for delayed error handling.
    fn store_error(&mut self, error: io::Error) {
        self.error = Some(error)
    }

    /// Increases indent by one level.
    fn indent(&mut self) {
        self.indent_level = self.indent_level.saturating_add(1);
    }

    /// Decreases indent by one level.
    fn dedent(&mut self) {
        self.indent_level = self.indent_level.saturating_sub(1);
    }

    /// Writes the indent.
    ///
    /// This does not add a line break.
    fn write_indent(&mut self) -> Result<(), io::Error> {
        if self.indent_level == 0 || self.indent.is_empty() {
            return Ok(())
        }

        for _ in 0..self.indent_level {
            self.write_all(self.indent.as_bytes())?
        }
        Ok(())
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

/// An XML element in the process of being written.
#[derive(Debug)]
pub struct Element<'a, W: io::Write> {
    /// The writer to write to.
    writer: &'a mut Writer<W>,

    /// The tag.
    tag: Name<'static, 'static>,

    /// Is the element still empty?
    ///
    /// We have to keep this because of the different way empty elements are
    /// closed.
    empty: bool,
}

impl<'a, W: io::Write> Element<'a, W> {
    /// Start a new element using the given writer and tag.
    ///
    /// Writes the start as far as that’s possible and then returns the
    /// element.
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

    /// Write an attribute.
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

    /// Write an optional attribute.
    pub fn attr_opt(
        self, name: &str, value: Option<&(impl Text + ?Sized)>,
    ) -> Result<Self, io::Error> {
        match value {
            None => Ok(self),
            Some(value) => self.attr(name, value)
        }
    }

    /// Write the content of the element.
    ///
    /// The actual content is written by the closure passed in.
    pub fn content(
        mut self, op: impl FnOnce(&mut Content<W>) -> Result<(), io::Error>
    ) -> Result<Self, io::Error> {
        self.empty = false;
        self.writer.write_all(b">")?;
        self.writer.indent();
        op(&mut Content { writer: self.writer})?;
        self.writer.dedent();
        Ok(self)
    }

    /// Writes the end of the element.
    fn end(&mut self) -> Result<(), io::Error> {
        if self.empty {
            self.writer.write_all(b"/>")?;
        }
        else {
            self.writer.write_all(b"\n")?;
            self.writer.write_indent()?;
            self.writer.write_all(b"</")?;
            if let Some(ns) = self.tag.namespace() {
                self.writer.write_all(ns)?;
                self.writer.write_all(b":")?;
            }
            self.writer.write_all(self.tag.local())?;
            self.writer.write_all(b">")?;
        }
        Ok(())
    }
}

impl<'a, W: io::Write> Drop for Element<'a, W> {
    fn drop(&mut self) {
        if let Err(err) = self.end() {
            self.writer.store_error(err)
        }
    }
}


//------------ Content -------------------------------------------------------

/// The content of an element.
///
/// This is passed to the closure for [`Element::content`] to use for actually
/// producing content.
#[derive(Debug)]
pub struct Content<'a, W> {
    /// The wrapped writer.
    writer: &'a mut Writer<W>,
}

impl<'a, W: io::Write> Content<'a, W> {
    /// Add an element with the given tag.
    ///
    /// This will write the beginning of the tag to the writer and therefore
    /// may error. Upon success, it returns an [`Element`] which can be used
    /// to add attributes and content. The element is finished when this
    /// element is dropped – which is necessary to regain access to `self` as
    /// well.
    pub fn element<'s>(
        &'s mut self, tag: Name<'static, 'static>
    ) -> Result<Element<'s, W>, io::Error> {
        self.writer.write_all(b"\n")?;
        self.writer.write_indent()?;
        Element::start(self.writer, tag)
    }

    /// Add an optional element with the given tag if the given option
    /// is some.
    pub fn element_opt<'s, T>(
        &'s mut self,
        option: Option<&T>,
        tag: Name<'static, 'static>,
        op: impl FnOnce(&T, Element<'s, W>) -> Result<(), io::Error>
    ) -> Result<(), io::Error> {
        if let Some(opt) = option {
            let element = self.element(tag)?;
            op(opt, element)
        } else {
            Ok(())
        }
    }

    /// Write some PCDATA text.
    ///
    /// The text will be correctly escaped while it is being written.
    pub fn pcdata(
        &mut self, text: &(impl Text + ?Sized)
    ) -> Result<(), io::Error> {
        self.writer.write_all(b"\n")?;
        self.writer.write_indent()?;
        text.write_escaped(TextEscape::Pcdata, &mut self.writer)
    }

    /// Write raw text.
    ///
    /// The text will not be escaped at all. This may lead to invalid XML.
    pub fn raw(
        &mut self, text: &(impl Text + ?Sized)
    ) -> Result<(), io::Error> {
        self.writer.write_all(b"\n")?;
        self.writer.write_indent()?;
        text.write_raw(&mut self.writer)
    }

    /// Write data encoded in BASE64.
    pub fn base64(
        &mut self, data: &(impl Text + ?Sized)
    ) -> Result<(), io::Error> {
        self.writer.write_all(b"\n")?;
        self.writer.write_indent()?;
        data.write_base64(&mut self.writer)
    }
}


//------------ Text ----------------------------------------------------------

/// Text to be written in XML.
///
/// This is a helper trait to allow passing different things to the various
/// text writing methods and still retain reasonable performance.
pub trait Text {
    /// Write text escaped for the given mode to `target`.
    fn write_escaped(
        &self, mode: TextEscape, target: &mut impl io::Write
    ) -> Result<(), io::Error>;

    /// Write text as is to `target`.
    fn write_raw(
        &self, target: &mut impl io::Write
    ) -> Result<(), io::Error>;

    /// Write text encoded in BASE64 to `target`.
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


//------------ DisplayText ---------------------------------------------------

/// A helper struct to transparently escape text via `fmt::Write`.
struct DisplayText<'a, W> {
    inner: &'a mut W,
    escape: TextEscape,
    error: Result<(), io::Error>,
}

impl<'a, W: io::Write> DisplayText<'a, W> {
    /// Creates a new instance atop the given writer for the given mode.
    fn new(inner: &'a mut W, escape: TextEscape) -> Self {
        DisplayText {
            inner, escape,
            error: Ok(()),
        }
    }

    /// Unwraps the struct into the final result.
    ///
    /// Because `fmt::Write` doesn’t handle IO errors, we have to keep any
    /// around and you need to use this function to get the error in the end.
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

/// The escape mode for writing text.
#[derive(Clone, Copy, Debug)]
pub enum TextEscape {
    /// The text appears as an attribute value.
    Attr,

    /// The text appears as PCDATA.
    Pcdata,
}

impl TextEscape {
    /// Return the text for replacing the given character if necessary.
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

    /// Write an octet sequence escaping all necessary characters.
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

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    const ROOT_TAG: Name = Name::unqualified(b"root");
    const OUTER_TAG: Name = Name::unqualified(b"outer");
    const INNER_TAG: Name = Name::unqualified(b"inner");

    #[test]
    fn xml_doc_should_not_be_wrapped_with_whitespace() -> io::Result<()> {
        let mut buf = Vec::<u8>::new();
        let mut writer = Writer::new(&mut buf);

        writer.element(ROOT_TAG)?;
        writer.done()?;

        assert_eq!("<root/>", std::str::from_utf8(&buf).unwrap());
        Ok(())
    }

    #[test]
    fn test_indent() -> io::Result<()> {
        let mut buf = Vec::<u8>::new();
        let mut writer = Writer::new(&mut buf);

        writer
            .element(ROOT_TAG)?
            .content(|content| {
                content.element(OUTER_TAG)?.content(|content| {
                    content.element(INNER_TAG)?;
                    Ok(())
                })?;
                Ok(())
            })?;
        writer.done()?;

        assert_eq!(
            "<root>\
            \n  <outer>\
            \n    <inner/>\
            \n  </outer>\
            \n</root>",
            std::str::from_utf8(&buf).unwrap()
        );
        Ok(())
    }
}
