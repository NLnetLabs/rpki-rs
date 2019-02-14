//! URIs.

use std::{fmt, io, str};
use bcder::encode;
use bcder::{Mode, Tag};
use bcder::encode::PrimitiveContent;
use bytes::{BufMut, Bytes, BytesMut};


//------------ Rsync ---------------------------------------------------------

/// An rsync URI.
///
/// This implements a simplified form of the the rsync URI defined in RFC 5781
/// which in turn references RFC 3986. Only absolute URIs including an
/// authority are allowed.
///
/// Parsing is simplified in that it only checks for the correct structure and
/// that no forbidden characters are present.
///
//  In particular, forbidden characters are
//
//     SPACE CONTROL " # < > ? [ \\ ] ^ ` { | }
//
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Rsync {
    module: RsyncModule,
    path: Bytes
}

impl Rsync {
    pub fn new(module: RsyncModule, path: Bytes) -> Self {
        Rsync { module, path }
    }

    pub fn from_string(s: String) -> Result<Self, Error> {
        Self::from_bytes(Bytes::from(s))
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(slice.into())
    }

    pub fn from_bytes(mut bytes: Bytes) -> Result<Self, Error> {
        if !is_uri_ascii(&bytes) {
            return Err(Error::NotAscii)
        }

        match Scheme::take(&mut bytes) {
            Ok(Scheme::Rsync) => {}
            _ => return Err(Error::BadScheme)
        }

        let (authority, module) = {
            let mut parts = bytes.splitn(3, |ch| *ch == b'/');
            let authority = match parts.next() {
                Some(part) => part.len(),
                None => return Err(Error::BadUri)
            };
            let module = match parts.next() {
                Some(part) => part.len(),
                None => return Err(Error::BadUri)
            };
            (authority, module)
        };
        let authority = bytes.split_to(authority);
        bytes.advance(1);
        let module = bytes.split_to(module);
        bytes.advance(1);
        Ok(Rsync {
            module: RsyncModule::new(authority, module),
            path: bytes
        })
    }

    pub fn module(&self) -> &RsyncModule {
        &self.module
    }

    pub fn to_module(&self) -> RsyncModule {
        self.module.clone()
    }

    pub fn path(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(self.path.as_ref()) }
    }

    pub fn to_string(&self) -> String {
        format!("{}", self)
    }

    pub fn parent(&self) -> Option<Self> {
        // rsplit always returns at least one element.
        let tail = self.path.rsplit(|ch| *ch == b'/').next().unwrap().len();
        if tail == 0 {
            None
        }
        else {
            let mut res = self.clone();
            if tail == self.path.len() {
                res.path = Bytes::from_static(b"")
            }
            else {
                res.path = self.path.slice(
                    0, self.path.len() - tail - 1
                );
            }
            Some(res)
        }
    }

    pub fn join(&self, path: &[u8]) -> Self {
        assert!(is_uri_ascii(path));
        let mut res = BytesMut::with_capacity(
            self.path.len() + path.len() + 1
        );
        if !self.path.is_empty() {
            res.put_slice(self.path.as_ref());
            if !self.path.ends_with(b"/") {
                res.put_slice(b"/");
            }
        }
        res.put_slice(path);
        Self::new(self.module.clone(), res.freeze())
    }

    pub fn ends_with(&self, extension: &str) -> bool {
        self.path.ends_with(extension.as_bytes())
    }

    /// Returns some relative path of self as a sub path of other, as long as
    /// other is a parent. If self and other are the same, or equal, then the
    /// the returned slice is empty. If other is not a parent of self, then
    /// None is returned.
    pub fn relative_to(&self, other: &Rsync) -> Option<&[u8]> {
        if self.module == other.module {
            if self.path.starts_with(other.path.as_ref()) {
                let cut_len = other.path.len();
                let (_, rel) = self.path.split_at(cut_len);
                Some(rel)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns true if this uri is a directory and it contains the other
    /// uri.
    pub fn is_parent_of(&self, other: &Rsync) -> bool {
        self.module == other.module &&
        (self.path.is_empty() || (
            self.ends_with("/") &&
            other.path.starts_with(self.path.as_ref())
        ))
    }

    pub fn encode_general_name<'a>(&'a self) -> impl encode::Values + 'a {
        self.encode_as(Tag::CTX_6)
    }
}


//--- FromStr

impl str::FromStr for Rsync {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_bytes(Bytes::from(s))
    }
}


//--- PrimitiveContent

impl<'a> encode::PrimitiveContent for &'a Rsync {
    const TAG: Tag = Tag::IA5_STRING;

    fn encoded_len(&self, _: Mode) -> usize {
        // "rsync://" + authority + "/" + module + "/" + path
        10 + self.module.authority.len() + self.module.module.len()
        + self.path.len()
    }

    fn write_encoded<W: io::Write>(
        &self,
        _mode: Mode,
        target: &mut W
    ) -> Result<(), io::Error> {
        target.write_all(b"rsync://")?;
        target.write_all(self.module.authority.as_ref())?;
        target.write_all(b"/")?;
        target.write_all(self.module.module.as_ref())?;
        target.write_all(b"/")?;
        target.write_all(self.path.as_ref())?;
        Ok(())
    }
}


//--- Display

impl fmt::Display for Rsync {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.module.fmt(f)?;
        if !self.path.is_empty() {
            write!(f, "{}", self.path())?;
        }
        Ok(())
    }
}


//------------ RsyncModule ---------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RsyncModule {
    authority: Bytes,
    module: Bytes,
}

impl RsyncModule {
    pub fn new<A, M>(authority: A, module: M) -> Self
    where A: Into<Bytes>, M: Into<Bytes> {
        let authority = authority.into();
        let module = module.into();
        assert!(is_uri_ascii(authority.as_ref()));
        assert!(is_uri_ascii(module.as_ref()));
        RsyncModule { authority, module }
    }

    pub fn to_uri(&self) -> Rsync {
        Rsync {
            module: self.clone(),
            path: Bytes::from_static(b""),
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}", self)
    }

    pub fn authority(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(self.authority.as_ref()) }
    }

    pub fn module(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(self.module.as_ref()) }
    }
}

impl fmt::Display for RsyncModule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "rsync://{}/{}/", self.authority(), self.module())
    }
}


//------------ Http ----------------------------------------------------------

/// A simple HTTP(s) URI
///
/// This supports only what we need for the references in RPKI objects and
/// publication / provisioning messages. In particular, this does not support
/// the query and fragment components of URIs.
#[derive(Clone, Debug, PartialEq)]
pub struct Http {
    secure: bool,
    host:   Bytes,
    path:   Bytes
}

impl Http {

    pub fn from_string(s: String) -> Result<Self, Error> {
        Self::from_bytes(Bytes::from(s))
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(slice.into())
    }

    pub fn from_bytes(mut bytes: Bytes) -> Result<Self, Error> {
        if !is_uri_ascii(&bytes) {
            return Err(Error::NotAscii)
        }

        let secure = match Scheme::take(&mut bytes)? {
            Scheme::Http => false,
            Scheme::Https => true,
            Scheme::Rsync => return Err(Error::BadScheme)
        };

        let host_length = {
            let mut parts = bytes.splitn(3, |ch| *ch == b'/');
            match parts.next() {
                Some(host) => { host.len() }
                None => return Err(Error::BadUri)
            }
        };

        let host = bytes.split_to(host_length);
        let path = bytes;

        if path.is_empty() {
            return Err(Error::BadUri)
        }

        Ok(Http { secure, host, path })
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    pub fn scheme(&self) -> Scheme {
        if self.secure { Scheme::Https }
        else { Scheme::Http }
    }

    pub fn host(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(self.host.as_ref()) }
    }

    pub fn path(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(self.path.as_ref()) }
    }

    pub fn to_string(&self) -> String {
        format!("{}", self)
    }

    pub fn encode_general_name<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence_as(Tag::CTX_6, self.encode())
    }
}


//--- FromStr

impl str::FromStr for Http {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_bytes(Bytes::from(s))
    }
}


//--- PrimitiveContent

impl<'a> encode::PrimitiveContent for &'a Http {
    const TAG: Tag = Tag::IA5_STRING;

    fn encoded_len(&self, _: Mode) -> usize {
        // scheme + "://" + host + path
        self.scheme().as_str().len() + 3 + self.host.len() + self.path.len()
    }

    fn write_encoded<W: io::Write>(
        &self,
        _mode: Mode,
        target: &mut W
    ) -> Result<(), io::Error> {
        target.write_all(self.scheme().as_str().as_bytes())?;
        target.write_all(b"://")?;
        target.write_all(self.host.as_ref())?;
        target.write_all(self.path.as_ref())?;
        Ok(())
    }
}


//--- Display

impl fmt::Display for Http {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.scheme().fmt(f)?;
        if !self.host.is_empty() {
            write!(f, "{}", self.host())?;
        }
        if !self.path.is_empty() {
            write!(f, "{}", self.path())?;
        }
        Ok(())
    }
}


//------------ Scheme --------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Scheme {
    Http,
    Https,
    Rsync
}

impl Scheme {

    fn take_if_matches(bytes: &mut Bytes, s: &str) -> bool {

        let l = s.len();

        if bytes.len()>l && bytes[..l].eq_ignore_ascii_case(s.as_ref()) {
            bytes.advance(l);
            return true
        }
        false
    }

    fn take(bytes: &mut Bytes) -> Result<Scheme, Error> {

        if Scheme::take_if_matches(bytes, "rsync://") {
            return Ok(Scheme::Rsync)
        }
        if Scheme::take_if_matches(bytes, "https://") {
            return Ok(Scheme::Https)
        }
        if Scheme::take_if_matches(bytes, "http://") {
            return Ok(Scheme::Http)
        }
        Err(Error::BadScheme)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Rsync => "rsync",
        }
    }

    pub fn into_string(self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}://", self.as_str())
    }
}



//------------ Helper Functions ----------------------------------------------

pub fn is_uri_ascii<S: AsRef<[u8]>>(slice: S) -> bool {
    slice.as_ref().iter().all(|&ch| {
        ch > b' ' && ch != b'"' && ch != b'#' && ch != b'<' && ch != b'>'
            && ch != b'?' && ch != b'[' && ch != b'\\' && ch != b']'
            && ch != b'^' && ch != b'`' && ch != b'{' && ch != b'|'
            && ch != b'}' && ch < 0x7F
    })
}


//------------ Error ---------------------------------------------------------

#[derive(Clone, Debug, Fail)]
pub enum Error {
    #[fail(display="invalid characters")]
    NotAscii,

    #[fail(display="bad URI")]
    BadUri,

    #[fail(display="bad URI scheme")]
    BadScheme,
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_resolve_relative_rsync_path() {
        let a = Rsync::from_str("rsync://localhost/module/a").unwrap();
        let a_b = Rsync::from_str("rsync://localhost/module/a/b").unwrap();
        let c = Rsync::from_str("rsync://localhost/module/c").unwrap();
        let m2_a_b = Rsync::from_str("rsync://localhost/mod_b/a/b").unwrap();

        assert_eq!(Some(b"".as_ref()), a.relative_to(&a));
        assert_eq!(Some(b"/b".as_ref()), a_b.relative_to(&a));
        assert_eq!(None, a_b.relative_to(&c));
        assert_eq!(None, c.relative_to(&a));
        assert_eq!(None, a.relative_to(&a_b));
        assert_eq!(None, m2_a_b.relative_to(&a));
    }

    #[test]
    fn should_reject_non_ascii_http_uri() {
        match  Http::from_bytes(Bytes::from("http://my.høst.tld/å/pâth")) {
            Err(Error::NotAscii) => { }
            _ => { assert!(false); }
        }
    }

    #[test]
    fn should_reject_bad_scheme_http_uri() {
        match Http::from_str("rsync://my.host.tld/path") {
            Err(Error::BadScheme) => {}
            _ => { assert!(false)}
        }
    }

    #[test]
    fn should_reject_bad_http_uri() {
        match Http::from_str("http://my.host.tld") {
            Err(Error::BadUri) => {}
            _ => { assert!(false)}
        }
    }

    #[test]
    fn should_parse_http_uri() {
        let http = Http::from_str("http://my.host.tld/and/a/path").unwrap();
        assert_eq!(Scheme::Http, http.scheme());
        assert_eq!(Bytes::from("my.host.tld"), http.host);
        assert_eq!(Bytes::from("/and/a/path"), http.path);
    }

    #[test]
    fn should_parse_https_uri() {
        let http = Http::from_str("https://my.host.tld/and/a/path").unwrap();
        assert_eq!(Scheme::Https, http.scheme());
        assert_eq!(Bytes::from("my.host.tld"), http.host);
        assert_eq!(Bytes::from("/and/a/path"), http.path);
    }
}
