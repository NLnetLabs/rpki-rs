//! URIs.

use std::{fmt, str};
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

    pub fn from_str(s: &str) -> Result<Self, Error> {
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
}

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
    scheme: Scheme,
    host:   Bytes,
    path:   Bytes
}

impl Http {

    pub fn from_string(s: String) -> Result<Self, Error> {
        Self::from_bytes(Bytes::from(s))
    }

    pub fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_bytes(Bytes::from(s))
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(slice.into())
    }

    pub fn from_bytes(mut bytes: Bytes) -> Result<Self, Error> {
        if !is_uri_ascii(&bytes) {
            return Err(Error::NotAscii)
        }

        let scheme = Scheme::take(&mut bytes)?;
        match scheme {
            Scheme::Rsync => { return Err(Error::BadScheme) }
            _ => { }
        }

        let host_length = {
            let mut parts = bytes.splitn(3, |ch| *ch == b'/');
            match parts.next() {
                Some(host) => { host.len() }
                None => return Err(Error::BadUri)
            }
        };

        let host = bytes.split_to(host_length);
        let path = bytes;

        if path.len() == 0 {
            return Err(Error::BadUri)
        }

        Ok(Http{scheme, host, path})
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
}

impl fmt::Display for Http {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.scheme.fmt(f)?;
        if !self.host.is_empty() {
            write!(f, "{}", self.host())?;
        }
        if !self.path.is_empty() {
            write!(f, "{}", self.path())?;
        }
        Ok(())
    }
}


#[derive(Clone, Debug, PartialEq)]
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
        return false
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

    pub fn to_string(&self) -> String {
        format!("{}", self)
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Scheme::Http  => { write!(f, "{}", "http://")?; },
            Scheme::Https => { write!(f, "{}", "https://")?; },
            Scheme::Rsync => { write!(f, "{}", "rsync://")?; }
        }
        Ok(())
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
        assert_eq!(Scheme::Http, http.scheme);
        assert_eq!(Bytes::from("my.host.tld"), http.host);
        assert_eq!(Bytes::from("/and/a/path"), http.path);
    }

    #[test]
    fn should_parse_https_uri() {
        let http = Http::from_str("https://my.host.tld/and/a/path").unwrap();
        assert_eq!(Scheme::Https, http.scheme);
        assert_eq!(Bytes::from("my.host.tld"), http.host);
        assert_eq!(Bytes::from("/and/a/path"), http.path);
    }
}