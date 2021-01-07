//! URIs.

use std::{error, fmt, hash, str};
use std::convert::TryFrom;
use bytes::{BufMut, Bytes, BytesMut};

#[cfg(feature = "repository")] use std::io;
#[cfg(feature = "repository")] use bcder::encode;
#[cfg(feature = "repository")] use bcder::{Mode, Tag};
#[cfg(feature = "repository")] use bcder::encode::PrimitiveContent;
#[cfg(feature = "serde")] use std::str::FromStr;
#[cfg(feature = "serde")] use serde::de;
#[cfg(feature = "serde")] use serde::{
    Deserialize, Deserializer, Serialize, Serializer
};


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
#[derive(Clone, Debug)]
pub struct Rsync {
    /// The bytes of the URI.
    bytes: Bytes,

    /// Index where the module portion starts.
    ///
    /// Everything before that is the scheme (always `"rsync://"), the
    /// authority, and a single slash.
    module_start: usize,

    /// Index where the path portion starts.
    ///
    /// This is the position of the first character after the slash.
    path_start: usize,
}

impl Rsync {
    /// Creates a new URI from a module and a path.
    ///
    /// # Panics
    ///
    /// This function panics if `path` contains bytes that are not allowed in
    /// an rsync URI’s path.
    pub fn new(module: RsyncModule, path: &[u8]) -> Self {
        module.uri.join(path.as_ref())
    }

    pub fn from_string(s: String) -> Result<Self, Error> {
        Self::from_bytes(Bytes::from(s))
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(Bytes::copy_from_slice(slice))
    }

    pub fn from_bytes(bytes: Bytes) -> Result<Self, Error> {
        if !is_uri_ascii(&bytes) {
            return Err(Error::NotAscii)
        }

        if !starts_with_ignore_case(&bytes, b"rsync://") {
            return Err(Error::BadScheme)
        }
        let (authority, module) = {
            let mut parts = bytes[8..].splitn(3, |ch| *ch == b'/');
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

        // +9: preceding "rsync://", trailing "/"
        let module_start = 9 + authority;

        // +1: trailing "/"
        let path_start = module_start + module + 1;

        let res = Rsync { bytes, module_start, path_start };
        Self::check_path(res.path().as_bytes())?;
        Ok(res)
    }

    /// Moves the URI to its own memory.
    ///
    /// Values use shared memory in order to allow cheap copying which may
    /// result in large allocations being kept around longer than necessary.
    /// This method moves the URI to a new memory location allowing the
    /// previous location to potentially be freed.
    pub fn unshare(&mut self) {
        self.bytes = Bytes::copy_from_slice(self.bytes.as_ref());
    }

    fn check_path(path: &[u8]) -> Result<(), Error> {
        // Don’t allow ".." anywhere. Don’t allow empty segments except at the
        // end.
        let mut items = path.split(|ch| *ch == b'/');
        loop {
            let item = match items.next() {
                Some(item) => item,
                None => return Ok(())
            };
            if item.is_empty() {
                break
            }
            if item == b".." || item == b"." {
                return Err(Error::DotSegments)
            }
        }
        if items.next().is_some() {
            Err(Error::EmptySegments)
        }
        else {
            Ok(())
        }
    }

    pub fn as_str(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(self.bytes.as_ref()) }
    }

    pub fn module(&self) -> RsyncModule {
        let mut uri = self.clone();
        uri.bytes.truncate(self.path_start);
        RsyncModule {
            uri
        }
    }

    pub fn authority(&self) -> &str {
        &self.as_str()[8..(self.module_start - 1)]
    }

    fn module_str(&self) -> &str {
        &self.as_str()[self.module_start..(self.path_start - 1)]
    }

    pub fn path(&self) -> &str {
        &self.as_str()[self.path_start..]
    }

    pub fn path_bytes(&self) -> &[u8] {
        &self.bytes[self.path_start..]
    }

    pub fn parent(&self) -> Option<Self> {
        // rsplit always returns at least one element.
        let tail = self.path().rsplit(|ch| ch == '/').next().unwrap().len();
        if tail == 0 {
            None
        }
        else {
            let mut res = self.clone();
            res.bytes.truncate(self.bytes.len() - tail);
            Some(res)
        }
    }

    /// Returns a copy of the URI extends by the given path.
    ///
    /// # Panics
    ///
    /// The method panics if `path` is not a valid path.
    pub fn join(&self, path: &[u8]) -> Self {
        assert!(is_uri_ascii(path));
        Self::check_path(path).unwrap();
        let mut res = BytesMut::with_capacity(
            self.bytes.len() + path.len() + 1
        );
        res.extend_from_slice(&self.bytes);
        if !res.ends_with(b"/") {
            res.extend_from_slice(b"/");
        }
        res.extend_from_slice(path);
        Rsync {
            bytes: res.freeze(),
            module_start: self.module_start,
            path_start: self.path_start,
        }
    }

    pub fn ends_with(&self, extension: &str) -> bool {
        self.path().ends_with(extension)
    }

    /// Returns some relative path of self as a sub path of other, as long as
    /// other is a parent. If self and other are the same, or equal, then the
    /// the returned slice is empty. If other is not a parent of self, then
    /// None is returned.
    pub fn relative_to(&self, other: &Rsync) -> Option<&[u8]> {
        if self.eq_module(other) {
            if self.path_bytes().starts_with(other.path_bytes()) {
                let cut_len = other.path_bytes().len();
                let (_, rel) = self.path_bytes().split_at(cut_len);
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
        self.eq_module(other) &&
        (self.path_bytes().is_empty() || (
            self.ends_with("/") &&
            other.path_bytes().starts_with(self.path_bytes())
        ))
    }

    /// Returns whether the two URIs are in the same module.
    fn eq_module(&self, other: &Rsync) -> bool {
        self.path_start == other.path_start
        && self.bytes[..self.path_start].eq_ignore_ascii_case(
            &other.bytes[..other.path_start]
        )
    }

    #[cfg(feature = "repository")]
    pub fn encode_general_name(&self) -> impl encode::Values + '_ {
        self.encode_as(Tag::CTX_6)
    }
}


//--- TryFrom and FromStr

impl TryFrom<String> for Rsync {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Error> {
        Self::from_string(s)
    }
}

impl str::FromStr for Rsync {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_bytes(Bytes::copy_from_slice(s.as_ref()))
    }
}


//--- AsRef

impl AsRef<[u8]> for Rsync {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl AsRef<str> for Rsync {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}


//--- PartialEq and Eq

impl<T: AsRef<[u8]>> PartialEq<T> for Rsync {
    fn eq(&self, other: &T) -> bool {
        let other = other.as_ref();
        if self.bytes.len() != other.len() {
            return false
        }
        self.bytes[..self.module_start].eq_ignore_ascii_case(
            &other[..self.module_start]
        )
        && self.bytes[self.module_start..] == other[self.module_start..]
    }
}

impl Eq for Rsync { }


//--- Hash

impl hash::Hash for Rsync {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for ch in &self.bytes[..self.module_start] {
            ch.to_ascii_lowercase().hash(state)
        }
        self.bytes[self.module_start].hash(state)
    }
}


//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl Serialize for Rsync {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        self.as_str().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Rsync {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        deserializer.deserialize_string(UriVisitor::<Rsync>::default())
    }
}


//--- PrimitiveContent

#[cfg(feature = "repository")]
impl<'a> encode::PrimitiveContent for &'a Rsync {
    const TAG: Tag = Tag::IA5_STRING;

    fn encoded_len(&self, _: Mode) -> usize {
        self.bytes.len()
    }

    fn write_encoded<W: io::Write>(
        &self,
        _mode: Mode,
        target: &mut W
    ) -> Result<(), io::Error> {
        target.write_all(&self.bytes)
    }
}


//--- Display

impl fmt::Display for Rsync {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}


//------------ RsyncModule ---------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RsyncModule {
    uri: Rsync,
}

impl RsyncModule {
    /// Creates a new valud from an authority and a module.
    ///
    /// # Panics
    ///
    /// The function panics if `authority` or `module` contain illegal
    /// characters.
    pub fn new<A, M>(authority: A, module: M) -> Self
    where A: AsRef<[u8]>, M: AsRef<[u8]> {
        let authority = authority.as_ref();
        let module = module.as_ref();

        let mut res = BytesMut::with_capacity(
            // "rsync://" authority "/" module "/"
            authority.len() + module.len() + 10
        );
        res.extend_from_slice(b"rsync://");
        res.extend_from_slice(authority);
        res.extend_from_slice(b"/");
        res.extend_from_slice(module);
        res.extend_from_slice(b"/");
        RsyncModule {
            uri: Rsync::from_bytes(res.freeze()).unwrap()
        }
    }

    /// Moves the value to its own memory.
    ///
    /// Values use shared memory in order to allow cheap copying which may
    /// result in large allocations being kept around longer than necessary.
    /// This method moves the URI to a new memory location allowing the
    /// previous location to potentially be freed.
    pub fn unshare(&mut self) {
        self.uri.unshare()
    }


    pub fn to_uri(&self) -> Rsync {
        self.uri.clone()
    }

    pub fn authority(&self) -> &str {
        self.uri.authority()
    }

    pub fn module(&self) -> &str {
        self.uri.module_str()
    }
}


//--- Display

impl fmt::Display for RsyncModule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "rsync://{}/{}/", self.authority(), self.module())
    }
}


//------------ Https ---------------------------------------------------------

/// A simple HTTPS URI.
///
/// This is only a slim wrapper around a `Bytes` value ensuring that the
/// scheme is `"https"`.
#[derive(Clone, Debug)]
pub struct Https {
    /// The raw octets of the URI.
    ///
    /// Since a URI is guaranteed to be ASCII-only, this is also a valid
    /// `str`.
    uri: Bytes,

    /// The index within `uri` where the hostname ends.
    ///
    /// We need this for comparison: the host part needs to be compared
    /// case insensitive while all the rest is case sensitive. This attribute
    /// then marks where case sensitive comparision starts.
    ///
    /// In a correctly encoded HTTPS URI, this is the third slash or the end
    /// of the bytes if there isn’t one.
    path_idx: usize,
}

impl Https {
    pub fn from_string(s: String) -> Result<Self, Error> {
        Self::from_bytes(Bytes::from(s))
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(Bytes::copy_from_slice(slice))
    }

    pub fn from_bytes(bytes: Bytes) -> Result<Self, Error> {
        if !is_uri_ascii(&bytes) {
            return Err(Error::NotAscii)
        }
        let (scheme, start) = Scheme::from_prefix(bytes.as_ref())?;
        if !scheme.is_https() {
            return Err(Error::BadScheme)
        }
        let path_idx = bytes.iter().enumerate().skip(start).find(|&(_, ch)| {
            *ch == b'/'
        }).map(|(idx, _)| idx).unwrap_or_else(|| bytes.len());
        Ok(Https { uri: bytes, path_idx })
    }

    /// Moves the URI to its own memory.
    ///
    /// Values use shared memory in order to allow cheap copying which may
    /// result in large allocations being kept around longer than necessary.
    /// This method moves the URI to a new memory location allowing the
    /// previous location to potentially be freed.
    pub fn unshare(&mut self) {
        self.uri = Bytes::copy_from_slice(self.uri.as_ref());
    }

    pub fn scheme(&self) -> Scheme {
        Scheme::Https
    }

    pub fn authority(&self) -> &str {
        &self.as_str()[self.scheme().as_str().len() + 3..self.path_idx]
    }

    pub fn as_str(&self) -> &str {
        unsafe { str::from_utf8_unchecked(self.uri.as_ref()) }
    }

    #[cfg(feature = "repository")]
    pub fn encode_general_name(&self) -> impl encode::Values + '_ {
        self.encode_as(Tag::CTX_6)
    }

    fn path(&self) -> &[u8] {
        &self.uri[self.path_idx..]
    }

    /// This function will join this URI and the given path. If the current
    /// URI does not end with a trailing '/', it will be injected.
    pub fn join(&self, path: &[u8]) -> Self {
        assert!(is_uri_ascii(path));
        let mut res = BytesMut::with_capacity(
            self.uri.len() + self.uri.len() + 1
        );
        res.put_slice(self.uri.as_ref());

        if !self.path().is_empty() && !self.path().ends_with(b"/") {
            res.put_slice(b"/");
        }

        res.put_slice(path);

        Https {
            uri: res.freeze(),
            path_idx: self.path_idx
        }
    }
}


//--- AsRef

impl AsRef<Bytes> for Https {
    fn as_ref(&self) -> &Bytes {
        &self.uri
    }
}

impl AsRef<str> for Https {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for Https {
    fn as_ref(&self) -> &[u8] {
        self.uri.as_ref()
    }
}


//--- TryFrom and FromStr

impl TryFrom<String> for Https {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Error> {
        Self::from_string(s)
    }
}

impl str::FromStr for Https {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_bytes(Bytes::copy_from_slice(s.as_ref()))
    }
}


//--- PartialEq and Eq

impl PartialEq for Https {
    fn eq(&self, other: &Self) -> bool {
        self.path_idx == other.path_idx
        && self.uri[..self.path_idx].eq_ignore_ascii_case(
            &other.uri[..other.path_idx]
        )
        && self.uri[self.path_idx..] == other.uri[self.path_idx..]
    }
}

impl Eq for Https { }


//--- Hash

impl hash::Hash for Https {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for ch in self.uri[..self.path_idx].iter() {
            ch.to_ascii_lowercase().hash(state)
        }
        self.uri[self.path_idx..].hash(state)
    }
}


//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl Serialize for Https {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        self.as_str().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Https {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        deserializer.deserialize_string(UriVisitor::<Https>::default())
    }
}


//--- PrimitiveContent

#[cfg(feature = "repository")]
impl<'a> encode::PrimitiveContent for &'a Https {
    const TAG: Tag = Tag::IA5_STRING;

    fn encoded_len(&self, _: Mode) -> usize {
        self.uri.len()
    }

    fn write_encoded<W: io::Write>(
        &self,
        _mode: Mode,
        target: &mut W
    ) -> Result<(), io::Error> {
        target.write_all(self.uri.as_ref())
    }
}


//--- Display

impl fmt::Display for Https {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_str().fmt(f)
    }
}


//------------ Scheme --------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Scheme {
    Https,
    Rsync
}

impl Scheme {
    /// Determines the scheme from the prefix of a bytes slice.
    ///
    /// Returns both the scheme itself and the index of the first byte
    /// following the scheme prefx including the two slashes.
    fn from_prefix(s: &[u8]) -> Result<(Self, usize), Error> {
        if starts_with_ignore_case(s, b"https://") {
            Ok((Scheme::Https, 8))
        }
        else if starts_with_ignore_case(s, b"rsync://") {
            Ok((Scheme::Rsync, 8))
        }
        else {
            Err(Error::BadScheme)
        }
    }

    pub fn is_https(self) -> bool {
        matches!(self, Scheme::Https)
    }

    pub fn is_rsync(self) -> bool {
        matches!(self, Scheme::Rsync)
    }

    pub fn as_str(self) -> &'static str {
        match self {
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


//------------ UriVisitor ----------------------------------------------------

/// Private helper type for implementing deserialization.
#[cfg(feature = "serde")]
struct UriVisitor<V>(std::marker::PhantomData<V>);

#[cfg(feature = "serde")]
impl<V> Default for UriVisitor<V> {
    fn default() -> Self {
        UriVisitor(std::marker::PhantomData)
    }
}

#[cfg(feature = "serde")]
impl<'de, V> serde::de::Visitor<'de> for UriVisitor<V>
where
    V: FromStr + TryFrom<String>,
    <V as FromStr>::Err: fmt::Display,
    <V as TryFrom<String>>::Error: fmt::Display,
{
    type Value = V;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a string containing a URI")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where E: de::Error {
        V::from_str(s).map_err(de::Error::custom)
    }

    fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
    where E: de::Error {
        V::try_from(s).map_err(de::Error::custom)
    }
}



//------------ Helper Functions ----------------------------------------------

pub fn starts_with_ignore_case(s: &[u8], expected: &[u8]) -> bool {
    if let Some(s) = s.get(..expected.len()) {
        s.eq_ignore_ascii_case(expected)
    }
    else {
        false
    }
}

pub fn is_uri_ascii<S: AsRef<[u8]>>(slice: S) -> bool {
    slice.as_ref().iter().all(|&ch| {
        ch > b' ' && ch != b'"' && ch != b'#' && ch != b'<' && ch != b'>'
            && ch != b'?' && ch != b'[' && ch != b'\\' && ch != b']'
            && ch != b'^' && ch != b'`' && ch != b'{' && ch != b'|'
            && ch != b'}' && ch < 0x7F
    })
}


//------------ Error ---------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NotAscii,
    BadUri,
    BadScheme,
    DotSegments,
    EmptySegments,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Error::NotAscii => "invalid characters",
            Error::BadUri => "bad URI",
            Error::BadScheme => "bad URI scheme",
            Error::DotSegments => "URI with dot path segments",
            Error::EmptySegments => "URI with emtpy path segments",
        })
    }
}

impl error::Error for Error { }



//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn rsync_components() {
        let uri = Rsync::from_slice(b"rsync://host/module/foo/bar").unwrap();
        assert_eq!(uri.module().authority(), "host");
        assert_eq!(uri.authority(), "host");
        assert_eq!(uri.module().module(), "module");
        assert_eq!(uri.path(), "foo/bar");

        let uri = Rsync::from_slice(b"rsync://host/module/").unwrap();
        assert_eq!(uri.module().authority(), "host");
        assert_eq!(uri.authority(), "host");
        assert_eq!(uri.module().module(), "module");
        assert_eq!(uri.path(), "");
    }

    #[test]
    fn rsync_check_uri() {
        assert!(Rsync::from_slice(b"rsync://host/module/foo/bar").is_ok());
        assert!(Rsync::from_slice(b"rsync://host/module/foo/bar/").is_ok());
        assert_eq!(
            Rsync::from_slice(b"rsync://host/module/foo/../bar/"),
            Err(Error::DotSegments)
        );
        assert_eq!(
            Rsync::from_slice(b"rsync://host/module/foo/./bar/"),
            Err(Error::DotSegments)
        );
        assert_eq!(
            Rsync::from_slice(b"rsync://host/module/foo/bar/.."),
            Err(Error::DotSegments)
        );
        assert_eq!(
            Rsync::from_slice(b"rsync://host/module/foo/bar/../"),
            Err(Error::DotSegments)
        );
        assert_eq!(
            Rsync::from_slice(b"rsync://host/module/foo//bar/"),
            Err(Error::EmptySegments)
        );
        assert_eq!(
            Rsync::from_slice(b"rsync://host/module//foo/bar/"),
            Err(Error::EmptySegments)
        );
    }

    #[test]
    fn resolve_relative_rsync_path() {
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
    fn https_authority() {
        assert_eq!(
            Https::from_str(
                "https://example.com/some/stuff"
            ).unwrap().authority(),
            "example.com"
        );
        assert_eq!(
            Https::from_str("https://example.com/",).unwrap().authority(),
            "example.com"
        );
    }

    #[test]
    fn https_eq()  {
        assert_eq!(
            Https::from_str("https://example.com/some/stuff").unwrap(),
            Https::from_str("https://example.com/some/stuff").unwrap(),
        );
        assert_eq!(
            Https::from_str("htTps://eXAMple.coM/some/stuff").unwrap(),
            Https::from_str("https://example.com/some/stuff").unwrap(),
        );
        assert_eq!(
            Https::from_str("https://example.com").unwrap(),
            Https::from_str("https://example.com").unwrap(),
        );
        assert_eq!(
            Https::from_str("https://example.com").unwrap(),
            Https::from_str("htTps://eXAMple.coM").unwrap(),
        );
        assert_ne!(
            Https::from_str("htTps://eXAMple.coM/some/stuff").unwrap(),
            Https::from_str("https://example.com/Some/stuff").unwrap(),
        );
        assert_ne!(
            Https::from_str("https://example.com/some/stuff").unwrap(),
            Https::from_str("https://example.com/Some/stuff").unwrap(),
        );
        assert_ne!(
            Https::from_str("https://example.com/some/stuff").unwrap(),
            Https::from_str("https://example.com/Some/stufF").unwrap(),
        );
    }

    #[test]
    fn https_hash() {
        fn hash<T: hash::Hash>(t: T) -> u64 {
            use std::hash::Hasher;

            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            t.hash(&mut hasher);
            hasher.finish()
        }
        
        assert_eq!(
            hash(Https::from_str("https://example.com/some/stuff").unwrap()),
            hash(Https::from_str("https://example.com/some/stuff").unwrap()),
        );
        assert_eq!(
            hash(Https::from_str("htTps://eXAMple.coM/some/stuff").unwrap()),
            hash(Https::from_str("https://example.com/some/stuff").unwrap()),
        );
        assert_eq!(
            hash(Https::from_str("https://example.com").unwrap()),
            hash(Https::from_str("https://example.com").unwrap()),
        );
        assert_eq!(
            hash(Https::from_str("https://example.com").unwrap()),
            hash(Https::from_str("htTps://eXAMple.coM").unwrap()),
        );
        assert_ne!(
            hash(Https::from_str("htTps://eXAMple.coM/some/stuff").unwrap()),
            hash(Https::from_str("https://example.com/Some/stuff").unwrap()),
        );
        assert_ne!(
            hash(Https::from_str("https://example.com/some/stuff").unwrap()),
            hash(Https::from_str("https://example.com/Some/stuff").unwrap()),
        );
        assert_ne!(
            hash(Https::from_str("https://example.com/some/stuff").unwrap()),
            hash(Https::from_str("https://example.com/Some/stufF").unwrap()),
        );

    }

    #[test]
    #[cfg(feature = "serde")]
    fn rsync_serde() {
        use serde_json::{from_str, to_string};

        let uri = Rsync::from_str("rsync://localhost/mod_b/a/b").unwrap();
        let res = from_str::<Rsync>(&to_string(&uri).unwrap()).unwrap();
        assert_eq!(uri, res);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn https_serde_string() {
        use serde_json::{from_str, to_string};

        let uri = Https::from_str("https://example.com/some/stuff").unwrap();
        let res = from_str(&to_string(&uri).unwrap()).unwrap();
        assert_eq!(uri, res);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn https_serde_reader() {
        let uri = Https::from_str("https://example.com/some/stuff").unwrap();
        let json = serde_json::to_string(&uri).unwrap();
        let deser_uri: Https = serde_json::from_reader(
            json.as_bytes()
        ).unwrap();
        assert_eq!(uri, deser_uri);
    }

    #[test]
    fn https_join() {
        let base_uri_no_trailing_slash = Https::from_str("https://example.com/some").unwrap();
        let base_uri_trailing_slash = Https::from_str("https://example.com/some/").unwrap();
        let sub = "sub/".as_bytes();

        let expected = Https::from_str("https://example.com/some/sub/").unwrap();

        assert_eq!(base_uri_no_trailing_slash.join(sub), expected);
        assert_eq!(base_uri_trailing_slash.join(sub), expected);
    }
}
