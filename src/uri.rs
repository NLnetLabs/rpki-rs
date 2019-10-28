//! URIs.

use std::{fmt, hash, io, str};
use std::convert::TryFrom;
use std::str::FromStr;
use bcder::encode;
use bcder::{Mode, Tag};
use bcder::encode::PrimitiveContent;
use bytes::{BufMut, Bytes, BytesMut};
use derive_more::Display;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};


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
        if bytes.is_empty() {
            return Err(Error::BadUri)
        }
        bytes.advance(1);
        Self::check_path(&bytes)?;
        Ok(Rsync {
            module: RsyncModule::new(authority, module),
            path: bytes
        })
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

    pub fn module(&self) -> &RsyncModule {
        &self.module
    }

    pub fn to_module(&self) -> RsyncModule {
        self.module.clone()
    }

    pub fn path(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(self.path.as_ref()) }
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
        Self::from_bytes(Bytes::from(s))
    }
}


//--- Serialize and Deserialize

impl Serialize for Rsync {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Rsync {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        deserializer.deserialize_string(UriVisitor::<Rsync>::default())
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

#[derive(Clone, Debug)]
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

    pub fn authority(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(self.authority.as_ref()) }
    }

    pub fn module(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(self.module.as_ref()) }
    }
}


//--- PartialEq and Eq

impl PartialEq for RsyncModule {
    fn eq(&self, other: &Self) -> bool {
        self.authority.eq_ignore_ascii_case(other.authority.as_ref())
        && self.module == other.module
    }
}

impl Eq for RsyncModule { }


//--- Hash

impl hash::Hash for RsyncModule {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for ch in self.authority.iter() {
            ch.to_ascii_lowercase().hash(state)
        }
        self.module.hash(state)
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
        Self::from_bytes(slice.into())
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

    pub fn scheme(&self) -> Scheme {
        Scheme::Https
    }

    pub fn as_str(&self) -> &str {
        unsafe { str::from_utf8_unchecked(self.uri.as_ref()) }
    }

    pub fn encode_general_name<'a>(&'a self) -> impl encode::Values + 'a {
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
        Self::from_bytes(Bytes::from(s))
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

impl Serialize for Https {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Https {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        deserializer.deserialize_string(UriVisitor::<Https>::default())
    }
}


//--- PrimitiveContent

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

    fn take(bytes: &mut Bytes) -> Result<Scheme, Error> {
        let (res, len) = Self::from_prefix(bytes.as_ref())?;
        bytes.advance(len);
        Ok(res)
    }

    pub fn is_https(self) -> bool {
        match self {
            Scheme::Https => true,
            _ => false
        }
    }

    pub fn is_rsync(self) -> bool {
        match self {
            Scheme::Rsync => true,
            _ => false
        }
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
struct UriVisitor<V>(std::marker::PhantomData<V>);

impl<V> Default for UriVisitor<V> {
    fn default() -> Self {
        UriVisitor(std::marker::PhantomData)
    }
}

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

#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum Error {
    #[display(fmt="invalid characters")]
    NotAscii,

    #[display(fmt="bad URI")]
    BadUri,

    #[display(fmt="bad URI scheme")]
    BadScheme,

    #[display(fmt="URI with dot segments")]
    DotSegments,

    #[display(fmt="URI with empty segments")]
    EmptySegments,
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

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
    fn rsync_serde() {
        use serde_json::{from_str, to_string};

        let uri = Rsync::from_str("rsync://localhost/mod_b/a/b").unwrap();
        let res = from_str(&to_string(&uri).unwrap()).unwrap();
        assert_eq!(uri, res);
    }

    #[test]
    fn https_serde_string() {
        use serde_json::{from_str, to_string};

        let uri = Https::from_str("https://example.com/some/stuff").unwrap();
        let res = from_str(&to_string(&uri).unwrap()).unwrap();
        assert_eq!(uri, res);
    }

    #[test]
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
