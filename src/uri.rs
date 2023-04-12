//! URIs.

use std::{error, fmt, hash, str};
use std::borrow::Cow;
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
/// Unlike specified in the RFC but following the way the rsync daemon works,
/// we enforce an rsync URI to consist of three parts: an authority, module
/// name, and path. The URI then is formed as such:
///
/// ```text
/// rsync://authority/module-name/path
/// ```
///
/// The path can be empty, but authority and module name cannot.
///
/// Parsing is simplified in that it only checks that a URI follows this
/// general structure and does not contain any forbidden characters. In
/// addition, empty path segments or path segments consisting solely of a
/// single or double full stop are rejected.
///
//  In particular, forbidden characters are
//
//     SPACE CONTROL " # < > ? [ \\ ] ^ ` { | }
//
#[derive(Clone, Debug)]
pub struct Rsync {
    /// The bytes of the URI including everything.
    ///
    /// Since this is guaranteed to only contain a subset of ASCII
    /// characters, it is also a valid `str`.
    bytes: Bytes,

    /// Index where the module portion starts.
    ///
    /// Everything before that is the scheme (always `"rsync://"), the
    /// authority, and a single slash.
    module_start: usize,

    /// Index where the path portion starts.
    ///
    /// This is the position of the first character after the slash following
    /// the module name.
    path_start: usize,
}

impl Rsync {
    /// Converts an owned string into a URI if it contains a valid URI.
    pub fn from_string(s: String) -> Result<Self, Error> {
        Self::from_bytes(Bytes::from(s))
    }

    /// Creates a new URI with the content given by `slice`.
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(Bytes::copy_from_slice(slice))
    }

    /// Converts a bytes value into a URI.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, Error> {
        check_uri_ascii(&bytes)?;
        if !starts_with_ignore_case(&bytes, b"rsync://") {
            return Err(Error::BadScheme)
        }
        let (authority, module) = {
            let mut parts = bytes[8..].splitn(3, |ch| *ch == b'/');
            let authority = match parts.next().map(|s| s.len()) {
                Some(len) if len > 0 => len,
                _ => return Err(Error::BadUri)
            };
            let module = match parts.next().map(|s| s.len()) {
                Some(len) if len > 0 => len,
                _ => return Err(Error::BadUri)
            };
            if parts.next().is_none() {
                return Err(Error::BadUri)
            }
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

    /// Checks additional requirements of the path portion.
    ///
    /// This does _not_ check whether the slice consists of allowed characters
    /// only. Use `check_uri_ascii` for that.
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

    /// Returns the URI’s content as a bytes slice.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Returns the URI’s content as a string slice.
    pub fn as_str(&self) -> &str {
        // self.bytes is always a valid `str`.
        unsafe { ::std::str::from_utf8_unchecked(self.bytes.as_ref()) }
    }

    /// Returns the URI’s content as a bytes value.
    pub fn to_bytes(&self) -> Bytes {
        self.bytes.clone()
    }

    /// Returns the URI’s authority part as a string slice.
    pub fn authority(&self) -> &str {
        &self.as_str()[8..(self.module_start - 1)]
    }

    /// Returns a canonical version of authority part.
    ///
    /// Since host names are case-insensitive, the authority part can be
    /// provided in different ways. This returns a version of the authority
    /// with all ASCII letters in lowercase.
    pub fn canonical_authority(&self) -> Cow<str> {
        let authority = self.authority();
        if authority.as_bytes().iter().any(u8::is_ascii_uppercase) {
            Cow::Owned(authority.to_ascii_lowercase())
        }
        else {
            Cow::Borrowed(authority)
        }
    }

    /// Returns the URI’s module name as a string slice.
    pub fn module_name(&self) -> &str {
        &self.as_str()[self.module_start..(self.path_start - 1)]
    }

    /// Returns the URI’s module.
    ///
    /// The module is identical to a URI with an empty path.
    pub fn module(&self) -> &str {
        &self.as_str()[..self.path_start]
    }

    /// Returns the URI’s canonical module.
    ///
    /// This is the same as the module but with the authority in canonical
    /// form.
    pub fn canonical_module(&self) -> Cow<str> {
        if self.authority().as_bytes().iter().any(u8::is_ascii_uppercase) {
            let mut res = String::with_capacity(self.path_start);
            res.push_str("rsync://");
            res.push_str(self.authority());
            res.make_ascii_lowercase();
            res.push('/');
            res.push_str(self.module_name());
            res.push('/');
            Cow::Owned(res)
        }
        else {
            Cow::Borrowed(self.module())
        }
    }

    /// Returns the URI’s path as a string slice.
    ///
    /// The path does _not_ start with a slash. As a consequence, an empty
    /// path results in an empty string.
    pub fn path(&self) -> &str {
        &self.as_str()[self.path_start..]
    }

    /// Returns whether the URI's path resolves to a directory.
    pub fn path_is_dir(&self) -> bool {
        self.path().is_empty() || self.path().ends_with("/")
    }

    /// Returns the URI’s path as a bytes slice.
    pub fn path_bytes(&self) -> &[u8] {
        &self.bytes[self.path_start..]
    }

    /// Returns the parent URI.
    ///
    /// The parent URI is the URI with the last path segment removed. If a
    /// URI has no path segment, the method returns `None`. If a URI is
    /// returned, it’s path will have a trailing slash to indicate that it
    /// is a directory.
    ///
    /// Keep in mind that a URI with an empty path will still have the module
    /// name after the authority part. The method will never return a URI
    /// with an empty module name.
    #[allow(clippy::manual_strip)] // str::strip_suffix not in 1.44
    pub fn parent(&self) -> Option<Self> {
        let path = self.path();
        let path = if path.ends_with('/') {
            &path[..path.len() - 1]
        }
        else {
            path
        };
        if path.is_empty() {
            None
        }
        else {
            let len = match path.rfind('/') {
                Some(idx) => self.path_start + idx + 1, // Trailing slash
                None => self.path_start
            };
            let mut res = self.clone();
            res.bytes.truncate(len);
            Some(res)
        }
    }

    /// Returns a copy of the URI extends by the given path.
    ///
    /// Returns an error if `path` contains illegal characters or path
    /// segments that are empty or comprised of only a single or double full
    /// stop. In other words, the method does not resolve double full stop
    /// segments into parent directories. In addition, a path starting with
    /// a slash will lead to an error, too.
    ///
    /// If `path` is empty, returns a clone of itself.
    pub fn join(&self, path: &[u8]) -> Result<Self, Error> {
        if path.is_empty() {
            return Ok(self.clone())
        }

        check_uri_ascii(path)?;
        Self::check_path(path)?;
        let mut res = if self.bytes.ends_with(b"/") {
            let mut res = BytesMut::with_capacity(
                self.bytes.len() + path.len() + 1
            );
            res.extend_from_slice(&self.bytes);
            res
        }
        else {
            let mut res = BytesMut::with_capacity(
                self.bytes.len() + path.len() + 2
            );
            res.extend_from_slice(&self.bytes);
            res.extend_from_slice(b"/");
            res
        };
        res.extend_from_slice(path);
        Ok(Rsync {
            bytes: res.freeze(),
            module_start: self.module_start,
            path_start: self.path_start,
        })
    }

    pub fn ends_with(&self, extension: &str) -> bool {
        self.path().ends_with(extension)
    }

    /// Returns the relative path from some other URI to self.
    ///
    /// If `other` is a parent of `self`, returns the path leading from
    /// other to self. If `other` and `self` are the same, returns an empty
    /// slice. Otherwise returns `None`.
    ///
    /// In other words, the method returns that path that should be passed
    /// to [`other.join`][Rsync::join] to receive a URI that is equal to self.
    #[allow(clippy::manual_strip)] // str::strip_suffix not in 1.44
    pub fn relative_to(&self, other: &Rsync) -> Option<&str> {
        if !self.eq_module(other) {
            return None
        }

        // Reminder: other is the shorter one.

        // Get the two paths. Drop a possible trailing slash from other_path
        // just so we have a single case.
        let self_path = self.path();
        let other_path = other.path();

        // If other_path is empty, self_path is the relative path.
        if other_path.is_empty() {
            return Some(self_path)
        }

        let other_path = if other_path.ends_with('/') {
            &other_path[..other_path.len() - 1]
        }
        else {
            other_path
        };

        // self_path needs to start with other_path. They either are the same
        // or the next thing in self_path needs to be a slash.
        if !self_path.starts_with(other_path) {
            return None
        }
        if self_path.len() == other_path.len() {
            return Some("")
        }
        if self_path.as_bytes()[other_path.len()] != b'/' {
            return None
        }

        // Now we know that self_path is long enough and we can just return
        // the rest.
        Some(&self_path[other_path.len() + 1..])
    }

    /// Returns whether self is a parent directory of another URI.
    ///
    /// If self and other are identical, they are _not_ parents of each other.
    pub fn is_parent_of(&self, other: &Rsync) -> bool {
        match other.relative_to(self) {
            Some(path) => !path.is_empty(),
            None => false
        }
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
    /// then marks where case sensitive comparison starts.
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
        check_uri_ascii(&bytes)?;
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

    /// Returns a octets slice reference of the URI.
    pub fn as_slice(&self) -> &[u8] {
        self.uri.as_ref()
    }

    /// Returns a string reference of the URI.
    pub fn as_str(&self) -> &str {
        // self.uri is always a valid `str`.
        unsafe { str::from_utf8_unchecked(self.uri.as_ref()) }
    }

    pub fn scheme(&self) -> Scheme {
        Scheme::Https
    }

    /// Returns the URI’s authority part as a string slice.
    pub fn authority(&self) -> &str {
        &self.as_str()[self.scheme().as_str().len() + 3..self.path_idx]
    }

    /// Returns a canonical version of authority part.
    ///
    /// Since host names are case-insensitive, the authority part can be
    /// provided in different ways. This returns a version of the authority
    /// with all ASCII letters in lowercase.
    pub fn canonical_authority(&self) -> Cow<str> {
        let authority = self.authority();
        if authority.as_bytes().iter().any(u8::is_ascii_uppercase) {
            Cow::Owned(authority.to_ascii_lowercase())
        }
        else {
            Cow::Borrowed(authority)
        }
    }

    #[cfg(feature = "repository")]
    pub fn encode_general_name(&self) -> impl encode::Values + '_ {
        self.encode_as(Tag::CTX_6)
    }

    /// Returns the URI’s path as a string slice.
    ///
    /// The path does _not_ start with a slash. As a consequence, an empty
    /// path results in an empty string.
    pub fn path(&self) -> &str {
        &self.as_str()[self.path_idx..]
    }

    /// This function will join this URI and the given path. If the current
    /// URI does not end with a trailing '/', it will be injected.
    pub fn join(&self, path: &[u8]) -> Result<Self, Error> {
        check_uri_ascii(path)?;
        let mut res = BytesMut::with_capacity(
            self.uri.len() + self.uri.len() + 1
        );
        res.put_slice(self.uri.as_ref());

        if !self.path().is_empty() && !self.path().ends_with('/') {
            res.put_slice(b"/");
        }

        res.put_slice(path);

        Ok(Https {
            uri: res.freeze(),
            path_idx: self.path_idx
        })
    }

    /// Returns the parent URI.
    ///
    /// The parent URI is the URI with the last path segment removed. If a
    /// URI has no path segment, the method returns `None`. If a URI is
    /// returned, it’s path will have a trailing slash to indicate that it
    /// is a directory.
    ///
    /// Keep in mind that a URI with an empty path will still have the module
    /// name after the authority part. The method will never return a URI
    /// with an empty module name.
    #[allow(clippy::manual_strip)] // str::strip_suffix not in 1.44
    pub fn parent(&self) -> Option<Self> {
        let path = self.path();
        let path = if path.ends_with('/') {
            &path[..path.len() - 1]
        }
        else {
            path
        };
        if path.is_empty() {
            None
        }
        else {
            let len = match path.rfind('/') {
                Some(idx) => self.path_idx + idx + 1, // Trailing slash
                None => self.path_idx
            };
            let mut res = self.clone();
            res.uri.truncate(len);
            Some(res)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

pub fn check_uri_ascii<S: AsRef<[u8]>>(slice: S) -> Result<(), Error> {
    if slice.as_ref().iter().all(|&ch| is_u8_uri_ascii(ch)) {
        Ok(())
    }
    else {
        Err(Error::InvalidCharacters)
    }
}

fn is_u8_uri_ascii(ch: u8) -> bool {
    matches!(
        ch,
        b'!' | b'$'..=b';' | b'=' | b'A'..=b'Z' | b'_' | b'a'..=b'z' | b'~'
    )
}


//------------ Error ---------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidCharacters,
    BadUri,
    BadScheme,
    DotSegments,
    EmptySegments,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Error::InvalidCharacters=> "invalid characters",
            Error::BadUri => "bad URI",
            Error::BadScheme => "bad URI scheme",
            Error::DotSegments => "URI with dot path segments",
            Error::EmptySegments => "URI with empty path segments",
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
    fn rsync_uri_characters() {
        assert!(Rsync::from_str("rsync://host/module/ ").is_err());
        assert!(Rsync::from_str("rsync://host/module/\"").is_err());
        assert!(Rsync::from_str("rsync://host/module/#").is_err());
        assert!(Rsync::from_str("rsync://host/module/<").is_err());
        assert!(Rsync::from_str("rsync://host/module/>").is_err());
        assert!(Rsync::from_str("rsync://host/module/?").is_err());
        assert!(Rsync::from_str("rsync://host/module/[").is_err());
        assert!(Rsync::from_str("rsync://host/module/\\").is_err());
        assert!(Rsync::from_str("rsync://host/module/]").is_err());
        assert!(Rsync::from_str("rsync://host/module/^").is_err());
        assert!(Rsync::from_str("rsync://host/module/`").is_err());
        assert!(Rsync::from_str("rsync://host/module/{").is_err());
        assert!(Rsync::from_str("rsync://host/module/|").is_err());
        assert!(Rsync::from_str("rsync://host/module/}").is_err());
        assert!(
            Rsync::from_str(
                "rsync://host/module/\
                $%&'()*+,-./0123456789:;=\
                ABCDEFGHIJKLMNOPQRSTUVWXYZ_\
                abcdefghijklmnopqrstuvwxyz~"
            ).is_ok()
        );
    }

    #[test]
    fn rsync_from_str() {
        assert!(Rsync::from_str("").is_err());
        assert!(Rsync::from_str("rsync://").is_err());
        assert!(Rsync::from_str("rsync://host/").is_err());
        assert!(Rsync::from_str("rsync://host/module").is_err());
        assert!(Rsync::from_str("rsync://host/module/").is_ok());
        assert!(Rsync::from_str("rsync:////foo").is_err());
        assert!(Rsync::from_str("rsync:///module/foo").is_err());
        assert!(Rsync::from_str("rsync://host//foo").is_err());
        assert!(Rsync::from_str("rsync://host/module/foo/").is_ok());
        assert!(Rsync::from_str("rsync://host/module/foo/bar").is_ok());
        assert!(Rsync::from_str("fsync://host/module/foo/bar").is_err());
        assert!(Rsync::from_str("rsync:// host/module/foo/bar").is_err());
        assert!(Rsync::from_str("rsync://host/ module/foo/bar").is_err());
        assert!(Rsync::from_str("rsync://host/module/f oo/bar").is_err());
    }

    #[test]
    fn rsync_components() {
        let uri = Rsync::from_slice(b"rsync://host/module/foo/bar").unwrap();
        assert_eq!(uri.authority(), "host");
        assert_eq!(uri.module_name(), "module");
        assert_eq!(uri.path(), "foo/bar");

        let uri = Rsync::from_slice(b"rsync://host/module/").unwrap();
        assert_eq!(uri.authority(), "host");
        assert_eq!(uri.module_name(), "module");
        assert_eq!(uri.path(), "");
    }

    #[test]
    fn rsync_canonical_authority() {
        assert_eq!(
            Rsync::from_str(
                "rsync://host/module/foo"
            ).unwrap().canonical_authority(),
            "host"
        );
        assert_eq!(
            Rsync::from_str(
                "rsync://hOSt/module/foo"
            ).unwrap().canonical_authority(),
            "host"
        );
    }

    #[test]
    fn rsync_module() {
        assert_eq!(
            Rsync::from_str("rsync://host/module/").unwrap().module(),
            "rsync://host/module/"
        );
        assert_eq!(
            Rsync::from_str("rsync://host/module/foo").unwrap().module(),
            "rsync://host/module/"
        );
    }

    #[test]
    fn rsync_canonical_module() {
        assert_eq!(
            Rsync::from_str(
                "rsync://host/module/"
            ).unwrap().canonical_module(),
            "rsync://host/module/"
        );
        assert_eq!(
            Rsync::from_str(
                "rsync://host/module/foo"
            ).unwrap().canonical_module(),
            "rsync://host/module/"
        );
        assert_eq!(
            Rsync::from_str(
                "rsync://hOst/module/"
            ).unwrap().canonical_module(),
            "rsync://host/module/"
        );
        assert_eq!(
            Rsync::from_str(
                "rsync://hOst/module/foo"
            ).unwrap().canonical_module(),
            "rsync://host/module/"
        );
    }

    #[test]
    fn rsync_from_slice() {
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
    fn rsync_parent() {
        assert_eq!(
            Rsync::from_str(
                "rsync://host/module/foo/bar/baz/"
            ).unwrap().parent(),
            Some(Rsync::from_str(
                "rsync://host/module/foo/bar/"
            ).unwrap())
        );
        assert_eq!(
            Rsync::from_str(
                "rsync://host/module/foo/bar/baz"
            ).unwrap().parent(),
            Some(Rsync::from_str(
                "rsync://host/module/foo/bar/"
            ).unwrap())
        );
        assert_eq!(
            Rsync::from_str(
                "rsync://host/module/foo/bar/baz"
            ).unwrap().parent(),
            Some(Rsync::from_str(
                "rsync://host/module/foo/bar/"
            ).unwrap())
        );
        assert_eq!(
            Rsync::from_str(
                "rsync://host/module/foo/bar/"
            ).unwrap().parent(),
            Some(Rsync::from_str(
                "rsync://host/module/foo/"
            ).unwrap())
        );
        assert_eq!(
            Rsync::from_str(
                "rsync://host/module/foo/bar"
            ).unwrap().parent(),
            Some(Rsync::from_str(
                "rsync://host/module/foo/"
            ).unwrap())
        );
        assert_eq!(
            Rsync::from_str(
                "rsync://host/module/foo/"
            ).unwrap().parent(),
            Some(Rsync::from_str(
                "rsync://host/module/"
            ).unwrap())
        );
        assert_eq!(
            Rsync::from_str(
                "rsync://host/module/foo"
            ).unwrap().parent(),
            Some(Rsync::from_str(
                "rsync://host/module/"
            ).unwrap())
        );
        assert!(
            Rsync::from_str(
                "rsync://host/module/"
            ).unwrap().parent().is_none()
        );
        assert!(
            Rsync::from_str(
                "rsync://host/module/foo/"
            ).unwrap().parent().unwrap().parent().is_none()
        );
    }

    #[test]
    fn rsync_join() {
        // Append empty path
        assert_eq!(
            Rsync::from_str("rsync://host/module/").unwrap().join(
                b""
            ).unwrap().as_str(),
            "rsync://host/module/"
        );

        // Append path to URI with empty path.
        assert_eq!(
            Rsync::from_str("rsync://host/module/").unwrap().join(
                b"foo"
            ).unwrap().as_str(),
            "rsync://host/module/foo"
        );
        assert_eq!(
            Rsync::from_str("rsync://host/module/").unwrap().join(
                b"foo/"
            ).unwrap().as_str(),
            "rsync://host/module/foo/"
        );
        assert_eq!(
            Rsync::from_str("rsync://host/module/").unwrap().join(
                b"foo/bar"
            ).unwrap().as_str(),
            "rsync://host/module/foo/bar"
        );

        // Append path to URI with non-empty path not ending in a slash.
        assert_eq!(
            Rsync::from_str("rsync://host/module/some").unwrap().join(
                b"foo"
            ).unwrap().as_str(),
            "rsync://host/module/some/foo"
        );
        assert_eq!(
            Rsync::from_str("rsync://host/module/some").unwrap().join(
                b"foo/"
            ).unwrap().as_str(),
            "rsync://host/module/some/foo/"
        );
        assert_eq!(
            Rsync::from_str("rsync://host/module/some").unwrap().join(
                b"foo/bar"
            ).unwrap().as_str(),
            "rsync://host/module/some/foo/bar"
        );

        // Append path to URI with non-empty path ending in a slash.
        assert_eq!(
            Rsync::from_str("rsync://host/module/some/").unwrap().join(
                b"foo"
            ).unwrap().as_str(),
            "rsync://host/module/some/foo"
        );
        assert_eq!(
            Rsync::from_str("rsync://host/module/some/").unwrap().join(
                b"foo/"
            ).unwrap().as_str(),
            "rsync://host/module/some/foo/"
        );
        assert_eq!(
            Rsync::from_str("rsync://host/module/some/").unwrap().join(
                b"foo/bar"
            ).unwrap().as_str(),
            "rsync://host/module/some/foo/bar"
        );

        // Error cases
        assert!(
            Rsync::from_str("rsync://host/module/").unwrap().join(
                b"."
            ).is_err()
        );
        assert!(
            Rsync::from_str("rsync://host/module/").unwrap().join(
                b"foo/."
            ).is_err()
        );
        assert!(
            Rsync::from_str("rsync://host/module/").unwrap().join(
                b".."
            ).is_err()
        );
        assert!(
            Rsync::from_str("rsync://host/module/").unwrap().join(
                b"foo/../bar"
            ).is_err()
        );
        assert!(
            Rsync::from_str("rsync://host/module/").unwrap().join(
                b"../bar"
            ).is_err()
        );
        assert!(
            Rsync::from_str("rsync://host/module/").unwrap().join(
                b"/bar"
            ).is_err()
        );
    }

    #[test]
    fn rsync_relative_to() {
        let m = Rsync::from_str("rsync://host/module/").unwrap();
        let m_a = Rsync::from_str("rsync://host/module/a").unwrap();
        let m_a_ = Rsync::from_str("rsync://host/module/a/").unwrap();
        let m_ab = Rsync::from_str("rsync://host/module/ab").unwrap();
        let m_ab_ = Rsync::from_str("rsync://host/module/ab/").unwrap();
        let m_a_b = Rsync::from_str("rsync://host/module/a/b").unwrap();
        let m_a_b_ = Rsync::from_str("rsync://host/module/a/b/").unwrap();
        let m_a_c = Rsync::from_str("rsync://host/module/a/c").unwrap();
        let m_a_c_ = Rsync::from_str("rsync://host/module/a/c/").unwrap();
        let m_c = Rsync::from_str("rsync://host/module/c").unwrap();
        let m_c_ = Rsync::from_str("rsync://host/module/c/").unwrap();
        let m2 = Rsync::from_str("rsync://host/mod_b/").unwrap();
        let m2_a_b = Rsync::from_str("rsync://host/mod_b/a/b").unwrap();

        assert_eq!(m.relative_to(&m), Some(""));
        assert_eq!(m.relative_to(&m_a), None);
        assert_eq!(m.relative_to(&m_a_b_), None);
        assert_eq!(m.relative_to(&m2), None);

        assert_eq!(m_a.relative_to(&m), Some("a"));
        assert_eq!(m_a.relative_to(&m_a), Some(""));
        assert_eq!(m_a.relative_to(&m_a_), Some(""));
        assert_eq!(m_a.relative_to(&m_a_b), None);
        assert_eq!(m_a.relative_to(&m_ab), None);
        assert_eq!(m_a.relative_to(&m_a_b_), None);
        assert_eq!(m_a.relative_to(&m_c), None);
        assert_eq!(m_a.relative_to(&m_c_), None);
        assert_eq!(m_a.relative_to(&m2), None);

        assert_eq!(m_a_.relative_to(&m), Some("a/"));
        assert_eq!(m_a_.relative_to(&m_a), Some(""));
        assert_eq!(m_a_.relative_to(&m_a_), Some(""));
        assert_eq!(m_a_.relative_to(&m_a_b), None);
        assert_eq!(m_a_.relative_to(&m_ab), None);
        assert_eq!(m_a_.relative_to(&m_a_b_), None);
        assert_eq!(m_a_.relative_to(&m_c), None);
        assert_eq!(m_a_.relative_to(&m_c_), None);
        assert_eq!(m_a_.relative_to(&m2), None);

        assert_eq!(m_ab.relative_to(&m_a), None);
        assert_eq!(m_ab.relative_to(&m_a_), None);
        assert_eq!(m_ab.relative_to(&m_a_b), None);

        assert_eq!(m_ab_.relative_to(&m_a), None);
        assert_eq!(m_ab_.relative_to(&m_a_), None);
        assert_eq!(m_ab_.relative_to(&m_a_b), None);

        assert_eq!(m_a_b.relative_to(&m), Some("a/b"));
        assert_eq!(m_a_b.relative_to(&m_a), Some("b"));
        assert_eq!(m_a_b.relative_to(&m_a_), Some("b"));
        assert_eq!(m_a_b.relative_to(&m_a_b_), Some(""));
        assert_eq!(m_a_b.relative_to(&m_a_b), Some(""));
        assert_eq!(m_a_b.relative_to(&m_ab), None);
        assert_eq!(m_a_b.relative_to(&m_ab_), None);
        assert_eq!(m_a_b.relative_to(&m_a_c), None);
        assert_eq!(m_a_b.relative_to(&m_a_c_), None);
        assert_eq!(m_a_b.relative_to(&m_c), None);
        assert_eq!(m_a_b.relative_to(&m_c_), None);
        assert_eq!(m_a_b.relative_to(&m2), None);
        assert_eq!(m_a_b.relative_to(&m2_a_b), None);

        assert_eq!(m_a_b_.relative_to(&m), Some("a/b/"));
        assert_eq!(m_a_b_.relative_to(&m_a), Some("b/"));
        assert_eq!(m_a_b_.relative_to(&m_a_), Some("b/"));
        assert_eq!(m_a_b_.relative_to(&m_a_b_), Some(""));
        assert_eq!(m_a_b_.relative_to(&m_a_b), Some(""));
        assert_eq!(m_a_b_.relative_to(&m_ab), None);
        assert_eq!(m_a_b_.relative_to(&m_ab_), None);
        assert_eq!(m_a_b_.relative_to(&m_a_c), None);
        assert_eq!(m_a_b_.relative_to(&m_a_c_), None);
        assert_eq!(m_a_b_.relative_to(&m_c), None);
        assert_eq!(m_a_b_.relative_to(&m_c_), None);
        assert_eq!(m_a_b_.relative_to(&m2), None);
        assert_eq!(m_a_b_.relative_to(&m2_a_b), None);
    }

    #[test]
    fn rsync_is_parent_of() {
        // As long as is_parent_is is implemented in terms of relative_to,
        // we can keep this short.
        let m = Rsync::from_str("rsync://host/module/").unwrap();
        let m_a = Rsync::from_str("rsync://host/module/a").unwrap();
        let m_a_b = Rsync::from_str("rsync://host/module/a/b").unwrap();
        let m2_a_b = Rsync::from_str("rsync://host/mod_b/a/b").unwrap();

        assert!(!m.is_parent_of(&m));
        assert!( m.is_parent_of(&m_a));
        assert!( m.is_parent_of(&m_a_b));
        assert!(!m.is_parent_of(&m2_a_b));
        assert!(!m_a.is_parent_of(&m));
        assert!(!m_a.is_parent_of(&m_a));
        assert!( m_a.is_parent_of(&m_a_b));
        assert!(!m_a.is_parent_of(&m2_a_b));
        assert!(!m_a_b.is_parent_of(&m));
        assert!(!m_a_b.is_parent_of(&m_a));
        assert!(!m_a_b.is_parent_of(&m_a_b));
        assert!(!m_a_b.is_parent_of(&m2_a_b));
        assert!(!m2_a_b.is_parent_of(&m));
        assert!(!m2_a_b.is_parent_of(&m_a));
        assert!(!m2_a_b.is_parent_of(&m_a_b));
        assert!(!m2_a_b.is_parent_of(&m2_a_b));
    }

    #[test]
    fn rsync_partial_eq() {
        assert_eq!(
            Rsync::from_str("rsync://host/module/").unwrap(),
            "rsync://host/module/"
        );
        assert_eq!(
            Rsync::from_str("rsyNc://hOst/module/").unwrap(),
            "rsync://host/module/"
        );

        assert_eq!(
            Rsync::from_str("rsync://host/module/path").unwrap(),
            "rsync://host/module/path"
        );
        assert_eq!(
            Rsync::from_str("rsyNc://hOst/module/path").unwrap(),
            "rsync://host/module/path"
        );
        assert_ne!(
            Rsync::from_str("rsync://host/module/pAth").unwrap(),
            "rsync://host/module/path"
        );
    }

    #[test]
    fn rsync_hash() {
        fn hash(uri: &str) -> u64 {
            use std::hash::{Hash, Hasher};

            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            Rsync::from_str(uri).unwrap().hash(&mut hasher);
            hasher.finish()
        }

        assert_eq!(
            hash("rsync://host/module/"),
            hash("rsync://host/module/")
        );
        assert_eq!(
            hash("rsyNc://hOst/module/"),
            hash("rsync://host/module/")
        );
        assert_eq!(
            hash("rsync://host/module/path"),
            hash("rsync://host/module/path")
        );
        assert_eq!(
            hash("rsyNc://hOst/module/path"),
            hash("rsync://host/module/path")
        );
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
        let base_uri_no_trailing_slash = Https::from_str(
            "https://example.com/some"
        ).unwrap();
        let base_uri_trailing_slash = Https::from_str(
            "https://example.com/some/"
        ).unwrap();
        let sub = "sub/".as_bytes();

        let expected = Https::from_str(
            "https://example.com/some/sub/"
        ).unwrap();

        assert_eq!(base_uri_no_trailing_slash.join(sub).unwrap(), expected);
        assert_eq!(base_uri_trailing_slash.join(sub).unwrap(), expected);
    }

    #[test]
    fn https_parent() {
        let base_uri = Https::from_str(
            "https://example.com/"
        ).unwrap();

        assert!(base_uri.parent().is_none());

        let uri_one_level = Https::from_str(
            "https://example.com/1/"
        ).unwrap();

        let uri_base_no_trail = Https::from_str(
            "https://example.com/foo"
        ).unwrap();

        assert_eq!(uri_one_level.parent().unwrap(), base_uri);
        assert_eq!(uri_base_no_trail.parent().unwrap(), base_uri);

        let uri_one_level_no_trail = Https::from_str(
            "https://example.com/1/foo"
        ).unwrap();

        let uri_two_level = Https::from_str(
            "https://example.com/1/2/"
        ).unwrap();

        assert_eq!(uri_one_level_no_trail.parent().unwrap(), uri_one_level);
        assert_eq!(uri_two_level.parent().unwrap(), uri_one_level);
    }
}
