//! Trust Anchor Locators

use std::{fmt, str};
use std::cmp::Ordering;
use std::convert::{Infallible, TryFrom};
use std::fs::{read_dir, DirEntry, File, ReadDir};
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;
use bytes::Bytes;
use bcder::decode;
use bcder::decode::IntoSource;
use log::{debug, error};
use crate::uri;
use crate::crypto::PublicKey;
use crate::util::base64;


//------------ Tal -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Tal {
    uris: Vec<TalUri>,
    key_info: PublicKey,
    info: Arc<TalInfo>,
}

impl Tal {
    pub fn read_dir<P: AsRef<Path>>(path: P) -> Result<TalIter, io::Error> {
        read_dir(path).map(TalIter)
    }

    pub fn read<P: AsRef<Path>, R: Read>(
        path: P,
        reader: &mut R
    ) -> Result<Self, ReadError> {
        Self::read_named(
            path.as_ref().file_stem()
                .expect("TAL path needs to have a file name")
                .to_string_lossy().into_owned(),
            reader
        )
    }

    pub fn read_named<R: Read>(
        name: String,
        reader: &mut R
    ) -> Result<Self, ReadError> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        let mut data = data.as_slice();
        let mut uris = Vec::new();
        while let Some(&b'#') = data.first() {
            Self::skip_line(&mut data)?;
        }
        while let Some(uri) = Self::take_uri(&mut data)? {
            uris.push(uri)
        }
        let data: Vec<_> = data.iter().filter_map(|b|
            if b.is_ascii_whitespace() { None }
            else { Some(*b) }
        ).collect();
        let key_info = base64::Xml.decode_bytes(&data)?;
        let key_info = PublicKey::decode(key_info.as_slice().into_source())?;
        Ok(Tal {
            uris,
            key_info,
            info: Arc::new(TalInfo::from_name(name))
        })
    }

    /// Reorders the TAL URIs placing HTTPS URIs first.
    ///
    /// The method keeps the order within each scheme.
    pub fn prefer_https(&mut self) {
        self.uris.sort_by(|left, right| {
            match (left.is_https(), right.is_https()) {
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => Ordering::Equal
            }
        })
    }

    fn skip_line(data: &mut &[u8]) -> Result<(), ReadError> {
        let mut split = data.splitn(2, |&ch| ch == b'\n');
        let _ = split.next().ok_or(ReadError::UnexpectedEof)?;
        *data = split.next().ok_or(ReadError::UnexpectedEof)?;
        Ok(())
    }

    fn take_uri(data: &mut &[u8]) -> Result<Option<TalUri>, ReadError> {
        let mut split = data.splitn(2, |&ch| ch == b'\n');
        let mut line = split.next().ok_or(ReadError::UnexpectedEof)?;
        *data = split.next().ok_or(ReadError::UnexpectedEof)?;
        if line.ends_with(b"\r") {
            line = line.split_last().unwrap().1;
        }
        if line.is_empty() {
            Ok(None)
        }
        else {
            Ok(Some(TalUri::from_slice(line)?))
        }
    }
}

impl Tal {
    pub fn uris(&self) -> ::std::slice::Iter<TalUri> {
        self.uris.iter()
    }

    pub fn key_info(&self) -> &PublicKey {
        &self.key_info
    }

    pub fn info(&self) -> &Arc<TalInfo> {
        &self.info
    }
}


//------------ TalIter -------------------------------------------------------

pub struct TalIter(ReadDir);

impl Iterator for TalIter {
    type Item = Result<Tal, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.0.next() {
                Some(Ok(entry)) => {
                    match next_entry(&entry) {
                        Ok(Some(res)) => return Some(Ok(res)),
                        Ok(None) => { },
                        Err(err) => {
                            error!("Bad trust anchor {}", err);
                            return Some(Err(err))
                        }
                    }
                }
                Some(Err(err)) => return Some(Err(err.into())),
                None => return None
            };
        }
    }
}

fn next_entry(entry: &DirEntry) -> Result<Option<Tal>, ReadError> {
    if !entry.file_type()?.is_file() {
        return Ok(None)
    }
    let path = entry.path();
    debug!("Processing TAL {}", path.display());
    Tal::read(&path, &mut File::open(&path)?).map(Some)
}


//------------ TalUri --------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TalUri {
    Rsync(uri::Rsync),
    Https(uri::Https),
}

impl TalUri {
    pub fn from_string(s: String) -> Result<Self, uri::Error> {
        Self::from_bytes(Bytes::from(s))
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, uri::Error> {
        Self::from_bytes(Bytes::copy_from_slice(slice))
    }

    pub fn from_bytes(bytes: Bytes) -> Result<Self, uri::Error> {
        if let Ok(uri) = uri::Rsync::from_bytes(bytes.clone()) {
            return Ok(TalUri::Rsync(uri))
        }
        uri::Https::from_bytes(bytes).map(Into::into)
    }

    pub fn is_rsync(&self) -> bool {
        matches!(*self, TalUri::Rsync(_))
    }

    pub fn is_https(&self) -> bool {
        matches!(*self, TalUri::Https(_))
    }

    pub fn as_str(&self) -> &str {
        match *self {
            TalUri::Rsync(ref inner) => inner.as_str(),
            TalUri::Https(ref inner) => inner.as_str(),
        }
    }
}


//--- From

impl From<uri::Rsync> for TalUri {
    fn from(uri: uri::Rsync) -> Self {
        TalUri::Rsync(uri)
    }
}

impl From<uri::Https> for TalUri {
    fn from(uri: uri::Https) -> Self {
        TalUri::Https(uri)
    }
}


//--- TryFrom and FromStr

impl TryFrom<String> for TalUri {
    type Error = uri::Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_string(s)
    }
}

impl str::FromStr for TalUri {
    type Err = uri::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(Bytes::copy_from_slice(s.as_ref()))
    }
}


//--- Display

impl fmt::Display for TalUri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TalUri::Rsync(ref uri) => uri.fmt(f),
            TalUri::Https(ref uri) => uri.fmt(f)
        }
    }
}


//------------ TalInfo -------------------------------------------------------

#[derive(Clone, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct TalInfo {
    name: String,
}

impl TalInfo {
    pub fn from_name(name: String) -> Self {
        TalInfo { name }
    }

    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }
}


//------------ ReadError -----------------------------------------------------

#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    UnexpectedEof,
    BadUri(uri::Error),
    BadKeyInfoEncoding(base64::XmlDecodeError),
    BadKeyInfo(decode::DecodeError<Infallible>),
}

impl From<io::Error> for ReadError {
    fn from(err: io::Error) -> ReadError {
        ReadError::Io(err)
    }
}

impl From<uri::Error> for ReadError {
    fn from(err: uri::Error) -> ReadError {
        ReadError::BadUri(err)
    }
}

impl From<base64::XmlDecodeError> for ReadError {
    fn from(err: base64::XmlDecodeError) -> ReadError {
        ReadError::BadKeyInfoEncoding(err)
    }
}

impl From<decode::DecodeError<Infallible>> for ReadError {
    fn from(err: decode::DecodeError<Infallible>) -> ReadError {
        ReadError::BadKeyInfo(err)
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ReadError::Io(ref err) => err.fmt(f),
            ReadError::UnexpectedEof
                => f.write_str("unexpected end of file"),
            ReadError::BadUri(ref err)
                => write!(f, "bad trust anchor URI: {}", err),
            ReadError::BadKeyInfoEncoding(ref err)
                => write!(f, "bad key info: {}", err),
            ReadError::BadKeyInfo(ref err)
                => write!(f, "bad key info: {}", err),
        }
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use bytes::Bytes;
    use crate::repository::cert::Cert;
    use super::*;

    #[test]
    fn tal_read() {
        let tal = include_bytes!("../../test-data/repository/ripe.tal");
        let tal = Tal::read("ripe.tal", &mut tal.as_ref()).unwrap();
        let cert = Cert::decode(Bytes::from_static(
            include_bytes!("../../test-data/repository/ta.cer")
        )).unwrap();
        assert_eq!(
            tal.key_info(),
            cert.subject_public_key_info(),
        );
    }

    #[test]
    fn prefer_https() {
        let tal = include_bytes!("../../test-data/repository/ripe.tal");
        let mut tal = Tal::read("ripe.tal", &mut tal.as_ref()).unwrap();
        tal.uris = vec![
            TalUri::from_slice(b"rsync://a.example.com/1/1").unwrap(),
            TalUri::from_slice(b"https://d.example.com/1/1").unwrap(),
            TalUri::from_slice(b"rsync://k.example.com/2/1").unwrap(),
            TalUri::from_slice(b"https://2.example.com/2/1").unwrap(),
            TalUri::from_slice(b"https://i.example.com/3/1").unwrap(),
            TalUri::from_slice(b"rsync://g.example.com/3/1").unwrap(),
            TalUri::from_slice(b"https://r.example.com/4/1").unwrap(),
        ];
        tal.prefer_https();

        assert_eq!(
            tal.uris,
            vec![
                TalUri::from_slice(b"https://d.example.com/1/1").unwrap(),
                TalUri::from_slice(b"https://2.example.com/2/1").unwrap(),
                TalUri::from_slice(b"https://i.example.com/3/1").unwrap(),
                TalUri::from_slice(b"https://r.example.com/4/1").unwrap(),
                TalUri::from_slice(b"rsync://a.example.com/1/1").unwrap(),
                TalUri::from_slice(b"rsync://k.example.com/2/1").unwrap(),
                TalUri::from_slice(b"rsync://g.example.com/3/1").unwrap(),
            ]
        );
    }
}
