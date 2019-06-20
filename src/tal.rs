//! Trust Anchor Locators

use std::fs::{read_dir, DirEntry, File, ReadDir};
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;
use base64;
use bcder::decode;
use derive_more::Display;
use log::{debug, error};
use crate::crypto::PublicKey;
use super::uri;


//------------ Tal -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Tal {
    uris: Vec<uri::Rsync>,
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
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        if let Some(&b'#') = data.first() {
            // Workaround for ARIN: If the TAL starts with a hash, it is
            // followed by a URI where to go to get it. We print out a
            // text and terminate.
            let data = String::from_utf8_lossy(&data[1..]);
            let path = path.as_ref().display();
            match data.lines().next().map(|s| s.trim()) {
                Some(uri) => {
                    eprintln!("MISSING TRUST ANCHOR LOCATOR\n\n\
                        The trust anchor locator (TAL) in \
                        file\n\n   {}\n\nhas not been installed. \
                        Please go to\n\n   {}\n\nand download the TAL \
                        in RFC 7730 format. Place the downloaded file \
                        at\n\n   {}\n\n\
                        Routinator will refuse to run until you have done \
                        that.",
                        path, uri, path
                    );
                }
                None => {
                    eprintln!("MISSING TRUST ANCHOR LOCATOR\
                        The trust anchor locator (TAL) in file {} has not\
                        been installed.\n\
                        Unfortunately, the file is malformed and we cannot \
                        tell you where to get it.\n
                        The file will have to contain a valid TAL in RFC \
                        7730 format.\n\n
                        Routinator will refuse to run until it does. Sorry.",
                        path
                    );
                }
            }
            ::std::process::exit(1);
        }
        
        let mut data = data.as_ref();
        let mut uris = Vec::new();
        while let Some(uri) = Self::take_uri(&mut data)? {
            uris.push(uri)
        }
        let data: Vec<_> = data.iter().filter_map(|b|
            if b.is_ascii_whitespace() { None }
            else { Some(*b) }
        ).collect();
        let key_info = base64::decode(&data)?;
        let key_info = PublicKey::decode(key_info.as_ref())?;
        Ok(Tal {
            uris,
            key_info,
            info: Arc::new(TalInfo::from_path(path))
        })
    }

    fn take_uri(data: &mut &[u8]) -> Result<Option<uri::Rsync>, ReadError> {
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
            Ok(Some(uri::Rsync::from_slice(line)?))
        }
    }
}

impl Tal {
    pub fn uris(&self) -> ::std::slice::Iter<uri::Rsync> {
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


//------------ TalInfo -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct TalInfo {
    name: String,
}

impl TalInfo {
    fn from_path<P: AsRef<Path>>(path: P) -> Self {
        TalInfo::from_name(
            path.as_ref().file_stem()
                .expect("TAL path needs to have a file name")
                .to_string_lossy().into_owned()
        )
    }

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

#[derive(Debug, Display)]
pub enum ReadError {
    #[display(fmt="{}", _0)]
    Io(io::Error),

    #[display(fmt="unexpected end of file")]
    UnexpectedEof,

    #[display(fmt="bad trunst anchor URI: {}", _0)]
    BadUri(uri::Error),

    #[display(fmt="bad key info: {}", _0)]
    BadKeyInfoEncoding(base64::DecodeError),

    #[display(fmt="bad key info: {}", _0)]
    BadKeyInfo(decode::Error),
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

impl From<base64::DecodeError> for ReadError {
    fn from(err: base64::DecodeError) -> ReadError {
        ReadError::BadKeyInfoEncoding(err)
    }
}

impl From<decode::Error> for ReadError {
    fn from(err: decode::Error) -> ReadError {
        ReadError::BadKeyInfo(err)
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use bytes::Bytes;
    use unwrap::unwrap;
    use crate::cert::Cert;
    use super::*;

    #[test]
    fn tal_read() {
        let tal = include_bytes!("../test-data/ripe.tal");
        let tal = unwrap!(Tal::read("ripe.tal", &mut tal.as_ref()));
        let cert = unwrap!(Cert::decode(Bytes::from_static(
            include_bytes!("../test-data/ta.cer")
        )));
        assert_eq!(
            tal.key_info(),
            cert.subject_public_key_info(),
        );
    }
}
