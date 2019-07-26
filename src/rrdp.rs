//! Parsing the XML representations.

use std::{fmt, io, ops, str};
use bytes::Bytes;
use ring::digest;
use uuid::Uuid;
use crate::uri;
use crate::xml::decode::{Reader, Name, Error};


//------------ NotificationFile ----------------------------------------------

pub struct NotificationFile {
    pub session_id: Uuid,
    pub serial: usize,
    pub snapshot: UriAndHash,
    pub deltas: Vec<(usize, UriAndHash)>,
}

impl NotificationFile {
    pub fn parse<R: io::BufRead>(reader: R) -> Result<Self, Error> {
        let mut reader = Reader::new(reader);

        let mut session_id = None;
        let mut serial = None;
        let mut outer = reader.start(|element| {
            if element.name() != NOTIFICATION {
                return Err(Error::Malformed)
            }

            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<u8>()? != 1 {
                        return Err(Error::Malformed)
                    }
                    Ok(())
                }
                b"session_id" => {
                    session_id = Some(value.ascii_into()?);
                    Ok(())
                }
                b"serial" => {
                    serial = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => Err(Error::Malformed)
            })
        })?;

        let mut snapshot = None;
        let mut deltas = Vec::new();
        while let Some(mut content) = outer.take_opt_element(&mut reader,
                                                             |element| {
            match element.name() {
                SNAPSHOT => {
                    if snapshot.is_some() {
                        return Err(Error::Malformed)
                    }
                    let mut uri = None;
                    let mut hash = None;
                    element.attributes(|name, value| match name {
                        b"uri" => {
                            uri = Some(value.ascii_into()?);
                            Ok(())
                        }
                        b"hash" => {
                            hash = Some(value.ascii_into()?);
                            Ok(())
                        }
                        _ => Err(Error::Malformed)
                    })?;
                    match (uri, hash) {
                        (Some(uri), Some(hash)) => {
                            snapshot = Some(UriAndHash::new(uri, hash));
                            Ok(())
                        }
                        _ => Err(Error::Malformed)
                    }
                }
                DELTA => {
                    let mut serial = None;
                    let mut uri = None;
                    let mut hash = None;
                    element.attributes(|name, value| match name {
                        b"serial" => {
                            serial = Some(value.ascii_into()?);
                            Ok(())
                        }
                        b"uri" => {
                            uri = Some(value.ascii_into()?);
                            Ok(())
                        }
                        b"hash" => {
                            hash = Some(value.ascii_into()?);
                            Ok(())
                        }
                        _ => Err(Error::Malformed)
                    })?;
                    match (serial, uri, hash) {
                        (Some(serial), Some(uri), Some(hash)) => {
                            deltas.push((serial, UriAndHash::new(uri, hash)));
                            Ok(())
                        }
                        _ => Err(Error::Malformed)
                    }
                }
                _ => Err(Error::Malformed)
            }
        })? {
            content.take_end(&mut reader)?;
        }

        outer.take_end(&mut reader)?;
        reader.end()?;

        match (session_id, serial, snapshot) {
            (Some(session_id), Some(serial), Some(snapshot)) => {
                Ok(NotificationFile { session_id, serial, snapshot, deltas })
            }
            _ => Err(Error::Malformed)
        }
    }
}


//------------ ProcessSnapshot -----------------------------------------------

pub trait ProcessSnapshot {
    type Err: From<Error>;

    fn meta(
        &mut self,
        session_id: Uuid,
        serial: usize
    ) -> Result<(), Self::Err>;

    fn publish(
        &mut self,
        uri: uri::Rsync,
        data: Vec<u8>,
    ) -> Result<(), Self::Err>;

    fn process<R: io::BufRead>(
        &mut self,
        reader: R
    ) -> Result<(), Self::Err> {
        let mut reader = Reader::new(reader);
        
        let mut session_id = None;
        let mut serial = None;
        let mut outer = reader.start(|element| {
            if element.name() != SNAPSHOT {
                return Err(Error::Malformed)
            }
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<u8>()? != 1 {
                        return Err(Error::Malformed)
                    }
                    Ok(())
                }
                b"session_id" => {
                    session_id = Some(value.ascii_into()?);
                    Ok(())
                }
                b"serial" => {
                    serial = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => Err(Error::Malformed)
            })
        })?;

        match (session_id, serial) {
            (Some(session_id), Some(serial)) => {
                self.meta(session_id, serial)?;
            }
            _ => return Err(Error::Malformed.into()),
        }

        loop {
            let mut uri = None;
            let inner = outer.take_opt_element(&mut reader, |element| {
                if element.name() != PUBLISH {
                    return Err(Error::Malformed)
                }
                element.attributes(|name, value| match name {
                    b"uri" => {
                        uri = Some(value.ascii_into()?);
                        Ok(())
                    }
                    _ => Err(Error::Malformed)
                })
            })?;
            let mut inner = match inner {
                Some(inner) => inner,
                None => break
            };
            let uri = match uri {
                Some(uri) => uri,
                None => return Err(Error::Malformed.into())
            };
            let data = inner.take_text(&mut reader, |text| {
                base64::decode(text.to_ascii()?.as_ref())
                    .map_err(|_| Error::Malformed)
            })?;
            self.publish(uri, data)?;
            inner.take_end(&mut reader)?;
        }

        outer.take_end(&mut reader)?;
        reader.end()?;
        Ok(())
    }
}


//------------ ProcessDelta --------------------------------------------------

pub trait ProcessDelta {
    type Err: From<Error>;

    fn meta(
        &mut self,
        session_id: Uuid,
        serial: usize
    ) -> Result<(), Self::Err>;

    fn publish(
        &mut self,
        uri: uri::Rsync,
        hash: Option<Bytes>,
        data: Vec<u8>,
    ) -> Result<(), Self::Err>;

    fn withdraw(
        &mut self,
        uri: uri::Rsync,
        hash: Bytes,
    ) -> Result<(), Self::Err>;


    fn process<R: io::BufRead>(
        &mut self,
        reader: R
    ) -> Result<(), Self::Err> {
        let mut reader = Reader::new(reader);
        
        let mut session_id = None;
        let mut serial = None;
        let mut outer = reader.start(|element| {
            if element.name() != DELTA {
                return Err(Error::Malformed)
            }
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<u8>()? != 1 {
                        return Err(Error::Malformed)
                    }
                    Ok(())
                }
                b"session_id" => {
                    session_id = Some(value.ascii_into()?);
                    Ok(())
                }
                b"serial" => {
                    serial = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => Err(Error::Malformed)
            })
        })?;

        match (session_id, serial) {
            (Some(session_id), Some(serial)) => {
                self.meta(session_id, serial)?;
            }
            _ => return Err(Error::Malformed.into()),
        }

        loop {
            let mut action = None;
            let mut uri = None;
            let mut hash = None;
            let inner = outer.take_opt_element(&mut reader, |element| {
                match element.name() {
                    PUBLISH => action = Some(Action::Publish),
                    WITHDRAW => action = Some(Action::Withdraw),
                    _ => return Err(Error::Malformed),
                };
                element.attributes(|name, value| match name {
                    b"uri" => {
                        uri = Some(value.ascii_into()?);
                        Ok(())
                    }
                    b"hash" => {
                        hash = Some(value.into_ascii_bytes()?);
                        Ok(())
                    }
                    _ => Err(Error::Malformed)
                })
            })?;
            let mut inner = match inner {
                Some(inner) => inner,
                None => break
            };
            let uri = match uri {
                Some(uri) => uri,
                None => return Err(Error::Malformed.into())
            };
            match action.unwrap() { // Or we'd have exited already.
                Action::Publish => {
                    let data = inner.take_text(&mut reader, |text| {
                        base64::decode(text.to_ascii()?.as_ref())
                            .map_err(|_| Error::Malformed)
                    })?;
                    self.publish(uri, hash, data)?;
                }
                Action::Withdraw => {
                    let hash = match hash {
                        Some(hash) => hash,
                        None => return Err(Error::Malformed.into())
                    };
                    self.withdraw(uri, hash)?;
                }
            }
            inner.take_end(&mut reader)?;
        }
        outer.take_end(&mut reader)?;
        reader.end()?;
        Ok(())
    }

}


//------------ UriAndHash ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct UriAndHash {
    uri: uri::Https,
    hash: DigestHex,
}

impl UriAndHash {
    pub fn new(uri: uri::Https, hash: DigestHex) -> Self {
        UriAndHash { uri, hash }
    }

    pub fn uri(&self) -> &uri::Https {
        &self.uri
    }

    pub fn hash(&self) -> &DigestHex {
        &self.hash
    }
}


//------------ DigestHex -----------------------------------------------------

/// A helper type to encode a digest as a sequence of hex-digits.
#[derive(Clone, Debug)]
pub struct DigestHex(Vec<u8>);

impl From<Vec<u8>> for DigestHex {
    fn from(value: Vec<u8>) -> DigestHex {
        DigestHex(value)
    }
}

impl From<digest::Digest> for DigestHex {
    fn from(value: digest::Digest) -> DigestHex {
        DigestHex(Vec::from(value.as_ref()))
    }
}

impl str::FromStr for DigestHex {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = Vec::new();
        let mut s = s.chars();
        while let Some(first) = s.next() {
            let first = first.to_digit(16).ok_or("invalid digest")?;
            let second = s.next().ok_or("invalid digest")?
                .to_digit(16).ok_or("invalid digest")?;

            res.push((first << 4 | second) as u8);
        }
        Ok(DigestHex(res))
    }
}

impl ops::Deref for DigestHex {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for DigestHex {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Display for DigestHex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.0.as_slice() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}


//------------ Action --------------------------------------------------------

enum Action {
    Publish,
    Withdraw,
}


//------------ Xml Names -----------------------------------------------------

const NS: &[u8] = b"http://www.ripe.net/rpki/rrdp";
const NOTIFICATION: Name = Name::qualified(NS, b"notification");
const SNAPSHOT: Name = Name::qualified(NS, b"snapshot");
const DELTA: Name = Name::qualified(NS, b"delta");
const PUBLISH: Name = Name::qualified(NS, b"publish");
const WITHDRAW: Name = Name::qualified(NS, b"withdraw");


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    pub struct Test;

    impl ProcessSnapshot for Test {
        type Err = Error;

        fn meta(
            &mut self,
            _session_id: Uuid,
            _serial: usize
        ) -> Result<(), Self::Err> {
            Ok(())
        }

        fn publish(
            &mut self,
            _uri: uri::Rsync,
            _data: Vec<u8>,
        ) -> Result<(), Self::Err> {
            Ok(())
        }
    }

    impl ProcessDelta for Test {
        type Err = Error;

        fn meta(
            &mut self,
            _session_id: Uuid,
            _serial: usize
        ) -> Result<(), Self::Err> {
            Ok(())
        }

        fn publish(
            &mut self,
            _uri: uri::Rsync,
            _hash: Option<Bytes>,
            _data: Vec<u8>,
        ) -> Result<(), Self::Err> {
            Ok(())
        }

        fn withdraw(
            &mut self,
            _uri: uri::Rsync,
            _hash: Bytes,
        ) -> Result<(), Self::Err> {
            Ok(())
        }
    }

    #[test]
    fn ripe_notification() {
        NotificationFile::parse(
            include_bytes!("../test-data/ripe-notification.xml").as_ref()
        ).unwrap();
    }

    #[test]
    fn ripe_snapshot() {
        <Test as ProcessSnapshot>::process(
            &mut Test,
            include_bytes!("../test-data/ripe-snapshot.xml").as_ref()
        ).unwrap();
    }

    #[test]
    fn ripe_delta() {
        <Test as ProcessDelta>::process(
            &mut Test,
            include_bytes!("../test-data/ripe-delta.xml").as_ref()
        ).unwrap();
    }
}
