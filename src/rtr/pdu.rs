//! Raw protocol data.
//!
//! This module contains types that represent the protocol data units of
//! RTR in their wire representation. That is, these types can be given to
//! read and write operations as buffers.  See section 5 of RFC 6810 and
//! RFC 8210. Annoyingly, the format of the `EndOfData` PDU changes between
//! the two versions.

use std::{io, mem, slice};
use std::convert::TryFrom;
use std::marker::Unpin;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use bytes::Bytes;
use routecore::addr::{MaxLenPrefix, Prefix};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt
};
use super::payload;
use super::state::{Serial, State};


//------------ Macro for Common Impls ----------------------------------------

macro_rules! common {
    ( $type:ident ) => {
        #[allow(dead_code)]
        impl $type {
            /// Writes a value to a writer.
            pub async fn write<A: AsyncWrite + Unpin>(
                &self,
                a: &mut A
            ) -> Result<(), io::Error> {
                a.write_all(self.as_ref()).await
            }
        }

        impl AsRef<[u8]> for $type {
            fn as_ref(&self) -> &[u8] {
                unsafe {
                    slice::from_raw_parts(
                        self as *const Self as *const u8,
                        mem::size_of::<Self>()
                    )
                }
            }
        }

        impl AsMut<[u8]> for $type {
            fn as_mut(&mut self) -> &mut [u8] {
                unsafe {
                    slice::from_raw_parts_mut(
                        self as *mut Self as *mut u8,
                        mem::size_of::<Self>()
                    )
                }
            }
        }
    }
}

macro_rules! concrete {
    ( $type:ident ) => {
        common!($type);

        #[allow(dead_code)]
        impl $type {
            /// Returns the value of the version field of the header.
            pub fn version(&self) -> u8 {
                self.header.version()
            }

            /// Returns the value of the session field of the header.
            ///
            /// Note that this field is used for other purposes in some PDU
            /// types.
            pub fn session(&self) -> u16 {
                self.header.session()
            }

            /// Returns the PDU size.
            ///
            /// The size is returned as a `u32` since that type is used in
            /// the header.
            pub fn size() -> u32 {
                mem::size_of::<Self>() as u32
            }

            /// Reads a value from a reader.
            ///
            /// If a value with a different PDU type is received, returns an
            /// error.
            pub async fn read<Sock: AsyncRead + Unpin>(
                sock: &mut Sock 
            ) -> Result<Self, io::Error> {
                let mut res = Self::default();
                sock.read_exact(res.header.as_mut()).await?;
                if res.header.pdu() != Self::PDU {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        concat!(
                            "PDU type mismatch when expecting ",
                            stringify!($type)
                        )
                    ))
                }
                if res.header.length() as usize != res.as_ref().len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        concat!(
                            "invalid length for ",
                            stringify!($type)
                        )
                    ))
                }
                sock.read_exact(&mut res.as_mut()[Header::LEN..]).await?;
                Ok(res)
            }

            /// Tries to read a value from a reader.
            ///
            /// If a different PDU type is received, returns the header as
            /// the error case of the ok case.
            pub async fn try_read<Sock: AsyncRead + Unpin>(
                sock: &mut Sock 
            ) -> Result<Result<Self, Header>, io::Error> {
                let mut res = Self::default();
                sock.read_exact(res.header.as_mut()).await?;
                if res.header.pdu() == Error::PDU {
                    // Since we should drop the session after an error, we
                    // can safely ignore all the rest of the error for now.
                    return Ok(Err(res.header))
                }
                if res.header.pdu() != Self::PDU {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        concat!(
                            "PDU type mismatch when expecting ",
                            stringify!($type)
                        )
                    ))
                }
                if res.header.length() as usize != res.as_ref().len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        concat!(
                            "invalid length for ",
                            stringify!($type)
                        )
                    ))
                }
                sock.read_exact(&mut res.as_mut()[Header::LEN..]).await?;
                Ok(Ok(res))
            }

            /// Reads only the payload part of a value from a reader.
            ///
            /// Assuming that the header was already read and is passed via
            /// `header`, the function reads the rest of the PUD from the
            /// reader and returns the complete value.
            pub async fn read_payload<Sock: AsyncRead + Unpin>(
                header: Header, sock: &mut Sock
            ) -> Result<Self, io::Error> {
                if header.length() as usize != mem::size_of::<Self>() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        concat!(
                            "invalid length for ",
                            stringify!($type),
                            " PDU"
                        )
                    ))
                }
                let mut res = Self::default();
                sock.read_exact(&mut res.as_mut()[Header::LEN..]).await?;
                res.header = header;
                Ok(res)
            }
        }
    }
}


//------------ SerialNotify --------------------------------------------------

/// A serial notify informs a client that a cache has new data.
#[derive(Default)]
#[repr(packed)]
#[allow(dead_code)]
pub struct SerialNotify {
    header: Header,
    serial: u32,
}

impl SerialNotify {
    /// The PDU type of a serial notify.
    pub const PDU: u8 = 0;

    /// Creates a new serial notify PDU.
    pub fn new(version: u8, state: State) -> Self {
        SerialNotify {
            header: Header::new(
                version, Self::PDU, state.session(), Self::size(),
            ),
            serial: state.serial().to_be(),
        }
    }
}

concrete!(SerialNotify);


//------------ SerialQuery ---------------------------------------------------

/// A serial query requests all updates since a router’s last update.
#[derive(Default)]
#[repr(packed)]
#[allow(dead_code)]
pub struct SerialQuery {
    header: Header,
    payload: SerialQueryPayload,
}

impl SerialQuery {
    /// The payload type of a serial query.
    pub const PDU: u8 = 1;

    /// Creates a new serial query from the given state.
    pub fn new(version: u8, state: State) -> Self {
        SerialQuery {
            header: Header::new(
                version, Self::PDU, state.session(), Self::size()
            ),
            payload: SerialQueryPayload::new(state.serial()),
        }
    }
}

concrete!(SerialQuery);


//------------ SerialQueryPayload --------------------------------------------

/// The payload of a serial query.
///
/// This the serial query PDU without the header.
#[derive(Default)]
#[repr(packed)]
pub struct SerialQueryPayload {
    serial: u32
}

impl SerialQueryPayload {
    /// Creates a new serial query payload from a serial number.
    pub fn new(serial: Serial) -> Self {
        SerialQueryPayload {
            serial: serial.to_be()
        }
    }

    /// Reads the serial query payload from a reader.
    pub async fn read<Sock: AsyncRead + Unpin>(
        sock: &mut Sock 
    ) -> Result<Self, io::Error> {
        let mut res = Self::default();
        sock.read_exact(res.as_mut()).await?;
        Ok(res)
    }

    /// Returns the router’s serial number announced in the serial query.
    pub fn serial(&self) -> Serial {
        Serial::from_be(self.serial)
    }
}

common!(SerialQueryPayload);


//------------ ResetQuery ----------------------------------------------------

/// A reset query requests the complete current set of data.
#[derive(Default)]
#[repr(packed)]
pub struct ResetQuery {
    header: Header
}

impl ResetQuery {
    /// The payload type of a reset query.
    pub const PDU: u8 = 2;

    /// Creates a new reset query.
    pub fn new(version: u8) -> Self {
        ResetQuery {
            header: Header::new(version, 2, 0, 8)
        }
    }
}

concrete!(ResetQuery);


//------------ CacheResponse -------------------------------------------------

/// The cache response starts a sequence of payload PDUs with data.
#[derive(Default)]
#[repr(packed)]
pub struct CacheResponse {
    header: Header
}

impl CacheResponse {
    /// The payload type of a cache response.
    pub const PDU: u8 = 3;

    /// Creates a new cache response for the given state.
    pub fn new(version: u8, state: State) -> Self {
        CacheResponse {
            header: Header::new(version, 3, state.session(), 8)
        }
    }
}

concrete!(CacheResponse);


//------------ Ipv4Prefix ----------------------------------------------------

/// An IPv4 prefix is the payload PDU for route origin authorisation in IPv4.
#[derive(Default)]
#[repr(packed)]
#[allow(dead_code)]
pub struct Ipv4Prefix {
    header: Header,
    flags: u8,
    prefix_len: u8,
    max_len: u8,
    zero: u8,
    prefix: u32,
    asn: u32
}

impl Ipv4Prefix {
    /// The payload type of an IPv4 prefix.
    pub const PDU: u8 = 4;

    /// Creates a new IPv4 prefix from all the various fields.
    pub fn new(
        version: u8,
        flags: u8,
        prefix_len: u8,
        max_len: u8,
        prefix: Ipv4Addr,
        asn: u32
    ) -> Self {
        Ipv4Prefix {
            header: Header::new(version, Self::PDU, 0, 20),
            flags,
            prefix_len,
            max_len,
            zero: 0,
            prefix: u32::from(prefix).to_be(),
            asn: asn.to_be()
        }
    }

    /// Returns the flags field of the prefix.
    ///
    /// The only flag currently used is the least significant but that is
    /// 1 for an announcement and 0 for a withdrawal.
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Returns the max length.
    pub fn max_len(&self) -> u8 {
        self.max_len
    }

    /// Returns the prefix as IPv4 address.
    pub fn prefix(&self) -> Ipv4Addr {
        u32::from_be(self.prefix).into()
    }

    /// Returns the autonomous system number.
    pub fn asn(&self) -> u32 {
        u32::from_be(self.asn)
    }
}

concrete!(Ipv4Prefix);


//------------ Ipv6Prefix ----------------------------------------------------

/// An IPv6 prefix is the payload PDU for route origin authorisation in IPv46.
#[derive(Default)]
#[repr(packed)]
#[allow(dead_code)]
pub struct Ipv6Prefix {
    header: Header,
    flags: u8,
    prefix_len: u8,
    max_len: u8,
    zero: u8,
    prefix: u128,
    asn: u32,
}

impl Ipv6Prefix {
    /// The payload type of an IPv6 prefix.
    pub const PDU: u8 = 6;

    /// Creates a new IPv6 prefix from all the various fields.
    pub fn new(
        version: u8,
        flags: u8,
        prefix_len: u8,
        max_len: u8,
        prefix: Ipv6Addr,
        asn: u32
    ) -> Self {
        Ipv6Prefix {
            header: Header::new(version, Self::PDU, 0, 32),
            flags,
            prefix_len,
            max_len,
            zero: 0,
            prefix: u128::from(prefix).to_be(),
            asn: asn.to_be()
        }
    }

    /// Returns the flags field of the prefix.
    ///
    /// The only flag currently used is the least significant but that is
    /// 1 for an announcement and 0 for a withdrawal.
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Returns the max length.
    pub fn max_len(&self) -> u8 {
        self.max_len
    }

    /// Returns the prefix as an IPv6 address.
    pub fn prefix(&self) -> Ipv6Addr {
        u128::from_be(self.prefix).into()
    }

    /// Returns the autonomous system number.
    pub fn asn(&self) -> u32 {
        u32::from_be(self.asn)
    }
}

concrete!(Ipv6Prefix);


//------------ RouterKey -----------------------------------------------------

/// A BGPsec router key.
pub struct RouterKey {
    fixed: RouterKeyFixed,
    key_info: Bytes,
}

#[derive(Default)]
#[repr(packed)]
struct RouterKeyFixed {
    header: Header,
    key_identifier: [u8; 20],
    asn: u32,
}

impl RouterKey {
    /// The PRDU type of a Router Key PDU.
    pub const PDU: u8 = 9;

    /// Creates a new router key PDU.
    ///
    /// # Panics
    ///
    /// This function panics if the length of the resulting PDU doesn’t fit
    /// in a `u32`.
    pub fn new(
        version: u8,
        flags: u8,
        key_identifier: [u8; 20],
        asn: u32,
        key_info: Bytes,
    ) -> Self {
        let len = u32::try_from(
            mem::size_of::<RouterKeyFixed>().checked_add(
                key_info.as_ref().len()
            ).expect("RouterKey RTR PDU size overflow")
        ).expect("RouterKey RTR PDU size overflow");
        RouterKey {
            fixed: RouterKeyFixed {
                header: Header::new(
                    version, Self::PDU,
                    (flags as u16) << 8,
                    len
                ),
                key_identifier,
                asn
            },
            key_info
        }
    }

    /// Returns the value of the version field of the header.
    pub fn version(&self) -> u8 {
        self.fixed.header.version()
    }

    /// Returns the PDU size.
    ///
    /// The size is returned as a `u32` since that type is used in
    /// the header.
    pub fn size(&self) -> u32 {
        (
            mem::size_of::<RouterKeyFixed>() + self.key_info.as_ref().len()
        ) as u32
    }

    /// Returns the flags field for the router key.
    ///
    /// The only flag currently used is the least significant but that is
    /// 1 for an announcement and 0 for a withdrawal.
    pub fn flags(&self) -> u8 {
        (self.fixed.header.session >> 8) as u8
    }

    /// Returns the subject key identifier.
    pub fn key_identifier(&self) -> [u8; 20] {
        self.fixed.key_identifier
    }

    /// Returns the ASN.
    pub fn asn(&self) -> u32 {
        self.fixed.asn
    }

    /// Returns a reference to the subject key info
    pub fn key_info(&self) -> &Bytes {
        &self.key_info
    }

    /// Converts the PDU into the subject key info.
    pub fn into_key_info(self) -> Bytes {
        self.key_info
    }

    /// Writes a value to a writer.
    pub async fn write<A: AsyncWrite + Unpin>(
        &self,
        a: &mut A
    ) -> Result<(), io::Error> {
        a.write_all(self.fixed.as_ref()).await?;
        a.write_all(self.key_info.as_ref()).await
    }

    /// Reads a value from a reader.
    ///
    /// If a value with a different PDU type is received, returns an
    /// error.
    pub async fn read<Sock: AsyncRead + Unpin>(
        sock: &mut Sock 
    ) -> Result<Self, io::Error> {
        let mut fixed = RouterKeyFixed::default();
        sock.read_exact(fixed.header.as_mut()).await?;
        if fixed.header.pdu() != Self::PDU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PDU type mismatch when expecting router key"
            ))
        }
        let info_len = match
            (fixed.header.length() as usize).checked_sub(fixed.as_ref().len())
        {
            Some(len) => len,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid length for router key"
                ))
            }
        };
        sock.read_exact(&mut fixed.as_mut()[Header::LEN..]).await?;
        let mut key_info = vec![0u8; info_len];
        sock.read_exact(&mut key_info.as_mut()).await?;
        Ok(RouterKey { fixed, key_info: key_info.into() })
    }

    /// Reads only the payload part of a value from a reader.
    pub async fn read_payload<Sock: AsyncRead + Unpin>(
        header: Header, sock: &mut Sock
    ) -> Result<Self, io::Error> {
        let info_len = match
            (header.length() as usize).checked_sub(
                mem::size_of::<RouterKeyFixed>()
            )
        {
            Some(len) => len,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid length for router key"
                ))
            }
        };
        let mut fixed = RouterKeyFixed::default();
        sock.read_exact(&mut fixed.as_mut()[Header::LEN..]).await?;
        let mut key_info = vec![0u8; info_len];
        sock.read_exact(&mut key_info.as_mut()).await?;
        Ok(RouterKey { fixed, key_info: key_info.into() })
    }
}

impl AsRef<[u8]> for RouterKeyFixed {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const Self as *const u8,
                mem::size_of::<Self>()
            )
        }
    }
}

impl AsMut<[u8]> for RouterKeyFixed {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self as *mut Self as *mut u8,
                mem::size_of::<Self>()
            )
        }
    }
}


//------------ Payload -------------------------------------------------------

/// All possible payload types.
#[non_exhaustive]
pub enum Payload {
    /// An IPv4 prefix.
    V4(Ipv4Prefix),

    /// An IPv6 prefix.
    V6(Ipv6Prefix),

    /// A router key.
    RouterKey(RouterKey),
}

impl Payload {
    /// Creates an payload value for the given payload.
    pub fn new(version: u8, flags: u8, payload: &payload::Payload) -> Self {
        match payload {
            payload::Payload::Origin(origin) => {
                match origin.prefix.addr() {
                    IpAddr::V4(addr) => {
                        Payload::V4(Ipv4Prefix::new(
                            version,
                            flags,
                            origin.prefix.prefix_len(),
                            origin.prefix.resolved_max_len(),
                            addr,
                            origin.asn.into()
                        ))
                    }
                    IpAddr::V6(addr) => {
                        Payload::V6(Ipv6Prefix::new(
                            version,
                            flags,
                            origin.prefix.prefix_len(),
                            origin.prefix.resolved_max_len(),
                            addr,
                            origin.asn.into()
                        ))
                    }
                }
            }
            payload::Payload::RouterKey(key) => {
                Payload::RouterKey(RouterKey::new(
                    version, flags,
                    key.key_identifier.into(),
                    key.asn.into(),
                    key.key_info.clone()
                ))
            }
        }
    }

    /// Reads a payload PDU from a reader.
    ///
    /// The return type is a little convoluted, but hey. The method returns
    /// `Ok(Ok(Some(payload)))` if reading went well and there was a payload
    /// PDU that we support. It returns `Ok(Ok(None))`, if reading went well
    /// and there was a payload PDU but we don’t actually support it. If
    /// reading went well but we received an end-of-data PDU, it will be
    /// returned as `Ok(Err(eod))`. If reading fails or any other PDU is
    /// received, an error is returned.
    ///
    /// The reason we are just not returning unsupported payload types is that
    /// router keys are variable length and we would need to allocate data.
    /// Which is a bit wasteful if we then just proceed to throw it away.
    pub async fn read<Sock: AsyncRead + Unpin>(
        sock: &mut Sock
    ) -> Result<Result<Option<Self>, EndOfData>, io::Error> {
        let header = Header::read(sock).await?;
        match header.pdu {
            Ipv4Prefix::PDU => {
                Ipv4Prefix::read_payload(header, sock).await.map(|res| {
                    Ok(Some(Payload::V4(res)))
                })
            }
            Ipv6Prefix::PDU => {
                Ipv6Prefix::read_payload(header, sock).await.map(|res| {
                    Ok(Some(Payload::V6(res)))
                })
            }
            RouterKey::PDU => {
                RouterKey::read_payload(header, sock).await.map(|res| {
                    Ok(Some(Payload::RouterKey(res)))
                })
            }
            EndOfData::PDU => {
                EndOfData::read_payload(header, sock).await.map(Err)
            }
            _ => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected PDU in payload sequence"
                ))
            }
        }
    }

    /// Returns the RTR version of the payload PDU.
    pub fn version(&self) -> u8 {
        match *self {
            Payload::V4(ref data) => data.version(),
            Payload::V6(ref data) => data.version(),
            Payload::RouterKey(ref key) => key.version(),
        }
    }

    /// Returns the flags of the payload PDU.
    pub fn flags(&self) -> u8 {
        match *self {
            Payload::V4(ref data) => data.flags(),
            Payload::V6(ref data) => data.flags(),
            Payload::RouterKey(ref key) => key.flags(),
        }
    }

    /// Writes the payload PDU to a writer.
    pub async fn write<A: AsyncWrite + Unpin>(
        &self,
        a: &mut A
    ) -> Result<(), io::Error> {
        match *self {
            Payload::V4(ref data) => data.write(a).await,
            Payload::V6(ref data) => data.write(a).await,
            Payload::RouterKey(ref data) => data.write(a).await,
        }
    }

    /// Converts the payload PDU into action and payload.
    ///
    /// Returns an error if the PDU isn’t acceptable for some reason.
    pub fn to_payload(
        &self
    ) -> Result<(payload::Action, payload::Payload), Error> {
        fn make_payload(
            payload: &Payload,
        ) -> Result<payload::Payload, &'static str> {
            match payload {
                Payload::V4(data) => {
                    Ok(payload::Payload::origin(
                        MaxLenPrefix::new(
                            Prefix::new_v4_relaxed(
                                data.prefix(), data.prefix_len()
                            )?,
                            Some(data.max_len())
                        )?,
                        data.asn().into()
                    ))
                }
                Payload::V6(data) => {
                    Ok(payload::Payload::origin(
                        MaxLenPrefix::new(
                            Prefix::new_v6_relaxed(
                                data.prefix(), data.prefix_len()
                            )?,
                            Some(data.max_len())
                        )?,
                        data.asn().into()
                    ))
                }
                Payload::RouterKey(key) => {
                    Ok(payload::Payload::router_key(
                        key.key_identifier().into(), key.asn().into(),
                        key.key_info().clone()
                    ))
                }
            }
        }

        Ok((
            payload::Action::from_flags(self.flags()),
            make_payload(self).map_err(|text| {
                Error::new(
                    self.version(), 0, self.as_partial_slice(), text.as_bytes()
                )
            })?
        ))
    }

    /// Returns an octets slice of as much of the PDU as possible.
    pub fn as_partial_slice(&self) -> &[u8] {
        match *self {
            Payload::V4(ref prefix) => prefix.as_ref(),
            Payload::V6(ref prefix) => prefix.as_ref(),
            Payload::RouterKey(ref key) => key.fixed.as_ref(),
        }
    }
}


//------------ EndOfData -----------------------------------------------------

/// End-of-data marks the end of sequence of payload PDUs.
///
/// This PDU differs between version 0 and 1 of RTR. Consequently, this
/// generic version is an enum that can be both, depending on the version
/// requested.
pub enum EndOfData {
    V0(EndOfDataV0),
    V1(EndOfDataV1),
}

impl EndOfData {
    /// The PDU type of the end-of-data PDU.
    pub const PDU: u8 = 7;

    /// Creates a new end-of-data PDU from the data given.
    ///
    /// If version is 0, the `V0` variant is created and the three timer
    /// values are ignored. Otherwise, a `V1` variant is created with the
    /// given version.
    pub fn new(
        version: u8,
        state: State,
        timing: payload::Timing,
    ) -> Self {
        if version == 0 {
            EndOfData::V0(EndOfDataV0::new(state))
        }
        else {
            EndOfData::V1(EndOfDataV1::new(
                version, state, timing
            ))
        }
    }

    /// Reads the end-of-data payload from a reader.
    ///
    /// Which version of the end-of-data PDU is expected depends on the
    /// version field of the `header`. On success, the return value contains
    /// a full PDU, filling in missing data from `header`.
    pub async fn read_payload<Sock: AsyncRead + Unpin>(
        header: Header, sock: &mut Sock
    ) -> Result<Self, io::Error> {
        match header.version() {
            0 => {
                EndOfDataV0::read_payload(header, sock)
                    .await.map(EndOfData::V0)
            }
            1 => {
                EndOfDataV1::read_payload(header, sock)
                    .await.map(EndOfData::V1)
            }
            _ => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid version in end of data PDU"
                ))
            }
        }
    }

    /// Returns the version field of the PDU.
    pub fn version(&self) -> u8 {
        match *self {
            EndOfData::V0(_) => 0,
            EndOfData::V1(_) => 1,
        }
    }

    /// Returns the session ID.
    pub fn session(&self) -> u16 {
        match *self {
            EndOfData::V0(ref data) => data.session(),
            EndOfData::V1(ref data) => data.session(),
        }
    }

    /// Returns the serial number.
    pub fn serial(&self) -> Serial {
        match *self {
            EndOfData::V0(ref data) => data.serial(),
            EndOfData::V1(ref data) => data.serial(),
        }
    }

    /// Returns the state by combing session ID and serial number.
    pub fn state(&self) -> State {
        State::from_parts(self.session(), self.serial())
    }

    /// Returns the three timing values if they are available.
    ///
    /// The values are only available in the `V1` variant.
    pub fn timing(&self) -> Option<payload::Timing> {
        match *self {
            EndOfData::V0(_) => None,
            EndOfData::V1(ref data) => Some(data.timing()),
        }
    }

    /// Writes the PDU to a writer.
    pub async fn write<A: AsyncWrite + Unpin>(
        &self, a: &mut A
    ) -> Result<(), io::Error> {
        a.write_all(self.as_ref()).await
    }
}

impl AsRef<[u8]> for EndOfData {
    fn as_ref(&self) -> &[u8] {
        match *self {
            EndOfData::V0(ref inner) => inner.as_ref(),
            EndOfData::V1(ref inner) => inner.as_ref(),
        }
    }
}

impl AsMut<[u8]> for EndOfData {
    fn as_mut(&mut self) -> &mut [u8] {
        match *self {
            EndOfData::V0(ref mut inner) => inner.as_mut(),
            EndOfData::V1(ref mut inner) => inner.as_mut(),
        }
    }
}


//------------ EndOfDataV0 ---------------------------------------------------

/// End-of-data marks the end of sequence of payload PDUs.
///
/// This type is the version used in protocol version 0.
#[derive(Default)]
#[repr(packed)]
pub struct EndOfDataV0 {
    header: Header,
    serial: u32
}

impl EndOfDataV0 {
    /// The PDU type of end-of-date.
    pub const PDU: u8 = 7;

    /// Creates a new end-of-data PDU from the given state.
    pub fn new(state: State) -> Self {
        EndOfDataV0 {
            header: Header::new(0, Self::PDU, state.session(), 12),
            serial: state.serial().to_be()
        }
    }

    /// Returns the serial number.
    pub fn serial(&self) -> Serial {
        Serial::from_be(self.serial)
    }
}

concrete!(EndOfDataV0);
    

//------------ EndOfDataV1 ---------------------------------------------------

/// End-of-data marks the end of sequence of payload PDUs.
///
/// This type is the version used beginning with protocol version 1.
#[derive(Default)]
#[repr(packed)]
pub struct EndOfDataV1 {
    header: Header,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
}

impl EndOfDataV1 {
    /// The PDU type of end-of-data.
    pub const PDU: u8 = 7;

    /// Creates a new end-of-data PDU from state and timer values.
    pub fn new(
        version: u8,
        state: State,
        timing: payload::Timing,
    ) -> Self {
        EndOfDataV1 {
            header: Header::new(version, Self::PDU, state.session(), 24),
            serial: state.serial().to_be(),
            refresh: timing.refresh.to_be(),
            retry: timing.retry.to_be(),
            expire: timing.expire.to_be(),
        }
    }

    /// Returns the serial number.
    pub fn serial(&self) -> Serial {
        Serial::from_be(self.serial)
    }

    /// Returns the timing paramters.
    pub fn timing(&self) -> payload::Timing {
        payload::Timing {
            refresh: u32::from_be(self.refresh),
            retry: u32::from_be(self.retry),
            expire: u32::from_be(self.expire),
        }
    }
}

concrete!(EndOfDataV1);


//------------ CacheReset ----------------------------------------------------

/// Cache reset is a response to a serial query indicating unavailability.
///
/// If a cache doesn’t have information available that reaches back to the
/// serial number indicated in the serial query, it responds with a cache
/// reset.
#[derive(Default)]
#[repr(packed)]
pub struct CacheReset {
    header: Header
}

impl CacheReset {
    /// The PDU type for a cache reset.
    pub const PDU: u8 = 8;

    /// Creates a cache reset.
    pub fn new(version: u8) -> Self {
        CacheReset {
            header: Header::new(version, Self::PDU, 0, 8)
        }
    }
}

concrete!(CacheReset);


//------------ Error ---------------------------------------------------------

/// An error report signals that something went wrong.
///
/// Error reports contain an error code and can contain both the erroneous
/// PDU and some diagnostic error text. Because of this, values of this type
/// are not fixed size byte arrays but rather are allocated according to the
/// contents of these two fields.
#[derive(Default)]
pub struct Error {
    octets: Vec<u8>,
}
/*
    /// The header of the error PDU.
    header: Header,

    /// The size of the embedded PDU in network byte order.
    pdu_len: u32,

    /// The embedded PDU.
    pdu: P,

    /// The size of the embedded reason text in network byte order.
    text_len: u32,

    /// The embedded text.
    text: T
*/

impl Error {
    /// The PDU type of an error PDU.
    pub const PDU: u8 = 10;

    /// Creates a new error PDU from components.
    pub fn new(
        version: u8,
        error_code: u16,
        pdu: impl AsRef<[u8]>,
        text: impl AsRef<[u8]>,
    ) -> Self {
        let pdu = pdu.as_ref();
        let text = text.as_ref();

        let size = 
            mem::size_of::<Header>()
            + 2 * mem::size_of::<u32>()
            + pdu.len() + text.len()
        ;
        let header = Header::new(
            version, 10, error_code, u32::try_from(size).unwrap()
        );

        let mut octets = Vec::with_capacity(size);
        octets.extend_from_slice(header.as_ref());
        octets.extend_from_slice(
            u32::try_from(pdu.len()).unwrap().to_be_bytes().as_ref()
        );
        octets.extend_from_slice(pdu);
        octets.extend_from_slice(
            u32::try_from(text.len()).unwrap().to_be_bytes().as_ref()
        );
        octets.extend_from_slice(text);

        Error { octets }
    }

    /// Writes the PUD to a writer.
    pub async fn write<A: AsyncWrite + Unpin>(
        &self, a: &mut A
    ) -> Result<(), io::Error> {
        a.write_all(self.as_ref()).await
    }
}


//--- AsRef and AsMut

impl AsRef<[u8]> for Error {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl AsMut<[u8]> for Error {
    fn as_mut(&mut self) -> &mut [u8] {
        self.octets.as_mut()
    }
}


//------------ Header --------------------------------------------------------

/// The header portion of an RTR PDU.
#[derive(Clone, Copy, Default)]
#[repr(packed)]
pub struct Header {
    /// The version of the PDU.
    version: u8,

    /// The PDU type.
    pdu: u8,

    /// The session ID for this RTR session.
    ///
    /// This field is re-used by some PDUs for other purposes.
    session: u16,

    /// The length of the PDU in network byte order.
    ///
    /// This is the size of the whole PDU including the header.
    length: u32,
}

impl Header {
    /// The size of the header.
    const LEN: usize = mem::size_of::<Self>();

    /// Creates a new header.
    pub fn new(version: u8, pdu: u8, session: u16, length: u32) -> Self {
        Header {
            version,
            pdu,
            session: session.to_be(),
            length: length.to_be(),
        }
    }

    /// Reads the header from a reader.
    pub async fn read<Sock: AsyncRead + Unpin>(
        sock: &mut Sock 
    ) -> Result<Self, io::Error> {
        let mut res = Self::default();
        sock.read_exact(res.as_mut()).await?;
        Ok(res)
    }

    /// Returns the version of this PDU.
    pub fn version(self) -> u8 {
        self.version
    }

    /// Returns the PDU type.
    pub fn pdu(self) -> u8 {
        self.pdu
    }

    /// Returns the session ID of this session.
    pub fn session(self) -> u16 {
        u16::from_be(self.session)
    }

    /// Returns the length of the PDU.
    ///
    /// This is the length of the full PDU including the header.
    pub fn length(self) -> u32 {
        u32::from_be(self.length)
    }
}

common!(Header);

