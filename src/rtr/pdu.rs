//! Raw protocol data.
//!
//! This module contains types that represent the protocol data units of
//! RTR in their wire representation. That is, these types can be given to
//! read and write operations as buffers.  See section 5 of RFC 6810 and
//! RFC 8210. Annoyingly, the format of the `EndOfData` PDU changes between
//! the two versions.

use std::{cmp, borrow, error, fmt, io, mem, ops, slice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::resources::addr::{MaxLenPrefix, Prefix};
use crate::resources::asn::Asn;
use crate::rtr::Action;
use crate::util::base64;
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
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
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
        asn: Asn,
    ) -> Self {
        Ipv4Prefix {
            header: Header::new(version, Self::PDU, 0, 20),
            flags,
            prefix_len,
            max_len,
            zero: 0,
            prefix: u32::from(prefix).to_be(),
            asn: asn.into_u32().to_be()
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
    pub fn asn(&self) -> Asn {
        u32::from_be(self.asn).into()
    }
}

concrete!(Ipv4Prefix);


//------------ Ipv6Prefix ----------------------------------------------------

/// An IPv6 prefix is the payload PDU for route origin authorisation in IPv6.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
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
        asn: Asn,
    ) -> Self {
        Ipv6Prefix {
            header: Header::new(version, Self::PDU, 0, 32),
            flags,
            prefix_len,
            max_len,
            zero: 0,
            prefix: u128::from(prefix).to_be(),
            asn: asn.into_u32().to_be()
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
    pub fn asn(&self) -> Asn {
        u32::from_be(self.asn).into()
    }
}

concrete!(Ipv6Prefix);


//------------ RouterKey -----------------------------------------------------

/// A BGPsec router key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RouterKey {
    fixed: RouterKeyFixed,
    key_info: RouterKeyInfo,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
struct RouterKeyFixed {
    header: Header,
    key_identifier: [u8; 20],
    asn: u32,
}

impl RouterKey {
    /// The PDU type of a Router Key PDU.
    pub const PDU: u8 = 9;

    /// The maximum size of the subject public key info data.
    pub const fn max_key_info_size() -> usize {
        (u32::MAX as usize) - mem::size_of::<RouterKeyFixed>()
    }

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
        asn: Asn,
        key_info: RouterKeyInfo,
    ) -> Self {
        // We know it fits but let’s be sure.
        let len = u32::try_from(
            mem::size_of::<RouterKeyFixed>().checked_add(
                key_info.len()
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
                asn: asn.into_u32().to_be(),
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
            mem::size_of::<RouterKeyFixed>() + self.key_info.len()
        ) as u32
    }

    /// Returns the flags field for the router key.
    ///
    /// The only flag currently used is the least significant bit that is
    /// 1 for an announcement and 0 for a withdrawal.
    pub fn flags(&self) -> u8 {
        // The two-byte Session field is reused for the Flags byte and one
        // reserved byte (of zeroes). As the value of the Session field is in
        // network byte order, we first convert it, then shift out the lower
        // byte.
        (u16::from_be(self.fixed.header.session) >> 8) as u8
    }

    /// Returns the subject key identifier.
    pub fn key_identifier(&self) -> [u8; 20] {
        self.fixed.key_identifier
    }

    /// Returns the ASN.
    pub fn asn(&self) -> Asn {
        u32::from_be(self.fixed.asn).into()
    }

    /// Returns a reference to the subject key info
    pub fn key_info(&self) -> &RouterKeyInfo {
        &self.key_info
    }

    /// Converts the PDU into the subject key info.
    pub fn into_key_info(self) -> RouterKeyInfo {
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
        let header = Header::read(sock).await?;
        if header.pdu() != Self::PDU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PDU type mismatch when expecting router key"
            ))
        }
        Self::read_payload(header, sock).await
    }

    /// Reads only the payload part of a value from a reader.
    pub async fn read_payload<Sock: AsyncRead + Unpin>(
        header: Header, sock: &mut Sock
    ) -> Result<Self, io::Error> {
        let info_len = match
            header.pdu_len()?.checked_sub(mem::size_of::<RouterKeyFixed>())
        {
            Some(len) => len,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid length for router key"
                ))
            }
        };
        let mut fixed = RouterKeyFixed { header, .. Default::default() };
        sock.read_exact(&mut fixed.as_mut()[Header::LEN..]).await?;
        let key_info = RouterKeyInfo::read(sock, info_len).await?;
        Ok(RouterKey { fixed, key_info })
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


//------------ RouterKeyInfo -------------------------------------------------

/// The subject public key info data of a router key.
///
/// This is a simple newtype around a `Bytes` enforcing a size limit so that
/// a value can always be used in a router key PDU.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouterKeyInfo(Bytes);

impl RouterKeyInfo {
    /// Creates a new value from some bytes.
    ///
    /// Returns an error if the bytes are too large to fit into a router key
    /// PDU.
    pub fn new(bytes: Bytes) -> Result<Self, KeyInfoError> {
        if bytes.len() > RouterKey::max_key_info_size() {
            Err(KeyInfoError)
        }
        else {
            Ok(RouterKeyInfo(bytes))
        }
    }

    /// Returns a reference to the octets of the value.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Converts the value into the underlying bytes.
    pub fn into_bytes(self) -> Bytes {
        self.0
    }

    /// Reads a value of the given length from the buffer.
    async fn read<Sock: AsyncRead + Unpin>(
        sock: &mut Sock, len: usize,
    ) -> Result<Self, io::Error> {
        let mut key_info = vec![0u8; len];
        sock.read_exact(key_info.as_mut()).await?;
        Ok(RouterKeyInfo(key_info.into()))
    }
}


//--- TryFrom

impl TryFrom<Vec<u8>> for RouterKeyInfo {
    type Error = KeyInfoError;

    fn try_from(src: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(src.into())
    }
}

impl TryFrom<Bytes> for RouterKeyInfo {
    type Error = KeyInfoError;

    fn try_from(src: Bytes) -> Result<Self, Self::Error> {
        Self::new(src)
    }
}


//--- Deref, AsRef, and Borrow

impl ops::Deref for RouterKeyInfo {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Bytes> for RouterKeyInfo {
    fn as_ref(&self) -> &Bytes {
        &self.0
    }
}

impl AsRef<[u8]> for RouterKeyInfo {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl borrow::Borrow<Bytes> for RouterKeyInfo {
    fn borrow(&self) -> &Bytes {
        self.as_ref()
    }
}

impl borrow::Borrow<[u8]> for RouterKeyInfo {
    fn borrow(&self) -> &[u8] {
        self.as_ref()
    }
}


//--- Display and Debug

impl fmt::Display for RouterKeyInfo{
    /// Formats the key info using the given formatter.
    ///
    /// The output format is identical to that used in local exception
    /// files defined by [RFC 8416], i.e., unpadded Base 64 using the URL-safe
    /// alphabet.
    ///
    /// [RFC 8416]: https://tools.ietf.org/html/rfc8416
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        base64::Slurm.display(self.0.as_ref()).fmt(f)
    }
}

impl fmt::Debug for RouterKeyInfo{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("RouterKeyInfo")
        .field(&format_args!("{self}"))
        .finish()
    }
}


//--- Arbitrary

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for RouterKeyInfo {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'a>
    ) -> arbitrary::Result<Self> {
        let size = usize::arbitrary(u)? % (RouterKey::max_key_info_size() + 1);
        Ok(Self(Bytes::copy_from_slice(u.bytes(size)?)))
    }
}


//------------ Aspa ----------------------------------------------------------

/// The PDU for ASPA.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Aspa {
    fixed: AspaFixed,
    providers: ProviderAsns,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
struct AspaFixed {
    header: Header,
    customer: u32,
}

impl Aspa {
    /// The PDU type of an ASPA PDU.
    pub const PDU: u8 = 11;

    /// Creates a new ASPA PDU.
    ///
    /// # Panics
    ///
    /// This function panics if the length of the resulting PDU doesn’t fit
    /// in a `u32`. Because `ProviderAsns` is now limited in size, this can’t
    /// happen.
    pub fn new(
        version: u8,
        flags: u8,
        customer: Asn,
        providers: ProviderAsns,
    ) -> Self {
        let len = u32::try_from(
            mem::size_of::<AspaFixed>().checked_add(
                providers.len()
            ).expect("ASPA RTR PDU size overflow")
        ).expect("ASPA RTR PDU size overflow");
        Aspa {
            fixed: AspaFixed {
                header: Header::new(
                    version, Self::PDU,
                    (flags as u16) << 8,
                    len
                ),
                customer: customer.into_u32().to_be(),
            },
            providers
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
        u32::try_from(
            mem::size_of::<AspaFixed>() + self.providers.len()
        ).expect("long ASPA PDU")
    }

    /// Returns the flags field.
    ///
    /// The only flag currently used is the least significant bit that is
    /// 1 for an announcement and 0 for a withdrawal.
    pub fn flags(&self) -> u8 {
        // The two-byte Session field is reused for the Flags byte and one
        // reserved byte (of zeroes). As the value of the Session field is in
        // network byte order, we first convert it, then shift out the lower
        // byte.
        (u16::from_be(self.fixed.header.session) >> 8) as u8
    }

    /// Returns the customer ASN.
    pub fn customer(&self) -> Asn {
        u32::from_be(self.fixed.customer).into()
    }

    /// Returns a reference to the provider ASNs.
    pub fn providers(&self) -> &ProviderAsns {
        &self.providers
    }

    /// Converts the PDU into the provider ASNs.
    pub fn into_providers(self) -> ProviderAsns {
        self.providers
    }

    /// Writes a value to a writer.
    pub async fn write<A: AsyncWrite + Unpin>(
        &self,
        a: &mut A
    ) -> Result<(), io::Error> {
        a.write_all(self.fixed.as_ref()).await?;
        a.write_all(self.providers.as_ref()).await
    }

    /// Reads a value from a reader.
    ///
    /// If a value with a different PDU type is received, returns an
    /// error.
    pub async fn read<Sock: AsyncRead + Unpin>(
        sock: &mut Sock 
    ) -> Result<Self, io::Error> {
        let header = Header::read(sock).await?;
        if header.pdu() != Self::PDU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PDU type mismatch when expecting ASPA PDU"
            ))
        }
        Self::read_payload(header, sock).await
    }

    /// Reads only the payload part of a value from a reader.
    pub async fn read_payload<Sock: AsyncRead + Unpin>(
        header: Header, sock: &mut Sock
    ) -> Result<Self, io::Error> {
        let provider_len = match
            header.pdu_len()?.checked_sub(mem::size_of::<AspaFixed>())
        {
            Some(len) => {
                if len % 4 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid length for ASPA PDU"
                    ))
                }
                len
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid length for ASPA PDU"
                ))
            }
        };
        let mut fixed = AspaFixed { header, .. Default::default() };
        sock.read_exact(&mut fixed.as_mut()[Header::LEN..]).await?;
        let providers = ProviderAsns::read(sock, provider_len).await?;
        Ok(Aspa { fixed, providers })
    }
}

impl AsRef<[u8]> for AspaFixed {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const Self as *const u8,
                mem::size_of::<Self>()
            )
        }
    }
}

impl AsMut<[u8]> for AspaFixed {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self as *mut Self as *mut u8,
                mem::size_of::<Self>()
            )
        }
    }
}


//------------ ProviderAsns --------------------------------------------------

/// The provider ASNs of an ASPA PDU.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderAsns(Bytes);

impl ProviderAsns {
    /// The maximum number of provider ASNs.
    pub const MAX_COUNT: usize = 16380;

    /// Returns an empty value.
    pub fn empty() -> Self {
        Self(Bytes::new())
    }

    /// Creates a new value from an iterator over ASNs.
    ///
    /// Returns an error if there are too many items in the iterator to fit
    /// into an RTR PDU.
    pub fn try_from_iter(
        iter: impl IntoIterator<Item = Asn>
    ) -> Result<Self, ProviderAsnsError> {
        let iter = iter.into_iter();
        let mut providers = Vec::with_capacity(iter.size_hint().0);
        iter.enumerate().try_for_each(|(idx, item)| {
            if idx >= Self::MAX_COUNT {
                return Err(ProviderAsnsError(()))
            }
            providers.extend_from_slice(&item.into_u32().to_be_bytes());
            Ok(())
        })?;
        Ok(ProviderAsns(providers.into()))
    }

    pub fn asn_count(&self) -> u16 {
        u16::try_from(
            self.0.len() / mem::size_of::<u32>()
        ).expect("ASPA RTR PDU size overflow")
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = Asn> + '_ {
        self.0.as_ref().chunks(mem::size_of::<u32>()).map(|chunk| {
            u32::from_be_bytes(
                TryFrom::try_from(chunk).expect("bad ASPA PDU size")
            ).into()
        })
    }

    /// Reads a value of the given length from the buffer.
    async fn read<Sock: AsyncRead + Unpin>(
        sock: &mut Sock, len: usize,
    ) -> Result<Self, io::Error> {
        let mut providers = vec![0u8; len];
        sock.read_exact(providers.as_mut()).await?;
        Ok(ProviderAsns(providers.into()))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for ProviderAsns {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'a>
    ) -> arbitrary::Result<Self> {
        let size = (
            usize::arbitrary(u)? % usize::from(u16::MAX)
        ) * mem::size_of::<Asn>();
        Ok(Self(Bytes::copy_from_slice(u.bytes(size)?)))
    }
}

impl AsRef<[u8]> for ProviderAsns {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}


//------------ Payload -------------------------------------------------------

/// All possible payload types.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Payload {
    /// An IPv4 prefix.
    V4(Ipv4Prefix),

    /// An IPv6 prefix.
    V6(Ipv6Prefix),

    /// A router key.
    RouterKey(RouterKey),

    /// An ASPA unit.
    Aspa(Aspa),
}

impl Payload {
    /// Creates a payload PDU for the given payload.
    pub fn new(version: u8, flags: u8, payload: payload::PayloadRef) -> Self {
        match payload {
            payload::PayloadRef::Origin(origin) => {
                match origin.prefix.addr() {
                    IpAddr::V4(addr) => {
                        Payload::V4(Ipv4Prefix::new(
                            version,
                            flags,
                            origin.prefix.prefix_len(),
                            origin.prefix.resolved_max_len(),
                            addr,
                            origin.asn,
                        ))
                    }
                    IpAddr::V6(addr) => {
                        Payload::V6(Ipv6Prefix::new(
                            version,
                            flags,
                            origin.prefix.prefix_len(),
                            origin.prefix.resolved_max_len(),
                            addr,
                            origin.asn,
                        ))
                    }
                }
            }
            payload::PayloadRef::RouterKey(key) => {
                Payload::RouterKey(RouterKey::new(
                    version, flags,
                    key.key_identifier.into(),
                    key.asn,
                    key.key_info.clone()
                ))
            }
            payload::PayloadRef::Aspa(aspa) => {
                Payload::Aspa(Aspa::new(
                    version, flags, aspa.customer, aspa.providers.clone(),
                ))
            }
        }
    }

    /// Creates a payload PDU if it is supported in the given version.
    pub fn new_if_supported(
        version: u8, flags: u8, payload: payload::PayloadRef
    ) -> Option<Self> {
        let min_version = match payload {
            payload::PayloadRef::Origin(_) => 0,
            payload::PayloadRef::RouterKey(_) => 1,
            payload::PayloadRef::Aspa(_) => 2,
        };
        if min_version > version {
            None
        }
        else {
            Some(Self::new(version, flags, payload))
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
    /// router keys and ASPA PDUs are variable length and we would need to
    /// allocate data. Which is a bit wasteful if we then just proceed to
    /// throw it away.
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
            Aspa::PDU => {
                Aspa::read_payload(header, sock).await.map(|res| {
                    Ok(Some(Payload::Aspa(res)))
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
            Payload::Aspa(ref aspa) => aspa.version(),
        }
    }

    /// Returns the flags of the payload PDU.
    pub fn flags(&self) -> u8 {
        match *self {
            Payload::V4(ref data) => data.flags(),
            Payload::V6(ref data) => data.flags(),
            Payload::RouterKey(ref key) => key.flags(),
            Payload::Aspa(ref aspa) => aspa.flags(),
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
            Payload::Aspa(ref aspa) => aspa.write(a).await,
        }
    }

    /// Converts the payload PDU into action and payload.
    ///
    /// Returns an error if the PDU isn’t acceptable for some reason.
    pub fn to_payload(
        &self
    ) -> Result<(payload::Action, payload::Payload), Error> {
        let action = payload::Action::from_flags(self.flags());

        fn make_payload(
            action: &Action,
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
                        data.asn(),
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
                        data.asn(),
                    ))
                }
                Payload::RouterKey(key) => {
                    Ok(payload::Payload::router_key(
                        key.key_identifier().into(), key.asn(),
                        key.key_info().clone()
                    ))
                }
                Payload::Aspa(aspa) => {
                    Ok(match action {
                        Action::Withdraw => payload::Payload::aspa(
                            aspa.customer(), ProviderAsns::empty(),
                        ),
                        _ => payload::Payload::aspa(
                            aspa.customer(), aspa.providers().clone(),
                        ),
                    })
                }
            }
        }

        Ok((
            action,
            make_payload(&action, self).map_err(|text| {
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
            Payload::Aspa(ref aspa) => aspa.fixed.as_ref(),
        }
    }
}


//------------ EndOfData -----------------------------------------------------

/// End-of-data marks the end of sequence of payload PDUs.
///
/// This PDU differs between version 0 and 1 of RTR. Consequently, this
/// generic version is an enum that can be both, depending on the version
/// requested. For version 2, the PDU is the same as for version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
            1|2 => {
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
            EndOfData::V1(v1_or_v2) => v1_or_v2.header.version()
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
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
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
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
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
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
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

    /// Skips over the payload of the error PDU.
    pub async fn skip_payload<Sock: AsyncRead + Unpin>(
        header: Header, sock: &mut Sock
    ) -> Result<(), io::Error> {
        let Some(mut remaining) = header.pdu_len()?.checked_sub(
            mem::size_of::<Header>()
        ) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PDU size smaller than header size",
            ))
        };

        let mut buf = [0u8; 1024];
        while remaining > 0 {
            let read_len = cmp::min(remaining, mem::size_of_val(&buf));
            let read = sock.read(
                // Safety: We limited the length to the buffer size.
                unsafe { buf.get_unchecked_mut(..read_len) }
            ).await?;
            remaining -= read;
        }
        Ok(())
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


//------------ ErrorCode -----------------------------------------------------

/// An error code.
///
/// This type wraps the raw error code that is part of the error PDU.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ErrorCode(pub u16);

impl ErrorCode {
    pub const CORRUPT_DATA: Self = Self(0);
    pub const INTERNAL_ERROR: Self = Self(1);
    pub const NO_DATA_AVAILABLE: Self = Self(2);
    pub const INVALID_REQUEST: Self = Self(3);
    pub const UNSUPPORTED_PROTOCOL_VERSION: Self = Self(4);
    pub const UNSUPPORTED_PDU_TYPE: Self = Self(5);
    pub const WITHDRAWAL_OF_UNKNOWN_RECORD: Self = Self(6);
    pub const DUPLICATE_ANNOUNCEMENT_RECEIVED: Self = Self(7);
    pub const UNEXPECTED_PROTOCOL_VERSION: Self = Self(8);
    pub const ASPA_PROVIDER_LIST_ERROR: Self = Self(9);
    pub const TRANSPORT_ERROR: Self = Self(10);
    pub const ORDERING_ERROR: Self = Self(11);
}

impl PartialEq<u16> for ErrorCode {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other
    }
}

impl PartialEq<ErrorCode> for u16 {
    fn eq(&self, other: &ErrorCode) -> bool {
        *self == other.0
    }
}


//------------ Header --------------------------------------------------------

/// The header portion of an RTR PDU.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
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

    /// Returns the length of the PDU as a `u32`.
    ///
    /// This is the length of the full PDU including the header.
    pub fn length(self) -> u32 {
        u32::from_be(self.length)
    }

    /// Returns the length of the PDU as a `usize`.
    ///
    /// Since at least in theory `usize` may only be 16 bit long, the
    /// conversion can fail.
    ///
    /// This is the length of the full PDU including the header.
    pub fn pdu_len(self) -> Result<usize, io::Error> {
        usize::try_from(self.length()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "PDU too large for this system to handle",
            )
        })
    }
}

common!(Header);


//============ ErrorTypes ====================================================

//------------ KeyInfoError --------------------------------------------------

/// The key info of a router key was too large.
#[derive(Clone, Copy, Debug)]
pub struct KeyInfoError;

impl fmt::Display for KeyInfoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("router key size overflow")
    }
}

impl error::Error for KeyInfoError { }


//------------ ProviderAsnsError ---------------------------------------------

/// The provider ASNs of an ASPA unit were too large.
#[derive(Clone, Copy, Debug)]
pub struct ProviderAsnsError(());

impl fmt::Display for ProviderAsnsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("provider ASNs size overflow")
    }
}

impl error::Error for ProviderAsnsError { }


//============ Tests =========================================================

#[cfg(all(test, feature = "tokio"))]
mod test {
    use super::*;
    use std::iter;

    const STATE: State = State::from_parts(0x1234, Serial(0xdead_beef));

    macro_rules! read_write {
        ( $ty:ident, $value:expr, $binary:expr $(,)? ) => {{
            let mut written = Vec::new();
            $value.write(&mut written).await.unwrap();
            assert_eq!(written, $binary);
            assert_eq!(
                $ty::read(&mut written.as_slice()).await.unwrap(),
                $value
            );
        }}
    }

    #[tokio::test]
    async fn read_write_serial_notify() {
        read_write!(
            SerialNotify,
            SerialNotify::new(1, STATE),
            [0x01, 0x00, 0x12, 0x34,   0, 0, 0, 12,   0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[tokio::test]
    async fn read_write_serial_query() {
        read_write!(
            SerialQuery,
            SerialQuery::new(1, STATE),
            [0x01, 0x01, 0x12, 0x34,   0, 0, 0, 12,   0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[tokio::test]
    async fn read_write_reset_query() {
        read_write!(
            ResetQuery,
            ResetQuery::new(1),
            [0x01, 0x02, 0, 0,   0, 0, 0, 8]
        );
    }

    #[tokio::test]
    async fn read_write_cache_response() {
        read_write!(
            CacheResponse,
            CacheResponse::new(1, STATE),
            [0x01, 0x03, 0x12, 0x34,   0, 0, 0, 8]
        );
    }

    #[tokio::test]
    async fn read_write_ipv4_prefix() {
        read_write!(
            Ipv4Prefix,
            Ipv4Prefix::new(
                1, 1, 23, 26, Ipv4Addr::new(192, 0, 2, 10),
                Asn::from_u32(0x1000f),
            ),
            [
                1, 4, 0, 0,      0, 0, 0, 20,  1, 23, 26, 0,
                192, 0, 2, 10,   0, 1, 0, 0x0f
            ],
        );
    }

    #[tokio::test]
    async fn read_write_ipv6_prefix() {
        read_write!(
            Ipv6Prefix,
            Ipv6Prefix::new(
                1, 1, 23, 26,
                Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 10, 0, 0xdead, 0xbeef),
                Asn::from_u32(0x1000f),
            ),
            [
                1, 6, 0, 0,             0, 0, 0, 32,  1, 23, 26, 0,
                0x20, 0x01, 0xd, 0xb8,  0, 0, 0, 2,
                0, 10, 0, 0,            0xde, 0xad, 0xbe, 0xef,
                0, 1, 0, 0x0f
            ],
        );
    }

    #[tokio::test]
    async fn read_write_router_key() {
        read_write!(
            RouterKey,
            RouterKey::new(
                1, 1,
                [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20],
                Asn::from_u32(0x1000f),
                RouterKeyInfo::new(Bytes::from_static(&[21,22,23,24])).unwrap()
            ),
            [
                1, 9, 1, 0,      0, 0, 0, 36,
                1, 2, 3, 4,      5, 6, 7, 8,
                9, 10, 11, 12,   13, 14, 15, 16,
                17, 18, 19, 20,  0, 1, 0, 15,
                21, 22, 23, 24,
            ]
        );
    }

    #[test]
    fn router_key_flags() {
        for flags in [0, 1, 128, 255] {
            let key = RouterKey::new(
                1, flags,
                [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20],
                Asn::from_u32(0x1000f),
                RouterKeyInfo::new(Bytes::from_static(&[21,22,23,24])).unwrap()
            );
            assert_eq!(key.flags(), flags);
        }
    }

    #[tokio::test]
    async fn read_write_aspa() {
        read_write!(
            Aspa,
            Aspa::new(
                2, 1, Asn::from_u32(0x1000f),
                ProviderAsns::try_from_iter([
                    Asn::from_u32(0x1000d), Asn::from_u32(0x1000e)
                ]).unwrap(),
            ),
            [
                2, 11, 1, 0,    0, 0, 0, 20,
                0, 1, 0, 15,    0, 1, 0, 13,
                0, 1, 0, 14,
            ]
        );
    }

    #[test]
    fn aspa_flags() {
        for flags in [0, 1, 128, 255] {
            let aspa = Aspa::new(
                2, flags,
                Asn::from_u32(0x1000f),
                ProviderAsns::try_from_iter([
                    Asn::from_u32(0x1000d), Asn::from_u32(0x1000e)
                ]).unwrap(),
            );
            assert_eq!(aspa.flags(), flags);
        }
    }

    #[test]
    fn provider_count() {
        assert_eq!(
            ProviderAsns::try_from_iter(
                iter::repeat_n(Asn::from(0), ProviderAsns::MAX_COUNT - 1)
            ).unwrap().asn_count(),
            (ProviderAsns::MAX_COUNT - 1) as u16,
        );
        assert_eq!(
            ProviderAsns::try_from_iter(
                iter::repeat_n(Asn::from(0), ProviderAsns::MAX_COUNT)
            ).unwrap().asn_count(),
            ProviderAsns::MAX_COUNT as u16,
        );
        assert!(
            ProviderAsns::try_from_iter(
                iter::repeat_n(Asn::from(0), ProviderAsns::MAX_COUNT + 1)
            ).is_err()
        );
    }

    #[tokio::test]
    async fn read_write_end_of_data_v0() {
        read_write!(
            EndOfDataV0,
            EndOfDataV0::new(STATE),
            [0, 7, 0x12, 0x34,   0, 0, 0, 12,  0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[tokio::test]
    async fn read_write_end_of_data_v1() {
        read_write!(
            EndOfDataV1,
            EndOfDataV1::new(1, STATE, Default::default()),
            [
                1, 7, 0x12, 0x34,         0, 0, 0, 24,
                0xde, 0xad, 0xbe, 0xef,   0x00, 0x00, 0x0e, 0x10,
                0x00, 0x00, 0x02, 0x58,   0x00, 0x00, 0x1c, 0x20,
            ]
        );
    }

    macro_rules! test_eod_pdu_version {
        ($version:expr, $raw:expr) => {
            if let Err(eod) = Payload::read(&mut $raw.as_slice()).await.unwrap() {
                assert_eq!($version, eod.version());
            } else {
                panic!("expected End of Data PDU");
            }
        }
    }

    #[tokio::test]
    async fn end_of_data_versions() {
        test_eod_pdu_version!(
            0,
            vec![0, 7, 0x12, 0x34, 0, 0, 0, 12,  0xde, 0xad, 0xbe, 0xef]
        );
        test_eod_pdu_version!(
            1,
            vec![
                0x01, 0x07, 0x8e, 0xef, 0x00, 0x00, 0x00, 0x18,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x8f,
                0x00, 0x00, 0x02, 0x58, 0x00, 0x00, 0x1c, 0x20
            ]
        );
        test_eod_pdu_version!(
            2,
            vec![
                0x02, 0x07, 0x8e, 0xef, 0x00, 0x00, 0x00, 0x18,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x8f,
                0x00, 0x00, 0x02, 0x58, 0x00, 0x00, 0x1c, 0x20
            ]
        );
    }

    #[tokio::test]
    async fn read_write_cache_reset() {
        read_write!(
            CacheReset,
            CacheReset::new(1),
            [1, 8, 0, 0,   0, 0, 0, 8]
        );
    }
}

