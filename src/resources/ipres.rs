//! IP Resources for use with RPKI certificates.
//!
//! The types herein are defined in RFC 3779 for use with certificates in
//! general. RFC 6487 specifies how to use them with RPKI certificates. In
//! particular, it prohibits the use of Subsequent AFI values for address
//! families, making them always 16 bit. Additionally, if the "inherit"
//! value is not used for an address family, the set of addresses must be
//! non-empty.

use std::{io, iter, mem};
use std::iter::FromIterator;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use bcder::{decode, encode};
use bcder::{BitString, Mode, OctetString, Tag};
use bcder::encode::PrimitiveContent;
use crate::cert::Overclaim;
use crate::roa::RoaIpAddress;
use crate::x509::ValidationError;
use super::chain::{Block, SharedChain};
use super::choice::ResourcesChoice;


//------------ IpResources ---------------------------------------------------

/// The IP Address Resources of an RPKI Certificate.
///
/// This type contains the resources for one of the address families that can
/// be contained in the certificate.
#[derive(Clone, Debug)]
pub struct IpResources(ResourcesChoice<IpBlocks>);

impl IpResources {
    /// Returns whether the resources are of the inherited variant.
    pub fn is_inherited(&self) -> bool {
        self.0.is_inherited()
    }

    /// Returns a reference to the blocks if there are any.
    pub fn as_blocks(&self) -> Option<&IpBlocks> {
        self.0.as_blocks()
    }

    /// Converts the resources into blocks or returns an error.
    pub fn to_blocks(&self) -> Result<IpBlocks, ValidationError> {
        self.0.to_blocks()
    }
}

impl IpResources {
    /// Takes all IP resources from the beginning of a constructed value.
    ///
    /// On success, the function returns a pair of optional IP resources,
    /// the first for IPv4, the second for IPv6.
    pub fn take_families_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(Option<Self>, Option<Self>), S::Err> {
        cons.take_sequence(|cons| {
            let mut v4 = None;
            let mut v6 = None;
            while let Some(()) = cons.take_opt_sequence(|cons| {
                let af = AddressFamily::take_from(cons)?;
                match af {
                    AddressFamily::Ipv4 => {
                        if v4.is_some() {
                            xerr!(return Err(decode::Malformed.into()));
                        }
                        v4 = Some(Self::take_from(cons)?);
                    }
                    AddressFamily::Ipv6 => {
                        if v6.is_some() {
                            xerr!(return Err(decode::Malformed.into()));
                        }
                        v6 = Some(Self::take_from(cons)?);
                    }
                }
                Ok(())
            })? { }
            if v4.is_none() && v6.is_none() {
                xerr!(return Err(decode::Malformed.into()));
            }
            Ok((v4, v6))
        })
    }

    /// Takes a single set of  IP resources from a constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_value(|tag, content| {
            if tag == Tag::NULL {
                content.to_null()?;
                Ok(ResourcesChoice::Inherit)
            }
            else if tag == Tag::SEQUENCE {
                IpBlocks::parse_content(content)
                    .map(ResourcesChoice::Blocks)
            }
            else {
                xerr!(Err(decode::Error::Malformed.into()))
            }
        }).map(IpResources)
    }

    pub fn encode_families(
        v4: Option<Self>,
        v6: Option<Self>
    ) -> Option<impl encode::Values> {
        if v4.is_none() && v6.is_none() {
            return None
        }
        Some(encode::sequence((
            v4.map(|v4| {
                encode::sequence((
                    AddressFamily::Ipv4.encode(),
                    v4.encode()
                ))
            }),
            v6.map(|v6| {
                encode::sequence((
                    AddressFamily::Ipv6.encode(),
                    v6.encode()
                ))
            }),
        )))
    }

    pub fn encode(self) -> impl encode::Values {
        match self.0 {
            ResourcesChoice::Inherit => encode::Choice2::One(().encode()),
            ResourcesChoice::Blocks(blocks) => {
                encode::Choice2::Two(blocks.encode())
            }
        }
    }
}


//------------ IpResourcesBuilder --------------------------------------------

#[derive(Clone, Debug)]
pub struct IpResourcesBuilder {
    res: Option<ResourcesChoice<IpBlocksBuilder>>
}

impl IpResourcesBuilder {
    pub fn new() -> Self {
        IpResourcesBuilder {
            res: None
        }
    }

    pub fn inherit(&mut self) {
        self.res = Some(ResourcesChoice::Inherit)
    }

    pub fn blocks<F>(&mut self, build: F)
    where F: FnOnce(&mut IpBlocksBuilder) {
        if self.res.as_ref().map(|res| res.is_inherited()).unwrap_or(true) {
            self.res = Some(ResourcesChoice::Blocks(IpBlocksBuilder::new()))
        }
        build(self.res.as_mut().unwrap().as_blocks_mut().unwrap())
    }
    
    pub fn finalize(self) -> Option<IpResources> {
        self.res.map(|choice| {
            IpResources(choice.map_blocks(IpBlocksBuilder::finalize))
        })
    }
}

impl Default for IpResourcesBuilder {
    fn default() -> Self {
        Self::new()
    }
}


//------------ IpBlocks ------------------------------------------------------

/// A sequence of address ranges for one address family.
#[derive(Clone, Debug)]
pub struct IpBlocks(SharedChain<IpBlock>);

impl IpBlocks {
    /// Creates an empty address blocks.
    pub fn empty() -> Self {
        IpBlocks(SharedChain::empty())
    }

    /// Creates address blocks from address resources.
    ///
    /// If the resources are of the inherited variant, returns an error.
    pub fn from_resources(
        res: Option<&IpResources>
    ) -> Result<Self, ValidationError> {
        match res.map(|res| &res.0) {
            Some(ResourcesChoice::Inherit) => Err(ValidationError),
            Some(ResourcesChoice::Blocks(ref some)) => Ok(some.clone()),
            None => Ok(IpBlocks::empty())
        }
    }

    /// Returns whether the blocks is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the address ranges in the block.
    pub fn iter(&self) -> impl Iterator<Item=&IpBlock> {
        self.0.iter()
    }

    /// Validates IP resources issued under these blocks.
    pub fn validate_issued(
        &self,
        res: Option<&IpResources>,
        mode: Overclaim,
    ) -> Result<IpBlocks, ValidationError> {
        match res.map(|res| &res.0) {
            Some(ResourcesChoice::Inherit) => Ok(self.clone()),
            Some(ResourcesChoice::Blocks(ref blocks)) => {
                match mode {
                    Overclaim::Refuse => {
                        if blocks.0.is_encompassed(&self.0) {
                            Ok(blocks.clone())
                        }
                        else {
                            Err(ValidationError)
                        }
                    }
                    Overclaim::Trim => {
                        match blocks.0.trim(&self.0) {
                            Ok(()) => Ok(blocks.clone()),
                            Err(new) => Ok(IpBlocks(new.into()))
                        }
                    }
                }
            },
            None => Ok(Self::empty()),
        }
    }


    /// Returns whether the address blocks cover the given ROA address prefix.
    pub fn contains(&self, addr: &RoaIpAddress) -> bool {
        let (min, max) = addr.range();
        for range in self.iter() {
            if range.min() <= min && range.max() >= max {
                return true
            }
        }
        false
    }
}

impl IpBlocks {
    /// Parses the content of an address block sequence.
    fn parse_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, S::Err> {
        let cons = content.as_constructed()?;
        let mut err = None;

        let res = SharedChain::from_iter(
            iter::repeat_with(|| IpBlock::take_opt_from(cons))
                .map(|item| {
                    match item {
                        Ok(Some(val)) => Some(val),
                        Ok(None) => None,
                        Err(e) => {
                            err = Some(e);
                            None
                        }
                    }
                })
                .take_while(|item| item.is_some())
                .map(Option::unwrap)
        );
        match err {
            Some(err) => Err(err),
            None => Ok(IpBlocks(res))
        }
    }

    pub fn encode(self) -> impl encode::Values {
        encode::sequence(encode::slice(self.0, |block| block.encode()))
    }
}


//------------ IpBlocksBuilder -----------------------------------------------

#[derive(Clone, Debug)]
pub struct IpBlocksBuilder(Vec<IpBlock>);

impl IpBlocksBuilder {
    fn new() -> Self {
        IpBlocksBuilder(Vec::new())
    }

    pub fn push<T: Into<IpBlock>>(&mut self, block: T) {
        self.0.push(block.into())
    }

    pub fn finalize(self) -> IpBlocks {
        IpBlocks(SharedChain::from_iter(self.0.into_iter()))
    }
}


//------------ IpBlock -------------------------------------------------------

/// A consecutive sequence of IP addresses.
#[derive(Clone, Copy, Debug)]
pub enum IpBlock {
    /// The block is expressed as a prefix.
    Prefix(Prefix),

    /// The block is expressed as a range.
    Range(AddressRange),
}

impl IpBlock {
    /// The smallest address of the block.
    pub fn min(&self) -> Addr {
        match *self {
            IpBlock::Prefix(ref inner) => inner.min(),
            IpBlock::Range(ref inner) => inner.min(),
        }
    }

    /// The largest address of the block.
    pub fn max(&self) -> Addr {
        match *self {
            IpBlock::Prefix(ref inner) => inner.max(),
            IpBlock::Range(ref inner) => inner.max(),
        }
    }
}

impl IpBlock {
    /// Takes an optional address block from the beginning of encoded value.
    fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_value(|tag, content| {
            if tag == Tag::BIT_STRING {
                Prefix::parse_content(content).map(IpBlock::Prefix)
            }
            else if tag == Tag::SEQUENCE {
                AddressRange::parse_content(content).map(IpBlock::Range)
            }
            else {
                xerr!(Err(decode::Malformed.into()))
            }
        })
    }

    /// Returns an encoder for the range.
    ///
    /// This encoder will produce a `IPAddressOrRange` value.
    pub fn encode(self) -> impl encode::Values {
        match self {
            IpBlock::Prefix(inner) => {
                encode::Choice2::One(inner.encode())
            }
            IpBlock::Range(inner) => {
                encode::Choice2::Two(inner.encode())
            }
        }
    }
}


//--- From

impl From<Prefix> for IpBlock {
    fn from(prefix: Prefix) -> Self {
        IpBlock::Prefix(prefix)
    }
}

impl From<AddressRange> for IpBlock {
    fn from(range: AddressRange) -> Self {
        IpBlock::Range(range)
    }
}

impl From<(Addr, Addr)> for IpBlock {
    fn from(range: (Addr, Addr)) -> Self {
        match AddressRange::new(range.0, range.1).into_prefix() {
            Ok(prefix) => prefix.into(),
            Err(range) => range.into(),
        }
    }
}


//--- Block

impl Block for IpBlock {
    type Item = Addr;

    fn new(min: Self::Item, max: Self::Item) -> Self {
        (min, max).into()
    }

    fn min(&self) -> Self::Item {
        self.min()
    }

    fn max(&self) -> Self::Item {
        self.max()
    }

    fn next(item: Self::Item) -> Option<Self::Item> {
        item.0.checked_add(1).map(Addr)
    }
}



//------------ AddressRange --------------------------------------------------

/// An IP address range.
///
/// This type appears in two variants in RFC 3779, either as a single prefix
/// (IPAddress) or as a range (IPAddressRange). Both cases actually cover a
/// consecutive range of addresses, so there is a minimum and a maximum
/// address covered by them. We simply model both of them as ranges of those
/// minimums and maximums.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AddressRange {
    /// The smallest IP address that is part of this range.
    min: Addr,

    /// The largest IP address that is part of this range.
    ///
    /// Note that this means that, unlike normal Rust ranges, our range is
    /// inclusive at the upper end. This is necessary to represent a range
    /// that goes all the way to the last address (which, for instance,
    /// `::0/0` does).
    max: Addr,
}

impl AddressRange {
    /// Creates a new address range from smallest and largest address.
    pub fn new(min: Addr, max: Addr) -> Self {
        AddressRange { min, max }
    }

    /// Returns the smallest IP address that is part of this range.
    pub fn min(&self) -> Addr {
        self.min
    }

    /// Returns the largest IP address that is still part of this range.
    pub fn max(&self) -> Addr {
        self.max
    }

    /// Sets a new minimum IP address.
    ///
    /// # Panics
    ///
    /// If you try to set the minimum to value larger than the current
    /// maximum, the method will panic.
    pub fn set_min(&mut self, min: Addr) {
        if min <= self.max() {
            self.min = min
        }
        else {
            panic!("trying to set minimum beyond current maximum");
        }
    }

    /// Sets a new maximum IP address.
    ///
    /// # Panics
    ///
    /// If you try to set the minimum to value smaller than the current
    /// minimum, the method will panic.
    pub fn set_max(&mut self, max: Addr) {
        if max > self.min() {
            self.max = max
        }
        else {
            panic!("trying to set maximum below current minimum");
        }
    }

    /// Tries to convert the range into a prefix.
    ///
    /// If this range cannot be expresses as a prefix, returns the range
    /// itself as an error.
    pub fn into_prefix(self) -> Result<Prefix, Self> {
        let len = (self.min.to_bits() ^ self.max.to_bits()).leading_zeros();
        let prefix = Prefix::new(self.min, len as u8);
        if prefix.range() == (self.min, self.max) {
            Ok(prefix)
        }
        else {
            Err(self)
        }
    }
}

impl AddressRange {
    fn parse_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, S::Err> {
        let mut cons = content.as_constructed()?;
        Ok(AddressRange {
            min: Prefix::take_from(&mut cons)?.min(),
            max: Prefix::take_from(&mut cons)?.max(),
        })
    }

    /*
    /// Skips over the address range at the beginning of a value.
    fn skip_opt_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        Self::take_opt_from(cons).map(|x| x.map(|_| ()))
    }
    */

    /// Calculates the prefix for the minimum address.
    ///
    /// This is a prefix with all trailing zeros dropped.
    fn min_to_prefix(&self) -> Prefix {
        Prefix::new(self.min, 128 - self.min.0.trailing_zeros() as u8)
    }

    /// Calculates the prefix for the maximum address.
    ///
    /// This is a prefix with all trailing ones dropped.
    fn max_to_prefix(&self) -> Prefix {
        Prefix::new(self.max, 128 - (!self.max.0).trailing_zeros() as u8)
    }

    /// Returns an encoder for the range.
    ///
    /// This encoder will produce a `IPAddressOrRange` value.
    pub fn encode(self) -> impl encode::Values {
        encode::sequence((
            self.min_to_prefix().encode(),
            self.max_to_prefix().encode(),
        ))
    }
}


//--- From

impl From<Prefix> for AddressRange {
    fn from(prefix: Prefix) -> Self {
        AddressRange::new(prefix.min(), prefix.max())
    }
}


//--- Block

impl Block for AddressRange {
    type Item = Addr;

    fn new(min: Self::Item, max: Self::Item) -> Self {
        Self::new(min, max)
    }

    fn min(&self) -> Self::Item {
        self.min()
    }

    fn max(&self) -> Self::Item {
        self.max()
    }

    fn next(item: Self::Item) -> Option<Self::Item> {
        item.0.checked_add(1).map(Addr)
    }
}


//------------ Prefix --------------------------------------------------------

/// An IP address prefix.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Prefix {
    /// The address of the prefix.
    ///
    /// The unused bits are zero.
    addr: Addr,

    /// The length of the prefix.
    ///
    /// This will never be more than 128.
    len: u8,
}

impl Prefix {
    /// Creates a new prefix from an address and a length.
    ///
    /// # Panics
    ///
    /// This function panics of `len` is larger than 128.
    pub fn new<A: Into<Addr>>(addr: A, len: u8) -> Self {
        assert!(len <= 128);
        Prefix { 
            addr: addr.into().to_min(len),
            len
        }
    }

    /// Creates a new prefix from its encoding as a BIT STRING.
    pub fn from_bit_string(src: &BitString) -> Result<Self, decode::Error> {
        if src.octet_len() > 16 {
            xerr!(return Err(decode::Malformed))
        }
        let mut addr = 0;
        for octet in src.octets() {
            addr = (addr << 8) | (u128::from(octet))
        }
        for _ in src.octet_len()..16 {
            addr <<= 8;
        }
        Ok(Self::new(addr, src.bit_len() as u8))
    }

    /// Returns the raw address of the prefix.
    pub fn addr(self) -> Addr {
        self.addr
    }

    /// Returns the length of the prefix.
    pub fn addr_len(self) -> u8 {
        self.len
    }

    /// Converts the prefix into an IPv4 address.
    pub fn to_v4(self) -> Ipv4Addr {
        self.addr.into()
    }

    /// Converts the prefix into an IPv6 address.
    pub fn to_v6(self) -> Ipv6Addr {
        self.addr.into()
    }

    /// Returns the range of addresses covered by this prefix.
    ///
    /// The first element of the returned pair is the smallest covered
    /// address, the second element is the largest.
    pub fn range(self) -> (Addr, Addr) {
        // self.addr has all unused bits cleared, so we don’t need to
        // explicitely do that for min.
        (self.addr, self.addr.to_max(self.len))
    }

    /// Returns the smallest address covered by the prefix.
    pub fn min(self) -> Addr {
        self.addr
    }

    /// Returns the largest address convered by the prefix.
    pub fn max(self) -> Addr {
        self.addr.to_max(self.addr_len())
    }

    /// Takes an encoded prefix from a source.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        Ok(Self::from_bit_string(&BitString::take_from(cons)?)?)
    }

    /// Parses the content of a prefix.
    pub fn parse_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, S::Err> {
        Ok(Self::from_bit_string(
            &BitString::from_content(content)?
        )?)
    }
}

impl encode::PrimitiveContent for Prefix {
    const TAG: Tag = Tag::BIT_STRING;

    fn encoded_len(&self, _: Mode) -> usize {
        if self.len % 8 == 0 {
            self.len as usize / 8 + 1
        }
        else {
            self.len as usize / 8 + 2
        }
    }

    fn write_encoded<W: io::Write>(
        &self, 
        _: Mode, 
        target: &mut W
    ) -> Result<(), io::Error> {
        // The type ensures that all the unused bits are zero, so we don’t
        // need to take care of that here.
        let len = if self.len % 8 == 0 { self.len }
                  else { self.len + 1 };
        target.write_all(&[(self.len % 8) as u8])?;
        let addr = self.addr.to_bytes();
        target.write_all(&addr[..len as usize])
    }
}


//------------ Addr ----------------------------------------------------------

/// An adddress.
///
/// This can be both an IPv4 and IPv6 address. It keeps the address internally
/// as a 128 bit unsigned integer. IPv6 address are kept in there in host byte
/// order while IPv4 addresses are kept in the upper four bytes. This makes it
/// possible to count prefix lengths the same way for both addresses, i.e., 
/// starting from the top of the raw integer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Addr(u128);

impl Addr {
    /// Creates a new address from 128 raw bits in host byte order.
    pub fn from_bits(bits: u128) -> Self {
        Addr(bits)
    }

    /// Creates a new address value for an IPv4 address.
    pub fn from_v4(addr: Ipv4Addr) -> Self {
        Addr::from_bits(u128::from(u32::from(addr)) << 96)
    }

    /// Creates a new address value for an IPv4 address.
    pub fn from_v6(addr: Ipv6Addr) -> Self {
        Addr::from_bits(u128::from(addr))
    }

    /// Returns the raw bits of the underlying integer.
    pub fn to_bits(self) -> u128 {
        self.0
    }

    /// Converts the address value into an IPv4 address.
    ///
    /// The methods disregards the lower twelve bytes of the value.
    pub fn to_v4(self) -> Ipv4Addr {
        ((self.0 >> 96) as u32).into()
    }

    /// Converts the address value into an IPv6 address.
    pub fn to_v6(self) -> Ipv6Addr {
        self.0.into()
    }

    /// Returns a byte array for the address.
    pub fn to_bytes(self) -> [u8; 16] {
        unsafe { mem::transmute(self.0.to_be()) }
    }

    /// Returns an address with all but the first `prefix_len` bits cleared.
    ///
    /// The first `prefix_len` bits are retained. Thus, the returned address
    /// is the smallest address in a prefix of this length.
    pub fn to_min(self, prefix_len: u8) -> Self {
        if prefix_len >= 128 {
            self
        }
        else {
            Addr(self.0 & !(!0 >> u32::from(prefix_len)))
        }
    }

    /// Returns an address with all but the first `prefix_len` bits set.
    ///
    /// The first `prefix_len` bits are retained. Thus, the returned address
    /// is the largest address in a prefix of this length.
    pub fn to_max(self, prefix_len: u8) -> Self {
        if prefix_len >= 128 {
            self
        }
        else {
            Addr(self.0 | (!0 >> prefix_len as usize))
        }
    }
}


//--- From

impl From<u128> for Addr {
    fn from(addr: u128) -> Addr {
        Addr::from_bits(addr)
    }
}

impl From<Ipv4Addr> for Addr {
    fn from(addr: Ipv4Addr) -> Addr {
        Addr::from_v4(addr)
    }
}

impl From<Ipv6Addr> for Addr {
    fn from(addr: Ipv6Addr) -> Addr {
        Addr::from_v6(addr)
    }
}

impl From<IpAddr> for Addr {
    fn from(addr: IpAddr) -> Addr {
        match addr {
            IpAddr::V4(addr) => Addr::from(addr),
            IpAddr::V6(addr) => Addr::from(addr)
        }
    }
}

impl From<Addr> for u128 {
    fn from(addr: Addr) -> u128 {
        addr.to_bits()
    }
}

impl From<Addr> for Ipv4Addr {
    fn from(addr: Addr) -> Ipv4Addr {
        addr.to_v4()
    }
}

impl From<Addr> for Ipv6Addr {
    fn from(addr: Addr) -> Ipv6Addr {
        addr.to_v6()
    }
}


//------------ AddressFamily -------------------------------------------------

/// The address family of an IP resources value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    /// IPv4.
    ///
    /// This is encoded by a two byte octet string with value `0x00 0x01`.
    Ipv4,

    /// IPv6.
    ///
    /// This is encoded by a two byte octet string with value `0x00 0x02`.
    Ipv6
}

impl AddressFamily {
    /// Takes a single address family from the beginning of a value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let str = OctetString::take_from(cons)?;
        let mut octets = str.octets();
        let first = match octets.next() {
            Some(first) => first,
            None => xerr!(return Err(decode::Malformed.into()))
        };
        let second = match octets.next() {
            Some(second) => second,
            None => xerr!(return Err(decode::Malformed.into()))
        };
        if octets.next().is_some() {
            xerr!(return Err(decode::Malformed.into()))
        }
        match (first, second) {
            (0, 1) => Ok(AddressFamily::Ipv4),
            (0, 2) => Ok(AddressFamily::Ipv6),
            _ => xerr!(Err(decode::Malformed.into())),
        }
    }

    pub fn encode(self) -> impl encode::Values {
        OctetString::encode_slice(
            match self {
                AddressFamily::Ipv4 => b"\x00\x01",
                AddressFamily::Ipv6 => b"\x00\x02",
            }
        )
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn addr_from() {
        assert_eq!(
            Addr::from(0x12345678_12345678),
            Addr(0x12345678_12345678)
        );
        assert_eq!(
            u128::from(Addr(0x12345678_12345678)),
            0x12345678_12345678
        );
        assert_eq!(
            Addr::from(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            Addr(0x7F000001_00000000_00000000_00000000)
        );
        assert_eq!(
            Ipv4Addr::from(Addr(0x7F000001_00000000_00000000_00000000)),
            Ipv4Addr::new(127, 0, 0, 1)
        );
        assert_eq!(
            Addr::from(IpAddr::V6(Ipv6Addr::new(
                0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56
            ))),
            Addr(0x00120034005600780090001200340056)
        );
        assert_eq!(
            Ipv6Addr::from(Addr(0x00120034005600780090001200340056)),
            Ipv6Addr::new(
                0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56
            )
        );
    }
    
    #[test]
    fn addr_to_min_max() {
        assert_eq!(
            Addr(0x12345678_12345678_12345678_12345678).to_min(11).0,
            0x12200000_00000000_00000000_00000000
        );
        assert_eq!(
            Addr(0x12345678_12345678_12345678_12345678).to_max(11).0,
            0x123fffff_ffffffff_ffffffff_ffffffff
        );
    }
}
