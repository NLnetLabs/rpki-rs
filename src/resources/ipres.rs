//! IP Resources for use with RPKI certificates.
//!
//! The types herein are defined in RFC 3779 for use with certificates in
//! general. RFC 6487 specifies how to use them with RPKI certificates. In
//! particular, it prohibits the use of Subsequent AFI values for address
//! families, making them always 16 bit. Additionally, if the "inherit"
//! value is not used for an address family, the set of addresses must be
//! non-empty.

use std::{fmt, io, iter, mem, str};
use std::fmt::Display;
use std::iter::FromIterator;
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::str::FromStr;
use bcder::{decode, encode};
use bcder::{BitString, Mode, OctetString, Tag, xerr};
use bcder::encode::PrimitiveContent;
use derive_more::{Display, From};
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpResources(ResourcesChoice<IpBlocks>);

impl IpResources {
    /// Creates a new IpResources with a ResourcesChoice::Inherit
    pub fn inherit() -> Self {
        IpResources(ResourcesChoice::Inherit)
    }

    /// Creates a new IpResources for the given blocks.
    pub fn blocks(blocks: IpBlocks) -> Self {
        IpResources(ResourcesChoice::Blocks(blocks))
    }

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

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        match self.0 {
            ResourcesChoice::Inherit => encode::Choice2::One(().encode()),
            ResourcesChoice::Blocks(ref blocks) => {
                encode::Choice2::Two(blocks.encode_ref())
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


//------------ IpBlocksForFamily ---------------------------------------------

/// IpBlocks for a specific family, to help formatting
pub struct IpBlocksForFamily<'a> {
    family: AddressFamily,
    blocks: &'a IpBlocks
}

impl<'a> IpBlocksForFamily<'a> {
    pub fn v4(blocks: &'a IpBlocks) -> Self {
        IpBlocksForFamily {
            family: AddressFamily::Ipv4,
            blocks
        }
    }
    pub fn v6(blocks: &'a IpBlocks) -> Self {
        IpBlocksForFamily {
            family: AddressFamily::Ipv6,
            blocks
        }
    }
}

impl<'a> fmt::Display for IpBlocksForFamily<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut blocks_iter = self.blocks.iter();

        if let Some(el) = blocks_iter.next() {
            match self.family {
                AddressFamily::Ipv4 => el.fmt_v4(f)?,
                AddressFamily::Ipv6 => el.fmt_v6(f)?,
            }
        }

        for el in blocks_iter {
            write!(f, ", ")?;
            match self.family {
                AddressFamily::Ipv4 => el.fmt_v4(f)?,
                AddressFamily::Ipv6 => el.fmt_v6(f)?,
            }
        }

        Ok(())
    }
}

//------------ IpBlocks ------------------------------------------------------

/// A sequence of address ranges for one address family.
#[derive(Clone, Debug, Eq, PartialEq)]
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
                        if self.contains(blocks) {
                            Ok(blocks.clone())
                        }
                        else {
                            Err(ValidationError)
                        }
                    }
                    Overclaim::Trim => {
                        Ok(blocks.intersection(&self))
                    }
                }
            },
            None => Ok(Self::empty()),
        }
    }


    /// Returns whether the address blocks cover the given ROA address prefix.
    pub fn contains_roa(&self, addr: &RoaIpAddress) -> bool {
        let (min, max) = addr.range();
        for range in self.iter() {
            if range.min() <= min && range.max() >= max {
                return true
            }
        }
        false
    }
}

/// # Set operations
///
impl IpBlocks {
    /// Returns whether this IpBlocks contains the other in its entirety.
    pub fn contains(&self, other: &Self) -> bool {
        other.0.is_encompassed(&self.0)
    }

    /// Return the intersection of this IpBlocks and the other. I.e. all
    /// resources which are found in both.
    pub fn intersection(&self, other: &Self) -> Self {
        match self.0.trim(&other.0) {
            Ok(()) => self.clone(),
            Err(owned) => IpBlocks(SharedChain::from_owned(owned))
        }
    }

    /// Returns a new IpBlocks with the union of this and the other IpBlocks.
    ///
    /// i.e. all resources found in one or both IpBlocks.
    pub fn union(&self, other: &Self) -> Self {
        IpBlocks(
            FromIterator::from_iter(
                self.0.iter().cloned().chain(other.0.iter().cloned())
            )
        )
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

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence(encode::slice(&self.0, |block| block.encode()))
    }

    /// Returns an IpBlocksForFamily for IPv4 for this,
    /// to help formatting.
    pub fn as_v4(&self) -> IpBlocksForFamily {
        IpBlocksForFamily::v4(&self)
    }

    /// Returns an IpBlocksForFamily for IPv4 for this,
    /// to help formatting.
    pub fn as_v6(&self) -> IpBlocksForFamily {
        IpBlocksForFamily::v6(&self)
    }
}

impl FromStr for IpBlocks {
    type Err = FromStrError;

    /// This parses comma separated IpBlocks (ranges, prefixes
    /// and single addresses). This will throw an error if the
    /// input contains a mix of AddressFamily.
    fn from_str(s: &str) -> Result<Self, Self::Err> {

        let family = if s.contains('.') {
            AddressFamily::Ipv4
        } else {
            AddressFamily::Ipv6
        };

        let mut builder = IpBlocksBuilder::default();

        for el in s.split(',') {
            let s = el.trim();
            if s.is_empty() {
                continue
            }
            match family {
                AddressFamily::Ipv4 => {
                    if let Ok(block) = IpBlock::from_v4_str(&s) {
                        builder.push(block)
                    } else {
                        return Err(FromStrError::FamilyMismatch)
                    }
                },
                AddressFamily::Ipv6 => {
                    if let Ok(block) = IpBlock::from_v6_str(&s) {
                        builder.push(block)
                    } else {
                        return Err(FromStrError::FamilyMismatch)
                    }
                }
            }
        }

        Ok(builder.finalize())
    }
}

impl FromIterator<IpBlock> for IpBlocks {
    fn from_iter<I: IntoIterator<Item = IpBlock>>(iter: I) -> Self {
        Self(SharedChain::from_iter(iter))
    }
}


//------------ IpBlocksBuilder -----------------------------------------------

#[derive(Clone, Debug)]
pub struct IpBlocksBuilder(Vec<IpBlock>);

impl IpBlocksBuilder {
    pub fn new() -> Self {
        IpBlocksBuilder(Vec::new())
    }

    pub fn push<T: Into<IpBlock>>(&mut self, block: T) {
        self.0.push(block.into())
    }

    pub fn finalize(self) -> IpBlocks {
        IpBlocks::from_iter(self.0.into_iter())
    }
}

impl Default for IpBlocksBuilder {
    fn default() -> Self {
        IpBlocksBuilder::new()
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
    /// Creates a new block from an IPv4 representation.
    pub fn from_v4_str(s: &str) -> Result<Self, FromStrError> {
        if let Some(sep) = s.find('/') {
            Prefix::from_v4_str_sep(s, sep).map(IpBlock::Prefix)
        }
        else if let Some(sep) = s.find('-') {
            AddressRange::from_v4_str_sep(s, sep).map(IpBlock::Range)
        }
        else {
            let addr = Addr::from(Ipv4Addr::from_str(s)?);
            Ok(IpBlock::Range(AddressRange::new(addr, addr.to_max(32))))
        }
    }

    /// Creates a new block from an IPv6 representation.
    pub fn from_v6_str(s: &str) -> Result<Self, FromStrError> {
        if let Some(sep) = s.find('/') {
            Prefix::from_v6_str_sep(s, sep).map(IpBlock::Prefix)
        }
        else if let Some(sep) = s.find('-') {
            AddressRange::from_v6_str_sep(s, sep).map(IpBlock::Range)
        }
        else {
            let addr = Ipv6Addr::from_str(s)?.into();
            Ok(IpBlock::Range(AddressRange::new(addr, addr)))
        }
    }

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

    /// Formats the block as a IPv4 block.
    pub fn fmt_v4(self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IpBlock::Prefix(prefix) => prefix.fmt_v4(f),
            IpBlock::Range(range) => range.fmt_v4(f),
        }
    }

    /// Formats the block as a IPv4 block.
    pub fn fmt_v6(self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IpBlock::Prefix(prefix) => prefix.fmt_v6(f),
            IpBlock::Range(range) => range.fmt_v6(f),
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


//--- From and FromStr

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

impl str::FromStr for IpBlock {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(sep) = s.find('/') {
            Prefix::from_str_sep(s, sep).map(IpBlock::Prefix)
        }
        else if let Some(sep) = s.find('-') {
            AddressRange::from_str_sep(s, sep).map(IpBlock::Range)
        }
        else {
            let (min, max) = match IpAddr::from_str(s)? {
                IpAddr::V4(addr) => {
                    let addr = Addr::from(addr);
                    (addr, addr.to_max(32))
                },
                IpAddr::V6(addr) => {
                    let addr = Addr::from(addr);
                    (addr, addr)
                }
            };
            Ok(IpBlock::Range(AddressRange::new(min, max)))
        }
    }
}


//--- PartialEq and Eq

impl PartialEq for IpBlock {
    fn eq(&self, other: &Self) -> bool {
        self.is_equivalent(other)
    }
}

impl Eq for IpBlock { }


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

    /// Creates a new range from a string with known separator position.
    fn from_str_sep(s: &str, sep: usize) -> Result<Self, FromStrError> {
        let min = IpAddr::from_str(&s[..sep])?;
        let max = IpAddr::from_str(&s[sep + 1..])?;
        match (min.is_ipv4(), max.is_ipv4()) {
            (true, true) => {
                Ok(Self::new(min.into(), Addr::from(max).to_max(32)))
            }
            (false, false) => {
                Ok(Self::new(min.into(), max.into()))
            }
            _ => Err(FromStrError::FamilyMismatch)
        }
    }

    /// Creates a new range from an IPv4 string with known separator.
    fn from_v4_str_sep(s: &str, sep: usize) -> Result<Self, FromStrError> {
        Ok(Self::new(
            Ipv4Addr::from_str(&s[..sep])?.into(),
            Addr::from(Ipv4Addr::from_str(&s[sep + 1..])?).to_max(32)
        ))
    }

    /// Creates a new range from an IPv4 string.
    pub fn from_v4_str(s: &str) -> Result<Self, FromStrError> {
        let sep = s.find('-').ok_or(FromStrError::MissingSeparator)?;
        Self::from_v4_str_sep(s, sep)
    }

    /// Creates a new range from an IPv6 string with known separator.
    fn from_v6_str_sep(s: &str, sep: usize) -> Result<Self, FromStrError> {
        Ok(Self::new(
            Ipv6Addr::from_str(&s[..sep])?.into(),
            Ipv6Addr::from_str(&s[sep + 1..])?.into()
        ))
    }

    /// Creates a new range from an IPv4 string.
    pub fn from_v6_str(s: &str) -> Result<Self, FromStrError> {
        let sep = s.find('-').ok_or(FromStrError::MissingSeparator)?;
        Self::from_v6_str_sep(s, sep)
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

    /// Formats the range as an IPv4 range.
    pub fn fmt_v4(self, f: &mut fmt::Formatter) -> fmt::Result {
        let min = self.min.to_v4();
        let max = self.max.to_v4();

        if min == max {
            min.fmt(f)
        } else {
            write!(f, "{}-{}", min, max)
        }
    }

    /// Formats the range as an IPv6 range.
    pub fn fmt_v6(self, f: &mut fmt::Formatter) -> fmt::Result {
        let min = self.min.to_v6();
        let max = self.max.to_v6();

        if min == max {
            min.fmt(f)
        } else {
            write!(f, "{}-{}", min, max)
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


//--- From and FromStr

impl From<(Addr, Addr)> for AddressRange {
    fn from((min, max): (Addr, Addr)) -> Self {
        AddressRange::new(min, max)
    }
}

impl From<Prefix> for AddressRange {
    fn from(prefix: Prefix) -> Self {
        AddressRange::new(prefix.min(), prefix.max())
    }
}

impl FromStr for AddressRange {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sep = s.find('-').ok_or(FromStrError::MissingSeparator)?;
        Self::from_str_sep(s, sep)
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

    /// Creates a prefix from a string with a known position of the slash.
    fn from_str_sep(s: &str, sep: usize) -> Result<Self, FromStrError> {
        let addr = IpAddr::from_str(&s[..sep])?;
        let len = u8::from_str(&s[sep + 1..])?;
        if addr.is_ipv4() {
            if len > 32 {
                // XXX Produce an artifical overflow error.
                let _ = u8::from_str("256")?;
            }
        }
        else if len > 128 {
            // XXX Produce an artifical overflow error.
            let _ = u8::from_str("256")?;
        }
        Ok(Prefix::new(addr, len))
    }

    /// Creates a prefix from a IPv4 string with a known position of the slash.
    fn from_v4_str_sep(s: &str, sep: usize) -> Result<Self, FromStrError> {
        let addr = Ipv4Addr::from_str(&s[..sep])?;
        let len = u8::from_str(&s[sep + 1..])?;
        if len > 32 {
            // XXX Produce an artifical overflow error.
            let _ = u8::from_str("256")?;
        }
        Ok(Prefix::new(addr, len))
    }

    /// Creates a prefix from an IPv4 string.
    pub fn from_v4_str(s: &str) -> Result<Self, FromStrError> {
        let sep = s.find('/').ok_or(FromStrError::MissingSeparator)?;
        Self::from_v4_str_sep(s, sep)
    }

    /// Creates a prefix from a IPv6 string with a known position of the slash.
    fn from_v6_str_sep(s: &str, sep: usize) -> Result<Self, FromStrError> {
        let addr = Ipv6Addr::from_str(&s[..sep])?;
        let len = u8::from_str(&s[sep + 1..])?;
        if len > 128 {
            // XXX Produce an artifical overflow error.
            let _ = u8::from_str("256")?;
        }
        Ok(Prefix::new(addr, len))
    }

    /// Creates a prefix from an IPv6 string.
    pub fn from_v6_str(s: &str) -> Result<Self, FromStrError> {
        let sep = s.find('/').ok_or(FromStrError::MissingSeparator)?;
        Self::from_v6_str_sep(s, sep)
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

    /// Formats the prefix as an IPv4 prefix.
    pub fn fmt_v4(self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt_v4(f)?;
        write!(f, "/{}", self.len)
    }

    /// Formats the prefix as an IPv4 prefix.
    pub fn fmt_v6(self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt_v6(f)?;
        write!(f, "/{}", self.len)
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


//--- FromStr

impl FromStr for Prefix {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sep = s.find('/').ok_or(FromStrError::MissingSeparator)?;
        Self::from_str_sep(s, sep)
    }
}


//--- PrimitiveContent

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
        /*
        let len = if self.len % 8 == 0 { self.len / 8 }
                  else { self.len / 8 + 1 };
        if self.len % 8 == 0 {
            target.write_all(&[0])?;
        }
        else {
            target.write_all(&[(8 - self.len % 8) as u8])?;
        }
        let addr = self.addr.to_bytes();
        target.write_all(&addr[..len as usize])
        */

        let addr = self.addr.to_bytes();
        if self.len % 8 == 0 {
            target.write_all(&[0])?;
            target.write_all(&addr[..(self.len / 8) as usize])
        }
        else {
            target.write_all(&[(8 - self.len % 8) as u8])?;
            target.write_all(&addr[..(self.len / 8 + 1) as usize])
        }
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

    /// Creates a new address from a IPv4 string representation.
    pub fn from_v4_str(s: &str) -> Result<Self, AddrParseError> {
        Ipv4Addr::from_str(s).map(Into::into)
    }

    /// Creates a new address from a IPv4 string representation.
    pub fn from_v6_str(s: &str) -> Result<Self, AddrParseError> {
        Ipv6Addr::from_str(s).map(Into::into)
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

    /// Formats the address as a IPv4 address.
    pub fn fmt_v4(self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&Ipv4Addr::from(self), f)
    }

    /// Formats the address as a IPv4 address.
    pub fn fmt_v6(self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&Ipv6Addr::from(self), f)
    }

}


//--- From and FromStr

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


impl FromStr for Addr {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, AddrParseError> {
        IpAddr::from_str(s).map(Into::into)
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


//------------ FromStrError --------------------------------------------------

#[derive(Clone, Debug, Display, Eq, From, PartialEq)]
pub enum FromStrError {
    #[display(fmt="{}", _0)]
    Addr(AddrParseError),

    #[display(fmt="bad prefix length: {}", _0)]
    PrefixLen(ParseIntError),

    #[display(fmt="missing separator")]
    MissingSeparator,

    #[display(fmt="address family mismatch")]
    FamilyMismatch,

    #[display(fmt="Cannot parse blocks.")]
    BadBlocks,
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use bcder::encode::Values;
    use unwrap::unwrap;
    use super::*;

    #[test]
    fn ip_blocks_to_v4_str() {
        let expected_str = "10.0.0.0, 10.1.0.0-10.1.2.255, 192.168.0.0/16";
        let blocks = IpBlocks::from_str(expected_str).unwrap();
        assert_eq!(expected_str, &blocks.as_v4().to_string())
    }

    #[test]
    fn ip_blocks_to_v6_str() {
        let expected_str = "::1, 2001:db8::/32";
        let blocks = IpBlocks::from_str(expected_str).unwrap();
        assert_eq!(expected_str, &blocks.as_v6().to_string())
    }

    #[test]
    fn ip_blocks_cannot_parse_mix() {
        let input = "10.0.0.0, ::1, 2001:db8::/32";
        assert_eq!(
            IpBlocks::from_str(input).err(),
            Some(FromStrError::FamilyMismatch)
        );
    }

    #[test]
    fn ip_blocks_from_empty_str() {
        let expected_str = "";
        let blocks = IpBlocks::from_str("").unwrap();
        assert_eq!(expected_str, blocks.as_v4().to_string());
        assert_eq!(expected_str, blocks.as_v6().to_string());
    }

    #[test]
    fn ip_blocks_contains() {
        let super_set = IpBlocks::from_str("10.0.0.0/16, 192.168.0.0/16").unwrap();
        let same = IpBlocks::from_str("10.0.0.0/16, 192.168.0.0/16").unwrap();
        let higher_block = IpBlocks::from_str("192.168.0.0/16").unwrap();
        let smaller_left = IpBlocks::from_str("10.0.0.0/17").unwrap();
        let smaller_right = IpBlocks::from_str("10.0.0.0/17").unwrap();
        let smaller = IpBlocks::from_str("10.0.0.1-10.0.255.254").unwrap();
        let bigger_left = IpBlocks::from_str("19.9.9.255-10.0.255.255").unwrap();
        let bigger_right = IpBlocks::from_str("19.9.9.255-10.1.0.0").unwrap();
        let bigger = IpBlocks::from_str("19.9.9.255-10.1.0.0").unwrap();

        assert!(super_set.contains(&same));
        assert!(super_set.contains(&higher_block));
        assert!(super_set.contains(&smaller_left));
        assert!(super_set.contains(&smaller_right));
        assert!(super_set.contains(&smaller));
        assert!(!super_set.contains(&bigger_left));
        assert!(!super_set.contains(&bigger_right));
        assert!(!super_set.contains(&bigger ));
    }

    #[test]
    fn ip_blocks_neighbours() {
        let super_set = unwrap!(IpBlocks::from_str(
            "10.0.0.0-10.0.0.10, 10.0.0.11-10.0.0.20"
        ));
        let between = unwrap!(IpBlocks::from_str("10.0.0.5-10.0.0.15"));

        assert!(super_set.contains(&between));
    }

    #[test]
    fn ip_blocks_intersection() {
        // Note: the IpBlocks::intersection function delegates to Chain::trim
        // which has been well fuzzed. Adding these tests here though for
        // readability and regression testing.

        // this:            |----
        // other:     |---|
        let this = IpBlocks::from_str("10.0.1.0-10.0.1.255").unwrap();
        let other = IpBlocks::from_str("10.0.0.0-10.0.0.255").unwrap();
        let expected = IpBlocks::empty();

        assert_eq!(this.intersection(&other), expected);
        assert_eq!(other.intersection(&this), expected);

        // this:            |----
        // other:     |-----|
        let this = IpBlocks::from_str("10.0.1.0/24").unwrap();
        let other = IpBlocks::from_str("10.0.0.0-10.0.1.0").unwrap();
        let expected = IpBlocks::from_str("10.0.1.0-10.0.1.0").unwrap();
        assert_eq!(expected, this.intersection(&other));
        assert_eq!(expected, other.intersection(&this));

        // this:          |----
        // other:     |-----|
        let this = IpBlocks::from_str("10.0.1.0/24").unwrap();
        let other = IpBlocks::from_str("10.0.0.0-10.0.1.27").unwrap();
        let expected = IpBlocks::from_str("10.0.1.0-10.0.1.27").unwrap();
        assert_eq!(expected, this.intersection(&other));
        assert_eq!(expected, other.intersection(&this));

        // this:          |----|
        // other:       |~{----|
        let this = IpBlocks::from_str("10.0.1.0/24").unwrap();
        let other = IpBlocks::from_str("10.0.0.0/23").unwrap();
        let expected = IpBlocks::from_str("10.0.1.0/24").unwrap();
        assert_eq!(expected, this.intersection(&other));
        assert_eq!(expected, other.intersection(&this));

        // this:          |----|
        // other:       |~{-----|
        let this = IpBlocks::from_str("10.0.1.0/24").unwrap();
        let other = IpBlocks::from_str("10.0.0.0-10.0.2.0").unwrap();
        let expected = IpBlocks::from_str("10.0.1.0/24").unwrap();
        assert_eq!(expected, this.intersection(&other));
        assert_eq!(expected, other.intersection(&this));

        // this:   |----------|
        // other:  |~~{-----|
        let this = IpBlocks::from_str("10.0.1.0/24").unwrap();
        let other = IpBlocks::from_str("10.0.1.3-10.0.1.98").unwrap();
        let expected = IpBlocks::from_str("10.0.1.3-10.0.1.98").unwrap();
        assert_eq!(expected, this.intersection(&other));
        assert_eq!(expected, other.intersection(&this));

        let this = IpBlocks::from_str("10.0.1.0/24").unwrap();
        let other = IpBlocks::from_str("10.0.1.0-10.0.1.98").unwrap();
        let expected = IpBlocks::from_str("10.0.1.0-10.0.1.98").unwrap();
        assert_eq!(expected, this.intersection(&other));
        assert_eq!(expected, other.intersection(&this));

        // this:   |----------|
        // other:  |~~{-------|
        let this = IpBlocks::from_str("10.0.1.0/24").unwrap();
        let other = IpBlocks::from_str("10.0.1.3-10.0.1.255").unwrap();
        let expected = IpBlocks::from_str("10.0.1.3-10.0.1.255").unwrap();
        assert_eq!(expected, this.intersection(&other));
        assert_eq!(expected, other.intersection(&this));

        let this = IpBlocks::from_str("10.0.1.0/24").unwrap();
        let other = IpBlocks::from_str("10.0.1.0-10.0.1.255").unwrap();
        let expected = IpBlocks::from_str("10.0.1.0-10.0.1.255").unwrap();
        assert_eq!(expected, this.intersection(&other));
        assert_eq!(expected, other.intersection(&this));

        // this:   |----------|
        // other:  |~~{----------|
        let this = IpBlocks::from_str("10.0.1.0/24").unwrap();
        let other = IpBlocks::from_str("10.0.1.3-10.0.2.0").unwrap();
        let expected = IpBlocks::from_str("10.0.1.3-10.0.1.255").unwrap();
        // Looking at the number, IPv4 is modelled as the left most 4 bytes in a u128
        // so the max number of the intersection comes out as 10.0.1.255 with the
        // remaining bytes set to FF. This is not significant but is not treated
        // as equals.
        //
        // In short we assert here that the as_v4().to_string() is equal, because
        // then these bytes are dropped.
        assert_eq!(
            this.intersection(&other).as_v4().to_string(),
            expected.as_v4().to_string()
        );
        assert_eq!(
            other.intersection(&this).as_v4().to_string(),
            expected.as_v4().to_string()
        );

        // this:   |------|
        // other:         |---------|
        let this = IpBlocks::from_str("10.0.0.0/24").unwrap();
        let other = IpBlocks::from_str("10.0.0.255-10.0.1.0").unwrap();
        let expected = IpBlocks::from_str("10.0.0.255/32").unwrap();
        assert_eq!(
            this.intersection(&other).as_v4().to_string(),
            expected.as_v4().to_string()
        );
        assert_eq!(
            other.intersection(&this).as_v4().to_string(),
            expected.as_v4().to_string()
        );

        // this:     |-----|
        // other:            |---
        let this = IpBlocks::from_str("10.0.0.0/24").unwrap();
        let other = IpBlocks::from_str("10.0.1.0/24").unwrap();
        let expected = IpBlocks::empty();
        assert_eq!(expected, this.intersection(&other));
        assert_eq!(expected, other.intersection(&this));
    }

    #[test]
    fn ip_block_from_v4_str() {
        fn check(s: &str, prefix: bool, min: &str, max: &str) {
            let block = unwrap!(IpBlock::from_v4_str(s));
            let is_prefix = match block {
                IpBlock::Prefix(_) => true,
                _ => false
            };
            assert_eq!(prefix, is_prefix);
            assert_eq!(
                block.min(),
                Addr::from(unwrap!(Ipv4Addr::from_str(min))).to_min(32)
            );
            assert_eq!(
                block.max(),
                Addr::from(unwrap!(Ipv4Addr::from_str(max))).to_max(32)
            );
        }

        check(
            "127.0.0.0/8", true,
            "127.0.0.0", "127.255.255.255"
        );
        check(
            "127.0.0.0-199.0.0.0", false,
            "127.0.0.0", "199.0.0.0"
        );
        check(
            "127.0.0.0", false,
            "127.0.0.0", "127.0.0.0"
        );
        assert!(IpBlock::from_v4_str("127.0.0.0/82").is_err());
        assert!(IpBlock::from_v4_str("127.0.0.0/282").is_err());
        assert!(IpBlock::from_v4_str("127.0.0.0/-282").is_err());
        assert!(IpBlock::from_v4_str("::32/82").is_err());
        assert!(IpBlock::from_v4_str("::32-::1").is_err());
    }

    #[test]
    fn ip_block_from_v6_str() {
        assert_eq!(
            IpBlock::from_v6_str("7f00::").unwrap(),
            IpBlock::Range((Addr(127 << 120), Addr(127 << 120)).into())
        );
        assert_eq!(
            IpBlock::from_v6_str("7f00::/8").unwrap(),
            IpBlock::Prefix(Prefix::new(Addr(127 << 120), 8))
        );
        assert_eq!(
            IpBlock::from_v6_str("7f00::-c700::").unwrap(),
            IpBlock::Range((Addr(127 << 120), Addr(199 << 120)).into())
        );
        assert!(IpBlock::from_v6_str("f700::/282").is_err());
        assert!(IpBlock::from_v6_str("f700:/-282").is_err());
        assert!(IpBlock::from_v6_str("127.0.0.0/8").is_err());
        assert!(IpBlock::from_v6_str("127.0.0.0-199.0.0.0").is_err());
    }

    #[test]
    fn ip_block_from_str() {
        fn check_v4(s: &str, prefix: bool, min: &str, max: &str) {
            let block = unwrap!(IpBlock::from_str(s));
            let is_prefix = match block {
                IpBlock::Prefix(_) => true,
                _ => false
            };
            assert_eq!(prefix, is_prefix);
            assert_eq!(
                block.min(),
                Addr::from(unwrap!(Ipv4Addr::from_str(min))).to_min(32)
            );
            assert_eq!(
                block.max(),
                Addr::from(unwrap!(Ipv4Addr::from_str(max))).to_max(32)
            );
        }

        check_v4(
            "127.0.0.0/8", true,
            "127.0.0.0", "127.255.255.255"
        );
        check_v4(
            "127.0.0.0-199.0.0.0", false,
            "127.0.0.0", "199.0.0.0"
        );
        check_v4(
            "127.0.0.0", false,
            "127.0.0.0", "127.0.0.0"
        );

        assert_eq!(
            IpBlock::from_str("7f00::").unwrap(),
            IpBlock::Range((Addr(127 << 120), Addr(127 << 120)).into())
        );
        assert_eq!(
            IpBlock::from_str("7f00::/8").unwrap(),
            IpBlock::Prefix(Prefix::new(Addr(127 << 120), 8))
        );
        assert_eq!(
            IpBlock::from_str("7f00::-c700::").unwrap(),
            IpBlock::Range((Addr(127 << 120), Addr(199 << 120)).into())
        );

        assert!(IpBlock::from_str("127.0.0.0/82").is_err());
        assert!(IpBlock::from_str("127.0.0.0/282").is_err());
        assert!(IpBlock::from_str("127.0.0.0/-282").is_err());
        assert!(IpBlock::from_str("f700::/282").is_err());
        assert!(IpBlock::from_str("f700:/-282").is_err());
    }

    #[test]
    fn prefix_encode() {
        assert_eq!(
            Prefix::new(Ipv4Addr::new(192, 168, 103, 0), 0)
                .encode().to_captured(Mode::Der).as_slice(),
            b"\x03\x01\x00".as_ref()
        );
        assert_eq!(
            Prefix::new(Ipv4Addr::new(192, 168, 103, 0), 18)
                .encode().to_captured(Mode::Der).as_slice(),
            b"\x03\x04\x06\xC0\xA8\x40".as_ref()
        );
        assert_eq!(
            Prefix::new(Ipv4Addr::new(192, 168, 103, 0), 16)
                .encode().to_captured(Mode::Der).as_slice(),
            b"\x03\x03\x00\xC0\xA8".as_ref()
        );
        assert_eq!(
            Prefix::new(Ipv4Addr::new(192, 168, 103, 0), 32)
                .encode().to_captured(Mode::Der).as_slice(),
            b"\x03\x05\x00\xC0\xA8\x67\x00".as_ref()
        );
    }

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
