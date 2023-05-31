//! Autonomous System identifier resources.
//!
//! The types herein are defined in [RFC 3779] for use with certificates in
//! general. RFC 6487 specifies how to use them with RPKI certificates. In
//! particular, it prohibits the use of RDI values. Additionally, if the
//! "inherit" value is not used, the set of identifiers must be non-empty.
//!
//! AS resources are represented in a certificate by an extension. The data
//! in this extension is represented by the [AsResources] enum which
//! decomposes into all the other types in this module.
//!
//! [AsResources]: enum.AsResources.html
//! [RFC 3779]: https://tools.ietf.org/html/rfc3779
//! [RFC 6487]: https://tools.ietf.org/html/rfc6487

use std::{error, fmt, iter};
use std::cmp::Ordering;
use std::iter::FromIterator;
use std::str::FromStr;
use bcder::{decode, encode};
use bcder::Tag;
use bcder::decode::{ContentError, DecodeError};
use bcder::encode::{PrimitiveContent, Nothing};
use crate::resources::asn::ParseAsnError;
use super::super::cert::Overclaim;
use super::super::x509::encode_extension;
use super::super::error::VerificationError;
use super::chain::{Block, OwnedChain, SharedChain};
use super::choice::{InheritedResources, ResourcesChoice};


//------------ Re-exports ----------------------------------------------------

pub use crate::resources::asn::Asn;


//------------ AsResources ---------------------------------------------------

/// The AS Resources of an RPKI Certificate.
///
/// This type contains the ‘Autonomous System Identifier Delegation Extension’
/// as defined in [RFC 3779] in the restricted form specified in [RFC 6487].
///
/// This type contains the resources as represented in an RPKI certificate’s
/// AS resources extension. This extension provides two options: there can
/// be an actual set of AS numbers associated with the certificate – this is
/// the `AsResources::Blocks` variant –, or the AS resources of the issuer can
/// be inherited – the `AsResources::Inherit` variant.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde-support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct AsResources(ResourcesChoice<AsBlocks>);

impl AsResources {
    /// Creates a new AsResources with a ResourcesChoice::Inherit
    pub fn inherit() -> Self {
        AsResources(ResourcesChoice::Inherit)
    }

    /// Creates a new AsResources with a ResourceChoice::Missing
    pub fn missing() -> Self {
        AsResources(ResourcesChoice::Missing)
    }

    /// Creates a new AsResources for the given blocks.
    ///
    /// If the blocks are empty, creates a missing variant in accordance with
    /// the specification.
    pub fn blocks(blocks: AsBlocks) -> Self {
        if blocks.is_empty() {
            AsResources::missing()
        }
        else {
            AsResources(ResourcesChoice::Blocks(blocks))
        }
    }

    /// Returns whether the resources are of the inherited variant.
    pub fn is_inherited(&self) -> bool {
        self.0.is_inherited()
    }

    /// Returns whether the resources are empty.
    ///
    /// Inherited resources are not empty.
    pub fn is_present(&self) -> bool {
        self.0.is_present()
    }

    /// Converts the resources into blocks or returns an error.
    pub fn to_blocks(&self) -> Result<AsBlocks, InheritedAsResources> {
        self.0.to_blocks().map_err(Into::into)
    }
}

impl AsResources {
    /// Takes the AS resources from the beginning of an encoded value.
    ///
    /// The ASN.1 specification for the `ASIdentifiers` types parsed here is
    /// given in section 3.2.3 of [RFC 3779] as follows:
    ///
    /// ```text
    /// ASIdentifiers      ::= SEQUENCE {
    ///     asnum              [0] EXPLICIT AsIdentifierChoice OPTIONAL,
    ///     rdi                [1] EXPLICIT AsIdentifierChoice OPTIONAL }
    ///
    /// AsIdentifierChoice ::= CHOICE {
    ///     inherit            NULL,
    ///     asIdsOrRanges      SEQUENCE OF ASIdOrRange }
    ///
    /// ASIdOrRange        ::= CHOICE {
    ///     id                 ASId,
    ///     range              ASRange }
    ///
    /// ASRange            ::= SEQUENCE {
    ///     min                ASId,
    ///     max                ASId }
    ///
    /// ASId               ::= INTEGER
    /// ```
    ///
    /// Section 4.8.11 of [RFC 6487] limits the `ASIdentifiers` to the
    /// `asnum` choice. If `asIdsOrRanges` is chosen, it must include a
    /// non-empty set of AS numbers.
    ///
    /// This function implements these limitations. It maps the `id` choice
    /// of `AsIdOrRange` to a range covering one number in order to keep
    /// things simpler.
    ///
    /// [RFC 3779]: https://tools.ietf.org/html/rfc3779
    /// [RFC 6487]: https://tools.ietf.org/html/rfc6487
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            cons.take_constructed_if(Tag::CTX_0, |cons| {
                cons.take_value(|tag, content| {
                    if tag == Tag::NULL {
                        content.to_null()?;
                        Ok(ResourcesChoice::Inherit)
                    }
                    else if tag == Tag::SEQUENCE {
                        AsBlocks::parse_content(content)
                            .map(ResourcesChoice::Blocks)
                    }
                    else {
                        Err(content.content_err("invalid AS resources"))
                    }
                })
            })
        }).map(AsResources)
    }

    pub fn encode(self) -> impl encode::Values {
        encode::sequence(
            encode::sequence_as(Tag::CTX_0,
                match self.0 {
                    ResourcesChoice::Inherit => {
                        encode::Choice3::One(().encode())
                    }
                    ResourcesChoice::Blocks(blocks) => {
                        encode::Choice3::Two(
                            encode::sequence(blocks.encode())
                        )
                    }
                    ResourcesChoice::Missing => {
                        encode::Choice3::Three(
                            encode::sequence(Nothing)
                        )
                    }
                }
            )
        )
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence(
            encode::sequence_as(Tag::CTX_0,
                match self.0 {
                    ResourcesChoice::Inherit => {
                        encode::Choice3::One(().encode())
                    }
                    ResourcesChoice::Blocks(ref blocks) => {
                        encode::Choice3::Two(
                            encode::sequence(blocks.encode_ref())
                        )
                    }
                    ResourcesChoice::Missing => {
                        encode::Choice3::Three(
                            encode::sequence(Nothing)
                        )
                    }
                }
            )
        )
    }

    pub fn encode_extension(
        &self, overclaim: Overclaim
    ) -> impl encode::Values + '_ {
        if self.0.is_present() {
            Some(encode_extension(
                overclaim.as_res_id(), true, self.encode_ref()
            ))
        }
        else {
            None
        }
    }

}

//--- Display

impl fmt::Display for AsResources {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

//--- FromStr

impl FromStr for AsResources {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "inherit" {
            Ok(AsResources::inherit())
        } else {
            AsBlocks::from_str(s).map(AsResources::blocks)
        }
    }
}


//------------ AsResourcesBuilder --------------------------------------------

#[derive(Clone, Debug)]
pub struct AsResourcesBuilder {
    /// The resources.
    ///
    /// A value of `None` means inherited resources, an empty builder will be
    /// transformed into missing resources.
    res: Option<AsBlocksBuilder>
}

impl AsResourcesBuilder {
    pub fn new() -> Self {
        AsResourcesBuilder {
            res: Some(AsBlocksBuilder::new())
        }
    }

    pub fn inherit(&mut self) {
        self.res = None
    }

    pub fn blocks<F>(&mut self, build: F)
    where F: FnOnce(&mut AsBlocksBuilder) {
        if let Some(ref mut builder) = self.res {
            build(builder)
        }
        else {
            let mut builder = AsBlocksBuilder::new();
            build(&mut builder);
            self.res = Some(builder)
        }
    }

    pub fn finalize(self) -> AsResources {
        match self.res {
            Some(blocks) => AsResources::blocks(blocks.finalize()),
            None => AsResources::inherit(),
        }
    }
}

impl Default for AsResourcesBuilder {
    fn default() -> Self {
        Self::new()
    }
}


//------------ AsBlocks ------------------------------------------------------

/// A possibly empty sequence of consecutive sets of AS numbers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsBlocks(SharedChain<AsBlock>);

impl AsBlocks {
    /// Creates empty AS blocks.
    pub fn empty() -> Self {
        AsBlocks(SharedChain::empty())
    }

    /// Creates a value covering all ASNs.
    pub fn all() -> Self {
        AsBlocks(SharedChain::from_owned(
            unsafe {
                OwnedChain::from_vec_unchecked(vec![
                    AsBlock::all()
                ])
            }
        ))
    }

    /// Creates AS blocks from AS resources.
    ///
    /// If the AS resources are of the inherited variant, a validation error
    /// is returned.
    pub fn from_resources(
        res: AsResources
    ) -> Result<Self, InheritedAsResources> {
        match res.0 {
            ResourcesChoice::Missing => Ok(AsBlocks::empty()),
            ResourcesChoice::Inherit => Err(InheritedAsResources(())),
            ResourcesChoice::Blocks(some) => Ok(some),
        }
    }

    /// Returns whether the blocks is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of ASNs covered by this value.
    pub fn asn_count(&self) -> u32 {
        self.iter().map(|block| block.asn_count()).sum()
    }

    /// Returns an iterator over the ASN blocks.
    pub fn iter(&self) -> impl Iterator<Item = AsBlock> + '_ {
        self.0.iter().copied()
    }

    /// Returns an iterator over the individual ASNs.
    pub fn iter_asns(&self) -> impl Iterator<Item = Asn> + '_ {
        self.iter().flatten()
    }

    /// Validates AS resources issued under these blocks.
    pub fn verify_issued(
        &self,
        res: &AsResources,
        mode: Overclaim,
    ) -> Result<AsBlocks, OverclaimedAsResources> {
        match res.0 {
            ResourcesChoice::Missing => Ok(Self::empty()),
            ResourcesChoice::Inherit => Ok(self.clone()),
            ResourcesChoice::Blocks(ref blocks) => {
                match mode {
                    Overclaim::Refuse => {
                        if blocks.0.is_encompassed(&self.0) {
                            Ok(blocks.clone())
                        }
                        else {
                            Err(OverclaimedAsResources::new(
                                self.clone(), blocks.clone(),
                            ))
                        }
                    }
                    Overclaim::Trim => {
                        match blocks.0.trim(&self.0) {
                            Ok(()) => Ok(blocks.clone()),
                            Err(new) => Ok(AsBlocks(new.into()))
                        }
                    }
                }
            }
        }
    }

    /// Verifies that these resources are covered by an issuer’s resources.
    ///
    /// This is used by bottom-up validation, therefore, issuer resources 
    /// of the inherited kind are considered covering.
    pub fn verify_covered(
        &self,
        issuer: &AsResources
    ) -> Result<(), OverclaimedAsResources> {
        match issuer.0 {
            ResourcesChoice::Missing => {
                if self.0.is_empty() {
                    Ok(())
                }
                else {
                    Err(OverclaimedAsResources::new(
                        AsBlocks::empty(), self.clone(),
                    ))
                }
            }
            ResourcesChoice::Inherit => Ok(()),
            ResourcesChoice::Blocks(ref blocks) => {
                if self.0.is_encompassed(&blocks.0) {
                    Ok(())
                }
                else {
                    Err(OverclaimedAsResources::new(
                        blocks.clone(), self.clone(),
                    ))
                }
            }
        }
    }
}

/// # Set operations
///
impl AsBlocks {
    /// Returns whether this AsBlocks contains a given ASN.
    pub fn contains_asn(&self, asn: Asn) -> bool {
        self.0.contains_item(asn)
    }

    /// Returns whether this AsBlocks contains the other in its entirety.
    pub fn contains(&self, other: &Self) -> bool {
        other.0.is_encompassed(&self.0)
    }

    /// Return the intersection of this AsBlocks and the other. I.e. all
    /// resources which are found in both.
    pub fn intersection(&self, other: &Self) -> Self {
        match self.0.trim(&other.0) {
            Ok(()) => self.clone(),
            Err(owned) => AsBlocks(SharedChain::from_owned(owned))
        }
    }

    pub fn intersection_assign(&mut self, other: &Self) {
        if let Err(owned) = self.0.trim(&other.0) {
            self.0 = SharedChain::from_owned(owned)
        }
    }

    /// Returns a new AsBlocks with the values found in self, but not in other.
    pub fn difference(&self, other: &Self) -> Self {
        AsBlocks(SharedChain::from_owned(self.0.difference(&other.0)))
    }    

    /// Returns a new AsBlocks with the union of this and the other AsBlocks.
    ///
    /// i.e. all resources found in one or both AsBlocks.
    pub fn union(&self, other: &Self) -> Self {
        AsBlocks(
            self.0.iter().cloned().chain(other.0.iter().cloned()).collect()
        )
    }
}

/// # Decoding and Encoding
///
impl AsBlocks {
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::parse_cons_content)
    }

    /// Parses the content of a AS ID blocks sequence.
    fn parse_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        let cons = content.as_constructed()?;
        Self::parse_cons_content(cons)
    }

    fn parse_cons_content<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        let mut err = None;

        let res = iter::repeat_with(||
            AsBlock::take_opt_from(cons)
        ).map(|item| {
            match item {
                Ok(Some(val)) => Some(val),
                Ok(None) => None,
                Err(e) => {
                    err = Some(e);
                    None
                }
            }
        }).take_while(|item| item.is_some()).map(Option::unwrap).collect();
        match err {
            Some(err) => Err(err),
            None => Ok(AsBlocks(res))
        }
    }

    pub fn encode(self) -> impl encode::Values {
        encode::slice(self.0, |block| block.encode())
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::slice(&self.0, |block| block.encode())
    }
}


//--- Default

impl Default for AsBlocks {
    fn default() -> Self {
        AsBlocks::empty()
    }
}


//--- FromStr and FromIterator

impl FromStr for AsBlocks {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut builder = AsBlocksBuilder::default();

        for el in s.split(',') {
            let el = el.trim();
            if !el.is_empty() {
                let block = AsBlock::from_str(el)?;
                builder.push(block);
            }
        }

        Ok(builder.finalize())
    }
}

impl FromIterator<AsBlock> for AsBlocks {
    fn from_iter<I: IntoIterator<Item = AsBlock>>(iter: I) -> Self {
        Self(SharedChain::from_iter(iter))
    }
}


//--- Display

impl fmt::Display for AsBlocks {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.iter();

        if let Some(el) = iter.next() {
            el.fmt(f)?;
        }

        for el in iter {
            write!(f, ", ")?;
            el.fmt(f)?;
        }

        Ok(())
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde-support")]
impl serde::Serialize for AsBlocks {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

#[cfg(feature = "serde-support")]
impl<'de> serde::Deserialize<'de> for AsBlocks {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        let string = String::deserialize(deserializer)?;
        Self::from_str(&string).map_err(serde::de::Error::custom)
    }
}


//------------ AsBlocksBuilder -----------------------------------------------

#[derive(Clone, Debug)]
pub struct AsBlocksBuilder(Vec<AsBlock>);

impl AsBlocksBuilder {
    pub fn new() -> Self {
        AsBlocksBuilder(Vec::new())
    }

    pub fn push(&mut self, block: impl Into<AsBlock>) {
        self.0.push(block.into())
    }

    pub fn finalize(self) -> AsBlocks {
        AsBlocks(self.0.into_iter().collect())
    }
}

impl Default for AsBlocksBuilder {
    fn default() -> Self {
        AsBlocksBuilder::new()
    }
}

impl Extend<AsBlock> for AsBlocksBuilder {
    fn extend<T>(&mut self, iter: T)
    where T: IntoIterator<Item = AsBlock> {
        self.0.extend(iter)
    }
}


//------------ AsBlock -------------------------------------------------------

/// A block of consecutive AS numbers.
#[derive(Clone, Copy, Debug)]
pub enum AsBlock {
    /// The block is a single AS number.
    Id(Asn),

    /// The block is a range of AS numbers.
    Range(AsRange),
}

impl AsBlock {
    /// Returns an AS block covering all ASNs.
    pub fn all() -> AsBlock {
        AsBlock::Range(AsRange::all())
    }

    /// The smallest AS number that is part of this block.
    pub fn min(&self) -> Asn {
        match *self {
            AsBlock::Id(id) => id,
            AsBlock::Range(ref range) => range.min(),
        }
    }

    /// The largest AS number that is still part of this block.
    pub fn max(&self) -> Asn {
        match *self {
            AsBlock::Id(id) => id,
            AsBlock::Range(ref range) => range.max(),
        }
    }

    /// Returns the number of ASNs covered by this value.
    pub fn asn_count(self) -> u32 {
        match self {
            AsBlock::Id(_) => 1,
            AsBlock::Range(range) => range.asn_count()
        }
    }

    /// Sets a new minimum AS number.
    ///
    /// # Panics
    ///
    /// If you try to set the minimum to value larger than the current
    /// maximum, the method will panic.
    pub fn set_min(&mut self, id: Asn) {
        match id.cmp(&self.max()) {
            Ordering::Less => {
                *self = AsBlock::Range(AsRange::new(id, self.max()))
            }
            Ordering::Equal => {
                *self = AsBlock::Id(id)
            }
            Ordering::Greater => {
                panic!("trying to set minimum beyond current maximum");
            }
        }
    }

    /// Sets a new maximum AS number.
    ///
    /// # Panics
    ///
    /// If you try to set the minimum to value smaller than the current
    /// minimum, the method will panic.
    pub fn set_max(&mut self, id: Asn) {
        match id.cmp(&self.min()) {
            Ordering::Greater => {
                *self = AsBlock::Range(AsRange::new(self.min(), id))
            }
            Ordering::Equal => {
                *self = AsBlock::Id(id)
            }
            Ordering::Less => {
                panic!("trying to set maximum below current minimum");
            }
        }
    }

    /// Returns whether this is a block covering all AS Ids.
    pub fn is_whole_range(&self) -> bool {
        matches!(
            *self,
            AsBlock::Range(range)
                if range.min() == Asn::MIN && range.max() == Asn::MAX
        )
    }

    /// Returns an iterator over the ASNs in the block.
    pub fn iter(self) -> AsBlockIter {
        AsBlockIter::new(self.min(), self.max())
    }
}

impl AsBlock {
    /// Takes an optional AS block from the beginning of an encoded value.
    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_value(|tag, content| {
            if tag == Tag::INTEGER {
                Asn::parse_content(content).map(AsBlock::Id)
            }
            else if tag == Tag::SEQUENCE {
                AsRange::parse_content(content).map(AsBlock::Range)
            }
            else {
                Err(content.content_err("invalid AS resources"))
            }
        })
    }

    /// Skips over the AS block at the beginning of an encoded value.
    pub fn skip_opt_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<()>, DecodeError<S::Error>> {
        cons.take_opt_value(|tag, content| {
            if tag == Tag::INTEGER {
                Asn::skip_content(content)
            }
            else if tag == Tag::SEQUENCE {
                AsRange::skip_content(content)
            }
            else {
                Err(content.content_err("invalid AS resources"))
            }
        })
    }

    fn encode(self) -> impl encode::Values {
        match self {
            AsBlock::Id(inner) => encode::Choice2::One(inner.encode()),
            AsBlock::Range(inner) => encode::Choice2::Two(inner.encode()),
        }
    }
}


//--- From and FromStr

impl From<Asn> for AsBlock {
    fn from(id: Asn) -> Self {
        AsBlock::Id(id)
    }
}

impl From<AsRange> for AsBlock {
    fn from(range: AsRange) -> Self {
        AsBlock::Range(range)
    }
}

impl From<(Asn, Asn)> for AsBlock {
    fn from(range: (Asn, Asn)) -> Self {
        AsBlock::Range(AsRange::new(range.0, range.1))
    }
}

impl FromStr for AsBlock {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {

        match s.find('-') {
            None => Ok(AsBlock::Id(Asn::from_str(s)?)),
            Some(pos) => {
                if s.len() < pos + 2 {
                    Err(FromStrError::BadRange)
                } else {
                    let min_str = &s[..pos];
                    let max_str = &s[pos + 1 ..];
                    let min = Asn::from_str(min_str)
                        .map_err(|_| FromStrError::BadRange)?;
                    let max = Asn::from_str(max_str)
                        .map_err(|_| FromStrError::BadRange)?;
                    Ok(AsBlock::Range(AsRange { min, max }))
                }
            }
        }
    }
}


//--- IntoIterator

impl IntoIterator for AsBlock {
    type Item = Asn;
    type IntoIter = AsBlockIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- PartialEq and Eq

impl PartialEq for AsBlock {
    fn eq(&self, other: &AsBlock) -> bool {
        self.is_equivalent(other)
    }
}

impl Eq for AsBlock {}


//--- Block

impl Block for AsBlock {
    type Item = Asn;

    fn new(min: Self::Item, max: Self::Item) -> Self {
        if min == max {
            AsBlock::Id(min)
        }
        else {
            AsBlock::Range(AsRange::new(min, max))
        }
    }

    fn min(&self) -> Self::Item {
        self.min()
    }

    fn max(&self) -> Self::Item {
        self.max()
    }

    fn next(item: Self::Item) -> Option<Self::Item> {
        item.into_u32().checked_add(1).map(Asn::from)
    }

    fn previous(item: Self::Item) -> Option<Self::Item> {
        item.into_u32().checked_sub(1).map(Asn::from)
    }
}

//--- Display

impl fmt::Display for AsBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsBlock::Id(id) => id.fmt(f),
            AsBlock::Range(range) => range.fmt(f)
        }
    }
}


//------------ AsBlockIter ---------------------------------------------------

/// An iterator over all the ASNs in a block.
#[derive(Clone, Debug)]
pub struct AsBlockIter {
    next: Option<Asn>,
    max: Asn,
}

impl AsBlockIter {
    fn new(min: Asn, max: Asn) -> Self {
        Self {
            next: Some(min),
            max
        }
    }
}

impl Iterator for AsBlockIter {
    type Item = Asn;

    fn next(&mut self) -> Option<Asn> {
        let next = self.next?;
        if next == self.max {
            self.next = None;
        }
        else {
            self.next = Some(next + 1);
        }
        Some(next)
    }
}


//------------ AsRange -------------------------------------------------------

/// A range of AS numbers.
#[derive(Clone, Copy, Debug)]
pub struct AsRange {
    /// The smallest AS number that is part of the range.
    min: Asn,

    /// The largest AS number that is part of the range.
    ///
    /// Note that this means that, unlike normal Rust ranges, our range is
    /// inclusive at the upper end. This is necessary to represent a range
    /// that goes all the way to the last number.
    max: Asn,
}

impl AsRange {
    /// Creates a new AS number range from the smallest and largest number.
    pub fn new(min: Asn, max: Asn) -> Self {
        AsRange { min, max }
    }

    /// Returns an AS block covering all ASNs.
    pub fn all() -> AsRange {
        AsRange::new(Asn::MIN, Asn::MAX)
    }

    /// Returns the smallest AS number that is part of this range.
    pub fn min(self) -> Asn {
        self.min
    }

    /// Returns the largest AS number that is still part of this range.
    pub fn max(self) -> Asn {
        self.max
    }

    /// Returns the number of ASNs covered by this value.
    pub fn asn_count(self) -> u32 {
        u32::from(self.max) - u32::from(self.min) + 1
    }
}

impl AsRange {
    /// Parses the content of an AS range value.
    fn parse_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        let cons = content.as_constructed()?;
        Ok(AsRange {
            min: Asn::take_from(cons)?,
            max: Asn::take_from(cons)?,
        })
    }

    /// Skips over the content of an AS range value.
    fn skip_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<(), DecodeError<S::Error>> {
        let cons = content.as_constructed()?;
        Asn::skip_in(cons)?;
        Asn::skip_in(cons)?;
        Ok(())
    }

    fn encode(self) -> impl encode::Values {
        encode::sequence((
            self.min.encode(),
            self.max.encode(),
        ))
    }
}


//--- Block

impl Block for AsRange {
    type Item = Asn;

    fn new(min: Self::Item, max: Self::Item) -> Self {
        Self::new(min, max)
    }

    fn min(&self) -> Self::Item {
        Self::min(*self)
    }

    fn max(&self) -> Self::Item {
        Self::max(*self)
    }

    fn next(item: Self::Item) -> Option<Self::Item> {
        item.into_u32().checked_add(1).map(Asn::from)
    }

    fn previous(item: Self::Item) -> Option<Self::Item> {
        item.into_u32().checked_sub(1).map(Asn::from)
    }
}

//--- Display

impl fmt::Display for AsRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.min, self.max)
    }
}


//============ Errors ========================================================

//------------ FromStrError --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum FromStrError {
    BadAsn,
    BadRange,
    BadBlocks,
}

impl From<ParseAsnError> for FromStrError {
    fn from(_: ParseAsnError) -> Self {
        FromStrError::BadAsn
    }
}

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            FromStrError::BadAsn
                => "Bad AS number. Expected format: AS#",
            FromStrError::BadRange
                => "Bad AS range. Expected format: AS#-AS#",
            FromStrError::BadBlocks
                => "Cannot parse blocks."
        })
    }
}

impl error::Error for FromStrError { }


//------------ InheritedAsResources ------------------------------------------

/// Inherited AS resources encountered where they are not allowed.
#[derive(Clone, Copy, Debug)]
pub struct InheritedAsResources(());

impl From<InheritedResources> for InheritedAsResources {
    fn from(_: InheritedResources) -> InheritedAsResources {
        InheritedAsResources(())
    }
}

impl fmt::Display for InheritedAsResources {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("inherited AS resources")
    }
}

impl error::Error for InheritedAsResources { }

impl From<InheritedAsResources> for VerificationError {
    fn from(_: InheritedAsResources) -> Self {
        VerificationError::new("inherited AS resources")
    }
}


//------------ OverclaimedAsResources ----------------------------------------

/// The AS resources of a certificate are not covered by its issuer.
#[derive(Clone, Debug)]
pub struct OverclaimedAsResources {
    issuer: AsBlocks,
    subject: AsBlocks,
}

impl OverclaimedAsResources {
    fn new(issuer: AsBlocks, subject: AsBlocks) -> Self {
        OverclaimedAsResources { issuer, subject }
    }
}

impl fmt::Display for OverclaimedAsResources {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "overclaimed AS resources: {}",
            self.subject.difference(&self.issuer)
        )
    }
}

impl error::Error for OverclaimedAsResources { }

impl From<OverclaimedAsResources> for VerificationError {
    fn from(err: OverclaimedAsResources) -> Self {
        ContentError::from_boxed(Box::new(err)).into()
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn as_blocks_all() {
        assert_eq!(AsBlocks::all().to_string(), "AS0-AS4294967295");
    }

    #[test]
    fn as_block_from_str() {
        // Good
        assert_eq!(
            AsBlock::from_str("AS1").unwrap(),
            Asn::from(1).into()
        );
        assert_eq!(
            AsBlock::from_str("AS1-AS3").unwrap(),
            AsRange::new(Asn::from(1), Asn::from(3)).into()
        );

        // Bad
        assert!(AsBlock::from_str("AS1-").is_err());
    }

    #[test]
    fn as_block_iter() {
        assert_eq!(
            AsBlock::Id(0.into()).iter().collect::<Vec<_>>(),
            [0.into()]
        );
        assert_eq!(
            AsBlock::Id(1200.into()).iter().collect::<Vec<_>>(),
            [1200.into()]
        );
        assert_eq!(
            AsBlock::Id(u32::MAX.into()).iter().collect::<Vec<_>>(),
            [u32::MAX.into()]
        );
        assert_eq!(
            AsBlock::Range(
                AsRange::new(0.into(), 4.into())
            ).iter().collect::<Vec<_>>(),
            [0.into(), 1.into(), 2.into(), 3.into(), 4.into()]
        );
        assert_eq!(
            AsBlock::Range(
                AsRange::new(10.into(), 14.into())
            ).iter().collect::<Vec<_>>(),
            [10.into(), 11.into(), 12.into(), 13.into(), 14.into()]
        );
        assert_eq!(
            AsBlock::Range(
                AsRange::new((u32::MAX - 4).into(), u32::MAX.into())
            ).iter().collect::<Vec<_>>(),
            [
                (u32::MAX - 4).into(), (u32::MAX - 3).into(),
                (u32::MAX - 2).into(), (u32::MAX - 1).into(),
                u32::MAX.into()
            ]
        );
    }

    #[test]
    fn as_blocks_from_str() {
        fn good(left: &str, right: Vec<AsBlock>) {
            assert_eq!(
                AsBlocks::from_str(left).unwrap().iter().collect::<Vec<_>>(),
                right
            );
        }

        good(
            "AS1, AS3-AS7", 
            vec![Asn::from(1).into(), AsRange::new(Asn::from(3), Asn::from(7)).into()]
        );
        good(
            "AS1,AS3-AS7", 
            vec![Asn::from(1).into(), AsRange::new(Asn::from(3), Asn::from(7)).into()]
        );
        good("", Vec::new());
    }

    #[test]
    fn as_blocks_difference() {
        // This delegates to Chain::difference which is well tested
        let left = "AS1, AS3-AS7";
        let right = "AS2, AS5-AS7";
        let expected = "AS1, AS3-AS4";

        let left = AsBlocks::from_str(left).unwrap();
        let right = AsBlocks::from_str(right).unwrap();
        let expected = AsBlocks::from_str(expected).unwrap();

        let found = left.difference(&right);

        assert_eq!(expected, found);
    }


    #[test]
    #[cfg(feature = "serde")]
    fn as_resources_inherit_serde() {
        let resources_str = "inherit";
        let as_resources = AsResources::from_str(resources_str).unwrap();

        let json = serde_json::to_string(&as_resources).unwrap();
        let deser_as_resources = serde_json::from_str(&json).unwrap();

        assert_eq!(as_resources, deser_as_resources)
    }

    #[test]
    #[cfg(feature = "serde")]
    fn as_resources_concrete_serde() {
        let resources_str = "AS6500-AS65005, AS65007";
        let as_resources = AsResources::from_str(resources_str).unwrap();

        let json = serde_json::to_string(&as_resources).unwrap();
        let deser_as_resources = serde_json::from_str(&json).unwrap();

        assert_eq!(as_resources, deser_as_resources)
    }
}
