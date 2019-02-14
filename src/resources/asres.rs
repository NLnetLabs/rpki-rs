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

use std::{fmt, iter, ops};
use std::iter::FromIterator;
use bcder::{decode, encode};
use bcder::Tag;
use bcder::encode::PrimitiveContent;
use crate::cert::Overclaim;
use crate::x509::ValidationError;
use super::chain::{Block, SharedChain};
use super::choice::ResourcesChoice;


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
#[derive(Clone, Debug)]
pub struct AsResources(ResourcesChoice<AsBlocks>);

impl AsResources {
    /// Returns whether the resources are of the inherited variant.
    pub fn is_inherited(&self) -> bool {
        self.0.is_inherited()
    }

    /// Returns a reference to the blocks if there are any.
    pub fn as_blocks(&self) -> Option<&AsBlocks> {
        self.0.as_blocks()
    }

    /// Converts the resources into blocks or returns an error.
    pub fn to_blocks(&self) -> Result<AsBlocks, ValidationError> {
        self.0.to_blocks()
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
    ) -> Result<Self, S::Err> {
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
                        xerr!(Err(decode::Error::Malformed.into()))
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
                        encode::Choice2::One(().encode())
                    }
                    ResourcesChoice::Blocks(blocks) => {
                        encode::Choice2::Two(blocks.encode())
                    }
                }
            )
        )
    }
}


//------------ AsResourcesBuilder --------------------------------------------

#[derive(Clone, Debug)]
pub struct AsResourcesBuilder {
    res: Option<ResourcesChoice<AsBlocksBuilder>>
}

impl AsResourcesBuilder {
    pub fn new() -> Self {
        AsResourcesBuilder {
            res: None
        }
    }

    pub fn inhert(&mut self) {
        self.res = Some(ResourcesChoice::Inherit)
    }

    pub fn blocks<F>(&mut self, build: F)
    where F: FnOnce(&mut AsBlocksBuilder) {
        if self.res.as_ref().map(|res| res.is_inherited()).unwrap_or(true) {
            self.res = Some(ResourcesChoice::Blocks(AsBlocksBuilder::new()))
        }
        build(self.res.as_mut().unwrap().as_blocks_mut().unwrap())
    }

    pub fn finalize(self) -> Option<AsResources> {
        self.res.map(|choice| {
            AsResources(choice.map_blocks(AsBlocksBuilder::finalize))
        })
    }
}

impl Default for AsResourcesBuilder {
    fn default() -> Self {
        Self::new()
    }
}


//------------ AsBlocks ------------------------------------------------------

/// A possibly empty sequence of consecutive sets of AS numbers.
#[derive(Clone, Debug)]
pub struct AsBlocks(SharedChain<AsBlock>);

impl AsBlocks {
    /// Creates empty AS blocks.
    pub fn empty() -> Self {
        AsBlocks(SharedChain::empty())
    }

    /// Creates AS blocks from AS resources.
    ///
    /// If the AS resources are of the inherited variant, a validation error
    /// is returned.
    pub fn from_resources(
        res: Option<&AsResources>
    ) -> Result<Self, ValidationError> {
        match res.map(|res| &res.0) {
            Some(ResourcesChoice::Inherit) => Err(ValidationError),
            Some(ResourcesChoice::Blocks(ref some)) => Ok(some.clone()),
            None => Ok(AsBlocks::empty())
        }
    }

    /// Returns whether the blocks is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the individual AS number blocks.
    pub fn iter(&self) -> impl Iterator<Item=&AsBlock> {
        self.0.iter()
    }

    /// Validates AS resources issued under these blocks.
    pub fn validate_issued(
        &self,
        res: Option<&AsResources>,
        mode: Overclaim,
    ) -> Result<AsBlocks, ValidationError> {
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
                            Err(new) => Ok(AsBlocks(new.into()))
                        }
                    }
                }
            },
            None => Ok(Self::empty()),
        }
    }
}


/// # Decoding and Encoding
///
impl AsBlocks {
    /// Parses the content of a AS ID blocks sequence.
    fn parse_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, S::Err> {
        let cons = content.as_constructed()?;
        let mut err = None;

        let res = SharedChain::from_iter(
            iter::repeat_with(|| AsBlock::take_opt_from(cons))
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
            None => Ok(AsBlocks(res))
        }
    }

    pub fn encode(self) -> impl encode::Values {
        encode::slice(self.0, |block| block.encode())
    }
}


//------------ AsBlocksBuilder -----------------------------------------------

#[derive(Clone, Debug)]
pub struct AsBlocksBuilder(Vec<AsBlock>);

impl AsBlocksBuilder {
    fn new() -> Self {
        AsBlocksBuilder(Vec::new())
    }

    pub fn push<T: Into<AsBlock>>(&mut self, block: T) {
        self.0.push(block.into())
    }

    pub fn finalize(self) -> AsBlocks {
        AsBlocks(SharedChain::from_iter(self.0.into_iter()))
    }
}


//------------ AsBlock -------------------------------------------------------

/// A block of consecutive AS numbers.
#[derive(Clone, Copy, Debug)]
pub enum AsBlock {
    /// The block is a single AS number.
    Id(AsId),

    /// The block is a range of AS numbers.
    Range(AsRange),
}

impl AsBlock {
    /// The smallest AS number that is part of this block.
    pub fn min(&self) -> AsId {
        match *self {
            AsBlock::Id(id) => id,
            AsBlock::Range(ref range) => range.min(),
        }
    }

    /// The largest AS number that is still part of this block.
    pub fn max(&self) -> AsId {
        match *self {
            AsBlock::Id(id) => id,
            AsBlock::Range(ref range) => range.max(),
        }
    }

    /// Sets a new minimum AS number.
    ///
    /// # Panics
    ///
    /// If you try to set the minimum to value larger than the current
    /// maximum, the method will panic.
    pub fn set_min(&mut self, id: AsId) {
        if id < self.max() {
            *self = AsBlock::Range(AsRange::new(id, self.max()))
        }
        else if id == self.max() {
            *self = AsBlock::Id(id)
        }
        else {
            panic!("trying to set minimum beyond current maximum");
        }
    }

    /// Sets a new maximum AS number.
    ///
    /// # Panics
    ///
    /// If you try to set the minimum to value smaller than the current
    /// minimum, the method will panic.
    pub fn set_max(&mut self, id: AsId) {
        if id > self.min() {
            *self = AsBlock::Range(AsRange::new(self.min(), id))
        }
        else if id == self.min() {
            *self = AsBlock::Id(id)
        }
        else {
            panic!("trying to set maximum below current minimum");
        }
    }
}

impl AsBlock {
    /// Takes an optional AS bock from the beginning of an encoded value.
    fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_value(|tag, content| {
            if tag == Tag::INTEGER {
                AsId::parse_content(content).map(AsBlock::Id)
            }
            else if tag == Tag::SEQUENCE {
                AsRange::parse_content(content).map(AsBlock::Range)
            }
            else {
                xerr!(Err(decode::Error::Malformed.into()))
            }
        })
    }

    /*
    /// Skips over the AS block at the beginning of an encoded value.
    fn skip_opt_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        cons.take_opt_value(|tag, content| {
            if tag == Tag::INTEGER {
                AsId::skip_content(content)
            }
            else if tag == Tag::SEQUENCE {
                AsRange::skip_content(content)
            }
            else {
                xerr!(Err(decode::Error::Malformed.into()))
            }
        })
    }
    */

    fn encode(self) -> impl encode::Values {
        match self {
            AsBlock::Id(inner) => encode::Choice2::One(inner.encode()),
            AsBlock::Range(inner) => encode::Choice2::Two(inner.encode()),
        }
    }
}


//--- From

impl From<AsId> for AsBlock {
    fn from(id: AsId) -> Self {
        AsBlock::Id(id)
    }
}

impl From<AsRange> for AsBlock {
    fn from(range: AsRange) -> Self {
        AsBlock::Range(range)
    }
}

impl From<(AsId, AsId)> for AsBlock {
    fn from(range: (AsId, AsId)) -> Self {
        AsBlock::Range(AsRange::new(range.0, range.1))
    }
}


//--- Block

impl Block for AsBlock {
    type Item = AsId;

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
        item.0.checked_add(1).map(AsId)
    }
}


//------------ AsRange -------------------------------------------------------

/// A range of AS numbers.
#[derive(Clone, Copy, Debug)]
pub struct AsRange {
    /// The smallest AS number that is part of the range.
    min: AsId,

    /// The largest AS number that is part of the range.
    ///
    /// Note that this means that, unlike normal Rust ranges, our range is
    /// inclusive at the upper end. This is necessary to represent a range
    /// that goes all the way to the last number.
    max: AsId,
}

impl AsRange {
    /// Creates a new AS number range from the smallest and largest number.
    pub fn new(min: AsId, max: AsId) -> Self {
        AsRange { min, max }
    }

    /// Returns the smallest AS number that is part of this range.
    pub fn min(self) -> AsId {
        self.min
    }

    /// Returns the largest AS number that is still part of this range.
    pub fn max(self) -> AsId {
        self.max
    }
}

impl AsRange {
    /// Parses the content of an AS range value.
    fn parse_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, S::Err> {
        let cons = content.as_constructed()?;
        Ok(AsRange {
            min: AsId::take_from(cons)?,
            max: AsId::take_from(cons)?,
        })
    }

    /*
    /// Skips over the content of an AS range value.
    fn skip_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<(), S::Err> {
        let cons = content.as_constructed()?;
        AsId::skip_in(cons)?;
        AsId::skip_in(cons)?;
        Ok(())
    }
    */

    fn encode(self) -> impl encode::Values {
        encode::sequence((
            self.min.encode(),
            self.max.encode(),
        ))
    }
}


//--- Block

impl Block for AsRange {
    type Item = AsId;

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
        item.0.checked_add(1).map(AsId)
    }
}


//------------ AsId ----------------------------------------------------------

/// An AS number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AsId(u32);

impl AsId {
    pub const MIN: AsId = AsId(std::u32::MIN);
    pub const MAX: AsId = AsId(std::u32::MAX);

    /// Takes an AS number from the beginning of an encoded value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_u32().map(AsId)
    }

    /*
    /// Skips over the AS number at the beginning of an encoded value.
    fn skip_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(), S::Err> {
        cons.take_u32().map(|_| ())
    }
    */

    /// Parses the content of an AS number value.
    fn parse_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, S::Err> {
        content.to_u32().map(AsId)
    }

    /*
    /// Skips the content of an AS number value.
    fn skip_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<(), S::Err> {
        content.to_u32().map(|_| ())
    }
    */

    fn encode(self) -> impl encode::Values {
        self.0.encode()
    }
}


//--- From

impl From<u32> for AsId {
    fn from(id: u32) -> Self {
        AsId(id)
    }
}

impl From<AsId> for u32 {
    fn from(id: AsId) -> Self {
        id.0
    }
}


//--- Add

impl ops::Add<u32> for AsId {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        AsId(self.0.checked_add(rhs).unwrap())
    }
}


//--- Display

impl fmt::Display for AsId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

