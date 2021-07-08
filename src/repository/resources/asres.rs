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

use std::{error, fmt, iter, ops};
use std::cmp::Ordering;
use std::iter::FromIterator;
use std::str::FromStr;
use bcder::{decode, encode};
use bcder::{Tag, xerr};
use bcder::encode::{PrimitiveContent, Nothing};
use super::super::cert::Overclaim;
use super::super::x509::{encode_extension, ValidationError};
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
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    /// Creates AS blocks from AS resources.
    ///
    /// If the AS resources are of the inherited variant, a validation error
    /// is returned.
    pub fn from_resources(
        res: AsResources
    ) -> Result<Self, ValidationError> {
        match res.0 {
            ResourcesChoice::Missing => Ok(AsBlocks::empty()),
            ResourcesChoice::Inherit => Err(ValidationError),
            ResourcesChoice::Blocks(some) => Ok(some),
        }
    }

    /// Returns whether the blocks is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the individual AS number blocks.
    pub fn iter(&self) -> impl Iterator<Item=AsBlock> + '_ {
        self.0.iter().copied()
    }

    /// Validates AS resources issued under these blocks.
    pub fn validate_issued(
        &self,
        res: &AsResources,
        mode: Overclaim,
    ) -> Result<AsBlocks, ValidationError> {
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
    ) -> Result<(), ValidationError> {
        match issuer.0 {
            ResourcesChoice::Missing => {
                if self.0.is_empty() {
                    Ok(())
                }
                else {
                    Err(ValidationError)
                }
            }
            ResourcesChoice::Inherit => Ok(()),
            ResourcesChoice::Blocks(ref blocks) => {
                if self.0.is_encompassed(&blocks.0) {
                    Ok(())
                }
                else {
                    Err(ValidationError)
                }
            }
        }
    }
}

/// # Set operations
///
impl AsBlocks {
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
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::parse_cons_content)
    }

    /// Parses the content of a AS ID blocks sequence.
    fn parse_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, S::Err> {
        let cons = content.as_constructed()?;
        Self::parse_cons_content(cons)
    }

    fn parse_cons_content<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
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

#[cfg(feature = "serde")]
impl serde::Serialize for AsBlocks {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
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
    pub fn set_max(&mut self, id: AsId) {
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
                if range.min() == AsId::MIN && range.max() == AsId::MAX
        )
    }
}

impl AsBlock {
    /// Takes an optional AS bock from the beginning of an encoded value.
    pub fn take_opt_from<S: decode::Source>(
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

    /// Skips over the AS block at the beginning of an encoded value.
    pub fn skip_opt_in<S: decode::Source>(
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

    fn encode(self) -> impl encode::Values {
        match self {
            AsBlock::Id(inner) => encode::Choice2::One(inner.encode()),
            AsBlock::Range(inner) => encode::Choice2::Two(inner.encode()),
        }
    }
}


//--- From and FromStr

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

impl FromStr for AsBlock {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {

        match s.find('-') {
            None => Ok(AsBlock::Id(AsId::from_str(s)?)),
            Some(pos) => {
                if s.len() < pos + 2 {
                    Err(FromStrError::BadRange)
                } else {
                    let min_str = &s[..pos];
                    let max_str = &s[pos + 1 ..];
                    let min = AsId::from_str(min_str)
                        .map_err(|_| FromStrError::BadRange)?;
                    let max = AsId::from_str(max_str)
                        .map_err(|_| FromStrError::BadRange)?;
                    Ok(AsBlock::Range(AsRange { min, max }))
                }
            }
        }
    }
}

impl PartialEq for AsBlock {
    fn eq(&self, other: &AsBlock) -> bool {
        self.is_equivalent(other)
    }
}

impl Eq for AsBlock {}


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

    fn previous(item: Self::Item) -> Option<Self::Item> {
        item.0.checked_sub(1).map(AsId)
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

    /// Skips over the content of an AS range value.
    fn skip_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<(), S::Err> {
        let cons = content.as_constructed()?;
        AsId::skip_in(cons)?;
        AsId::skip_in(cons)?;
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

    fn previous(item: Self::Item) -> Option<Self::Item> {
        item.0.checked_sub(1).map(AsId)
    }
}

//--- Display

impl fmt::Display for AsRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.min, self.max)
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

    /// Skips over the AS number at the beginning of an encoded value.
    fn skip_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(), S::Err> {
        cons.take_u32().map(|_| ())
    }

    /// Parses the content of an AS number value.
    fn parse_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, S::Err> {
        content.to_u32().map(AsId)
    }

    /// Skips the content of an AS number value.
    fn skip_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<(), S::Err> {
        content.to_u32().map(|_| ())
    }

    pub fn encode(self) -> impl encode::Values {
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


//--- FromStr

impl FromStr for AsId {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {

        let s = if s.len() > 2 && s[..2].eq_ignore_ascii_case("as") {
            &s[2..]
        } else {
            s
        };

        let id = u32::from_str(s).map_err(|_| FromStrError::BadAsn)?;
        Ok(AsId(id))
    }
}


//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl serde::Serialize for AsId {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let s = format!("{}", self);
        serializer.serialize_str(&s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::de::Deserialize<'de> for AsId {
    fn deserialize<D: serde::de::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = AsId;

            fn expecting(
                &self, formatter: &mut fmt::Formatter
            ) -> fmt::Result {
                write!(formatter, "a string with an AS number")
            }

            fn visit_str<E: serde::de::Error>(
                self, v: &str
            ) -> Result<Self::Value, E> {
                AsId::from_str(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
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


//------------ FromStrError --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum FromStrError {
    BadAsn,
    BadRange,
    BadBlocks,
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


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use serde_test::{Token, assert_de_tokens, assert_tokens};

    #[test]
    fn as_id_from_str() {
        assert_eq!(AsId::from_str("AS1").unwrap(), AsId(1));
        assert_eq!(AsId::from_str("As1").unwrap(), AsId(1));
        assert_eq!(AsId::from_str("1").unwrap(), AsId(1));
    }

    #[test]
    fn as_id_display() {
        assert_eq!(format!("{}", AsId(1)), "AS1");
    }

    #[test]
    fn as_id_serde() {
        assert_tokens(&AsId(12), &[Token::Str("AS12")]);
        assert_de_tokens(&AsId(12), &[Token::Str("as12")]);
        assert_de_tokens(&AsId(12), &[Token::Str("12")]);
    }

    #[test]
    fn as_block_from_str() {
        // Good
        assert_eq!(
            AsBlock::from_str("AS1").unwrap(),
            AsId(1).into()
        );
        assert_eq!(
            AsBlock::from_str("AS1-AS3").unwrap(),
            AsRange::new(AsId(1), AsId(3)).into()
        );

        // Bad
        assert!(AsBlock::from_str("AS1-").is_err());
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
            vec![AsId(1).into(), AsRange::new(AsId(3), AsId(7)).into()]
        );
        good(
            "AS1,AS3-AS7", 
            vec![AsId(1).into(), AsRange::new(AsId(3), AsId(7)).into()]
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
