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

use std::{fmt, ops};
use bcder::{decode, encode};
use bcder::{Captured, Mode, Tag};
use bcder::encode::PrimitiveContent;
use super::x509::ValidationError;


//------------ AsResources ---------------------------------------------------

/// The AS Resources of an RPKI Certificate.
///
/// This type contains the resources as represented in an RPKI certificates
/// AS resources extension. This extension provides two options: there can
/// be an actual set of AS numbers associated with the certificate – this is
/// the `AsResources::Ids` variant –, or the AS resources of the issuer can
/// be inherited – the `AsResources::Inherit` variant.
pub type AsResources = AsChoice<AsIdBlocks>;

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
                        Ok(AsChoice::Inherit)
                    }
                    else if tag == Tag::SEQUENCE {
                        AsIdBlocks::parse_content(content)
                            .map(AsChoice::Ids)
                    }
                    else {
                        xerr!(Err(decode::Error::Malformed.into()))
                    }
                })
            })
        })
    }
}


//------------ AsResourcesBuilder --------------------------------------------

#[derive(Clone, Debug)]
pub struct AsResourcesBuilder {
    res: Option<AsChoice<AsIdBlocksBuilder>>
}

impl AsResourcesBuilder {
    pub fn new() -> Self {
        AsResourcesBuilder {
            res: None
        }
    }

    pub fn inhert(&mut self) {
        self.res = Some(AsChoice::Inherit)
    }

    pub fn blocks<F>(&mut self, build: F)
    where F: FnOnce(&mut AsIdBlocksBuilder) {
        if self.res.as_ref().map(|res| res.is_inherited()).unwrap_or(false) {
            self.res = Some(AsChoice::Ids(AsIdBlocksBuilder::new()))
        }
        build(self.res.as_mut().unwrap().as_blocks_mut().unwrap())
    }

    pub fn encode<'a>(&'a self) -> Option<impl encode::Values + 'a> {
        self.res.as_ref().map(|res| {
            encode::sequence(
                encode::sequence_as(Tag::CTX_0, res.encode())
            )
        })
    }
}


//------------ AsChoice ------------------------------------------------------
#[derive(Clone, Debug)]
pub enum AsChoice<T> {
    /// AS resources are to be inherited from the issuer.
    Inherit,

    /// The AS resources are provided as a set of AS numbers.
    ///
    /// This set is represented as a sequence of consecutive blocks of AS
    /// numbers.
    Ids(T),
}

impl<T> AsChoice<T> {
    /// Returns whether the AS resources are of the inherited variant.
    pub fn is_inherited(&self) -> bool {
        match self {
            AsChoice::Inherit => true,
            _ =>  false
        }
    }

    pub fn as_blocks(&self) -> Option<&T> {
        match self {
            AsChoice::Inherit => None,
            AsChoice::Ids(ref some) => Some(some)
        }
    }

    pub fn as_blocks_mut(&mut self) -> Option<&mut T> {
        match self {
            AsChoice::Inherit => None,
            AsChoice::Ids(ref mut some) => Some(some)
        }
    }

    /// Converts the AS resources into a AS number blocks sequence.
    ///
    /// If this value is of the inherited variant, a validation error will
    /// be returned.
    pub fn to_blocks(&self) -> Result<T, ValidationError>
    where T: Clone {
        match self {
            AsChoice::Inherit => Err(ValidationError),
            AsChoice::Ids(ref some) => Ok(some.clone()),
        }
    }
}

impl AsChoice<AsIdBlocksBuilder> {
    fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        match *self {
            AsChoice::Inherit => encode::Choice2::One(().encode()),
            AsChoice::Ids(ref blocks) => {
                encode::Choice2::Two(blocks.encode())
            }
        }
    }
}


//------------ AsBlocks ------------------------------------------------------

/// A possibly empty sequence of consecutive sets of AS numbers.
#[derive(Clone, Debug)]
pub struct AsBlocks(Option<AsIdBlocks>);

impl AsBlocks {
    /// Creates AS blocks from AS resources.
    ///
    /// If the AS resources are of the inherited variant, a validation error
    /// is returned.
    pub fn from_resources(
        res: Option<&AsResources>
    ) -> Result<Self, ValidationError> {
        match res {
            Some(AsChoice::Inherit) => Err(ValidationError),
            Some(AsChoice::Ids(ref some)) => {
                Ok(AsBlocks(Some(some.clone())))
            }
            None => Ok(AsBlocks(None))
        }
    }

    /// Checks that some AS resource are encompassed by this AS blocks value.
    ///
    /// Upon success, returns the effictive AS blocks to use for the AS
    /// resource.
    pub fn encompasses(
        &self,
        res: Option<&AsResources>
    ) -> Result<Self, ValidationError> {
        match res {
            Some(AsChoice::Inherit) => Ok(self.clone()),
            Some(AsChoice::Ids(ref inner)) => {
                match self.0 {
                    Some(ref outer) => {
                        if outer.encompasses(inner) {
                            Ok(AsBlocks(Some(inner.clone())))
                        }
                        else {
                            Err(ValidationError)
                        }
                    }
                    None => Err(ValidationError)
                }
            }
            None => Ok(AsBlocks(None))
        }
    }
}


//------------ AsIdBlocks ----------------------------------------------------

/// A DER-encoded sequence of blocks of consecutive AS numbers.
//
//  The bytes values contains the content octets of the DER encoding of the
//  blocks.
#[derive(Clone, Debug)]
pub struct AsIdBlocks(Captured);

impl AsIdBlocks {
    /// Creates a new, empty value.
    pub fn new() -> Self {
        AsIdBlocks(Captured::empty(Mode::Der))
    }

    /// Pushes a new block to the end of the value.
    pub fn push(&mut self, block: &AsBlock) {
        self.0.extend(block.encode())
    }

    /// Returns an iterator over the individual AS number blocks.
    pub fn iter(&self) -> AsIdBlockIter {
        AsIdBlockIter(self.0.as_ref())
    }
}

impl AsIdBlocks {
    /// Parses the content of a AS ID blocks sequence.
    fn parse_content<S: decode::Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, S::Err> {
        let cons = content.as_constructed()?;
        cons.capture(|cons| {
            while let Some(()) = AsBlock::skip_opt_in(cons)? { }
            Ok(())
        }).map(AsIdBlocks)
    }

    /// Returns wether `other` is encompassed by `self`.
    ///
    /// For this to be true, `other` all AS numbers that are part of `other`
    /// need to be part of `self`, too.
    fn encompasses(&self, other: &AsIdBlocks) -> bool {
        // Numbers need to be in increasing order. So we can loop over the
        // blocks in other and check that self keeps pace.
        let mut siter = self.iter();
        let mut oiter = other.iter();
        let (mut sas, mut oas) = match (siter.next(), oiter.next()) {
            (_, None) => return true,
            (None, Some(_)) => return false,
            (Some(sas), Some(oas)) => (sas, oas),
        };
        loop {
            // If they start below us, we don’t encompass them.
            if oas.min() < sas.min() {
                return false
            }
            // It they start above us, we need to go to the next range.
            else if oas.min() > sas.max() {
                sas = match siter.next() {
                    Some(sas) => sas,
                    None => return false,
                }
            }
            // If they end above us we lift their start to our end plus 1.
            else if oas.max() > sas.max() {
                // This can’t happen if sas.max() is u32::MAX (because
                // oas.max() can never be greater than that), so this
                // should be safe.
                oas.set_min(sas.max() + 1)
            }
            // If they neither start below us nor end above us, we cover them
            // and take the next block.
            else {
                oas = match oiter.next() {
                    Some(oas) => oas,
                    None => return true
                }
            }
        }
    }

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        &self.0
    }
}


//------------ AsIdBlockIter -------------------------------------------------

/// An iterator over the AS blocks in an AS blocks sequence.
pub struct AsIdBlockIter<'a>(&'a [u8]);

impl<'a> Iterator for AsIdBlockIter<'a> {
    type Item = AsBlock;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        }
        else {
            Mode::Der.decode(&mut self.0, AsBlock::take_opt_from).unwrap()
        }
    }
}


//------------ AsIdBlocksBuilder ---------------------------------------------

#[derive(Clone, Debug)]
pub struct AsIdBlocksBuilder(Vec<AsBlock>);

impl AsIdBlocksBuilder {
    fn new() -> Self {
        AsIdBlocksBuilder(Vec::new())
    }

    pub fn push<T: Into<AsBlock>>(&mut self, block: T) {
        self.0.push(block.into())
    }

    fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode::Iter::new(self.0.iter().map(|block| block.encode()))
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

    fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        match *self {
            AsBlock::Id(ref inner) => encode::Choice2::One(inner.encode()),
            AsBlock::Range(ref inner) => encode::Choice2::Two(inner.encode()),
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


//------------ AsId ----------------------------------------------------------

/// An AS number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AsId(u32);

impl AsId {
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

    fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        self.0.encode()
    }
}

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

impl ops::Add<u32> for AsId {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        AsId(self.0.checked_add(rhs).unwrap())
    }
}

impl fmt::Display for AsId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AS{}", self.0)
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
    pub fn min(&self) -> AsId {
        self.min
    }

    /// Returns the largest AS number that is still part of this range.
    pub fn max(&self) -> AsId {
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

    fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            self.min.encode(),
            self.max.encode(),
        ))
    }
}

