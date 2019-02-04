//! Types for dealing with ranges of resources.
//!
//! These types are used for dealing with both IP resources and AS resources.
//! A range of such resources, defined by a minimum and a maximum range shall
//! be a `block`. As there are different representations of these blocks, we
//! define the trait [`Block`] for that.
//!
//! An sequence of ordered, non-overlapping blocks shall be called a `chain`.
//! It is available as the unsized type `Chain` and `OwnedChain` which is
//! essentially a boxed chain.

use std::{iter, mem, ops};
use std::cmp::{min, max};
use std::sync::Arc;


//------------ Block ---------------------------------------------------------

pub trait Block: Clone {
    type Item: Copy + Eq + Ord;

    /// Creates a new block from the minimum and maximum.
    fn new(min: Self::Item, max: Self::Item) -> Self;

    /// Returns the smallest item that is part of the block.
    fn min(&self) -> Self::Item;

    /// Returns the largest item that is part of the block.
    fn max(&self) -> Self::Item;

    /// Returns the item immediately following the given item.
    fn next(item: Self::Item) -> Option<Self::Item>;

    /// Returns a pair of the smallest and largest item in the block.
    fn bounds(&self) -> (Self::Item, Self::Item) {
        (self.min(), self.max())
    }

    /// Returns whether an item is part of the block.
    fn contains(&self, item: Self::Item) -> bool {
        self.min() <= item && self.max() >= item
    }

    /// Returnes whether a block intersects with another block.
    fn intersects(&self, other: &Self) -> bool {
        self.min() <= other.max() && self.max() >= other.min()
    }

    /// Returns whether a block is encompassed by another block.
    ///
    /// For this to happen, the other block needs to be larger or the same.
    fn is_encompassed(&self, other: &Self) -> bool {
        other.min() <= self.min() && other.max() >= self.max()
    }

    /// Returns the sum of two blocks if they overlap.
    fn sum(&self, other: &Self) -> Option<Self>
    where Self: Sized {
        if self.intersects(other) {
            Some(Self::new(
                min(self.min(), other.min()),
                max(self.max(), other.max())
            ))
        }
        else if Self::next(self.max()) == Some(other.min()) {
            Some(Self::new(self.min(), other.max()))
        }
        else if Self::next(other.max()) == Some(self.min()) {
            Some(Self::new(other.min(), self.max()))
        }
        else {
            None
        }
    }
}


//------------ Chain ---------------------------------------------------------

/// An ordered, non-overlapping, non-continuous sequence of blocks.
#[derive(Debug)]
pub struct Chain<T: Block>([T]);

impl<T: Block> Chain<T> {
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn empty() -> &'static Self {
        unsafe { mem::transmute::<&[T], _>(&[]) }
    }

    /// Checks whether `self` is encompassed by `other`.
    ///
    /// The chain `other` needs to be equal to or bigger than `self`.
    pub fn is_encompassed<C: AsRef<Chain<T>>>(&self, other: &C) -> bool {
        let mut other = &other.as_ref().0;

        // Border case: if other is empty, self must be empty to.
        if other.is_empty() {
            return self.0.is_empty()
        }

        // Each block in self needs to be fully contained by a block in
        // other. It can’t be in more than one block because the chain does
        // not contain two consecutive blocks. Also, since the blocks are
        // ordered, the matching block in outer cannot be before the last
        // one we found. So we work on the slice of other and cut off the
        // first block whenever we have gone past it.

        for block in self.iter() {
            // Skip over other blocks before our block. Return if other
            // becomes empty. Other always has at least one block left when
            // we start this, so unwrap here is fine.
            while other.first().unwrap().max() < block.min() {
                other = match other.split_first() {
                    Some((_, tail)) => tail,
                    None => return false,
                }
            }
            // The first other block ends after our start, so it must
            // encompass us.
            if !block.is_encompassed(&other.first().unwrap()) {
                return false
            }
        }
        true
    }

    /// Trims `self` down do be encompassed by `other`.
    ///
    /// Returns `Ok(())` if `self` is already encompassed by `other` and,
    /// depending on the use case, can either be used directly or cloned.
    /// Returns `Err(_)` with a new owned chain if `self` needed be trimmed
    /// down to fit `other`
    pub fn trim<C: AsRef<Chain<T>>>(
        &self, other: &C
    ) -> Result<(), OwnedChain<T>> {
        let other = other.as_ref();

        // Border case: if other is empty, the result is an empty chain.
        if other.0.is_empty() {
            return Err(OwnedChain::empty())
        }
        // Second border case: if self is empty, it is fine no matter what.
        if self.0.is_empty() {
            return Ok(())
        }

        // The iterators return references since we don’t own the chains but
        // we need to be able to update the self item when we processed part
        // of it. To allow that, we keep it as a pair of
        // `(item.min(), item.max()` and use `T::new()` when we create an
        // actual block.

        let mut other_iter = other.iter();
        let mut other_item = other_iter.next().unwrap();
        let mut self_iter = self.iter();
        let mut self_item = {
            self_iter.next().map(|item| (item.min(), item.max())).unwrap()
        };

        // This will either hold the index of the block we’re currently
        // working on or a vector of cloned and trimmed blocks.
        let mut res: Result<usize, Vec<_>> = Ok(0);

        loop {
            // Skip over other items before self item. If we run out of other
            // items, we are done.
            while other_item.max() < self_item.0 {
                other_item = match other_iter.next() {
                    Some(item) => item,
                    None => break
                }
            }

            // Other item ends after self item starts. There is a few
            // possibilities now. It self item is covered, we get to
            // keep it.
            if self_item.0 >= other_item.min()
                        && self_item.1 <= other_item.max() {
                match res {
                    Ok(ref mut idx) => *idx += 1,
                    Err(ref mut vec) => {
                        vec.push(T::new(self_item.0, self_item.1));
                    }
                }
                self_item = match self_iter.next() {
                    Some(item) => (item.min(), item.max()),
                    None => {
                        match res {
                            Ok(_) => return Ok(()),
                            Err(_) => break,
                        }
                    }
                }
            }
            else {
                // We now produce a pair of the processed and unprocessed
                // parts of self item. If the processed part is None, there
                // isn’t anything to keep. If the unprocessed part is None,
                // self item has been fully processed.
                let (keep, redo) = if self_item.1 < other_item.min() {
                    (None, None)
                }
                else if self_item.1 <= other_item.max() {
                    (
                        Some(T::new(
                            max(self_item.0, other_item.min()),
                            self_item.1
                        )),
                        None
                    )
                }
                else {
                    (
                        Some(T::new(
                            max(self_item.0, other_item.min()),
                            other_item.max())
                        ),
                        Some((
                            // next is None of the value cannot be
                            // incremented. In this case, self_item.1 cannot
                            // be larger than it and we don’t end up here.
                            T::next(other_item.max()).unwrap(),
                            self_item.1
                        ))
                    )
                };

                // If we don’t have a vector yet, we need to create one.
                if let Ok(idx) = res {
                    res = Err(self.0[..idx].into());
                }

                // Now we can add the trimmed item if there is one.
                if let Some(keep) = keep {
                    match res {
                        Err(ref mut vec) => vec.push(keep),
                        _ => unreachable!()
                    }
                }

                match redo {
                    Some(item) => self_item = item,
                    None => {
                        match self_iter.next() {
                            Some(item) => {
                                self_item = (item.min(), item.max())
                            }
                            None => {
                                // res is a vec. Just break.
                                break;
                            }
                        }
                    }
                }
            }
        }

        // If we come out here, we ran out of items. If res is a vec,
        // we have everything.
        //
        // If res is an index, we ran out of other items (we return early
        // otherwise) and need to make a copy of the indexed elements.
        let res = match res {
            Ok(idx) => self.0[..idx + 1].into(),
            Err(vec) => vec
        };
        Err(unsafe { OwnedChain::from_vec_unchecked(res) })
    }

}


//--- Deref, AsRef

impl<T: Block> ops::Deref for Chain<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Block> AsRef<[T]> for Chain<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}


//------------ OwnedChain ----------------------------------------------------

/// An owned version of a chain.
//
//  Note: This isn’t a `Box<Chain<T>>` because converting a vec to a box
//        likely means re-allocating to drop down from capacity. We don’t
//        want to force that upon users, so we keep the vec.
#[derive(Clone, Debug)]
pub struct OwnedChain<T: Block>(Vec<T>);

impl<T: Block> OwnedChain<T> {
    unsafe fn from_vec_unchecked(vec: Vec<T>) -> Self {
        OwnedChain(vec)
    }

    pub fn empty() -> Self {
        OwnedChain(Vec::new())
    }

    pub fn as_chain(&self) -> &Chain<T> {
        unsafe { mem::transmute(self.0.as_slice()) }
    }
}


//--- FromIterator

impl<T: Block> iter::FromIterator<T> for OwnedChain<T> {
    fn from_iter<I>(iter: I) -> Self
    where I: IntoIterator<Item=T> {
        // We optimize for the case where the blocks in the iterator are
        // sorted. If that turns out not to be the case, we switch to a
        // different strategy.
        let mut res = Vec::new();
        let mut iter = iter.into_iter();

        while let Some(block) = iter.next() {
            if let Some((last_min, last_max)) = res.last().map(Block::bounds) {
                if block.min() < last_min {
                    return from_iter_unsorted(res, block, iter)
                }
                else if block.min() <= last_max {
                    // The blocks starts within the last block. If it ends
                    // later (i.e., it overlaps) we just update the last
                    // block’s max. Else we ignore it.
                    if block.max() > last_max {
                        *res.last_mut().unwrap() = T::new(
                            last_min, block.max()
                        );
                    }
                }
                else if T::next(last_max) == Some(block.min()) {
                    // The block starts right after the previous block ends.
                    // We merge the two.
                    *res.last_mut().unwrap() = T::new(last_min, block.max())
                }
                else {
                    res.push(block)
                }
            }
            else {
                res.push(block)
            }
        }
        unsafe { Self::from_vec_unchecked(res) }
    }
}

fn from_iter_unsorted<T: Block, I: Iterator<Item=T>>(
    mut res: Vec<T>,
    block: T,
    iter: I,
) -> OwnedChain<T> {
    // Here’s the strategy for now: For each block, check whether it extends
    // an existing block, otherwise push it to the end. Sort after we have
    // all blocks.
    merge_or_add_block(&mut res, block);
    for block in iter {
        merge_or_add_block(&mut res, block);
    }
    res.sort_unstable_by_key(|block| block.min());
    unsafe { OwnedChain::from_vec_unchecked(res) }
}

fn merge_or_add_block<T: Block>(res: &mut Vec<T>, block: T) {
    for elem in res.iter_mut() {
        if let Some(sum) = elem.sum(&block) {
            *elem = sum;
            return
        }
    }
    res.push(block)
}


//--- From

impl<T: Block> From<Vec<T>> for OwnedChain<T> {
    fn from(src: Vec<T>) -> Self {
        <Self as iter::FromIterator<T>>::from_iter(src)
    }
}

impl<'a, T: Block + Clone> From<&'a [T]> for OwnedChain<T> {
    fn from(src: &'a [T]) -> Self {
        <Self as iter::FromIterator<T>>::from_iter(
            src.iter().map(Clone::clone)
        )
    }
}


//--- Deref and AsRef

impl<T: Block> ops::Deref for OwnedChain<T> {
    type Target = Chain<T>;

    fn deref(&self) -> &Self::Target {
        self.as_chain()
    }
}

impl<T: Block> AsRef<Chain<T>> for OwnedChain<T> {
    fn as_ref(&self) -> &Chain<T> {
        self.as_chain()
    }
}

impl<T: Block> AsRef<[T]> for OwnedChain<T> {
    fn as_ref(&self) -> &[T] {
        self.as_chain().as_ref()
    }
}


//------------ SharedChain ---------------------------------------------------

/// A shared, owned version of a chain.
///
/// This is essentially an owned chain inside of an arc with an optimization
/// so that empty chains never get actually allocated.
#[derive(Clone, Debug)]
pub struct SharedChain<T: Block + 'static>(Option<Arc<OwnedChain<T>>>);

impl<T: Block + 'static> SharedChain<T> {
    pub fn from_owned(owned: OwnedChain<T>) -> Self {
        if owned.is_empty() {
            SharedChain(None)
        }
        else {
            SharedChain(Some(Arc::new(owned)))
        }
    }

    pub fn empty() -> Self {
        SharedChain(None)
    }

    pub fn as_chain(&self) -> &Chain<T> {
        match self.0.as_ref() {
            Some(chain) => chain.as_chain(),
            None => Chain::empty(),
        }
    }
}


//--- From, FromIterator

impl<T: Block + 'static, F> From<F> for SharedChain<T>
where OwnedChain<T>: From<F> {
    fn from(f: F) -> Self {
        Self::from_owned(OwnedChain::from(f))
    }
}

impl<T: Block + 'static> iter::FromIterator<T> for SharedChain<T> {
    fn from_iter<I>(iter: I) -> Self
    where I: IntoIterator<Item=T> {
        OwnedChain::from_iter(iter).into()
    }
}


//--- Deref and AsRef

impl<T: Block + 'static> ops::Deref for SharedChain<T> {
    type Target = Chain<T>;

    fn deref(&self) -> &Self::Target {
        self.as_chain()
    }
}

impl<T: Block + 'static> AsRef<Chain<T>> for SharedChain<T> {
    fn as_ref(&self) -> &Chain<T> {
        self.as_chain()
    }
}

impl<T: Block + 'static> AsRef<[T]> for SharedChain<T> {
    fn as_ref(&self) -> &[T] {
        self.as_chain().as_ref()
    }
}



//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    impl Block for (u8, u8) {
        type Item = u8;

        fn new(min: u8, max: u8) -> Self { (min, max) }
        fn min(&self) -> u8 { self.0 }
        fn max(&self) -> u8 { self.1 }
        fn next(item: u8) -> Option<u8> { item.checked_add(1) }
    }

    #[test]
    fn from_iter() {
        // Happy case.
        assert_eq!(
            OwnedChain::from([(1,4), (6,8), (23,48)].as_ref()).as_slice(),
            &[(1,4), (6,8), (23,48)][..]
        );
        // Sorted consecutive blocks
        assert_eq!(
            OwnedChain::from([(1,4), (5,8), (23,48)].as_ref()).as_slice(),
            &[(1,8), (23,48)][..]
        );
        // Sorted overlapping blocks
        assert_eq!(
            OwnedChain::from([(1,4), (3,8), (23,48)].as_ref()).as_slice(),
            &[(1,8), (23,48)][..]
        );
        // Unsorted blocks
        assert_eq!(
            OwnedChain::from([(1,4), (23,48), (6,8)].as_ref()).as_slice(),
            &[(1,4), (6,8), (23,48)][..]
        );
        // Unsorted overlapping blocks
        assert_eq!(
            OwnedChain::from([(1,4), (23,48), (5,8)].as_ref()).as_slice(),
            &[(1,8), (23,48)][..]
        );
        assert_eq!(
            OwnedChain::from([(1,4), (23,48), (3,8)].as_ref()).as_slice(),
            &[(1,8), (23,48)][..]
        );
        assert_eq!(
            OwnedChain::from([(5,8), (3,6), (4,8)].as_ref()).as_slice(),
            &[(3, 8)][..]
        );
    }

    #[test]
    fn is_encompassed() {
        let chain = OwnedChain::from([(1,4), (11,18), (23,48)].as_ref());
        assert!(
            OwnedChain::from([(1,4), (13,18), (23,48)].as_ref())
                .is_encompassed(&chain)
        );
        assert!(
            OwnedChain::from([(3,4)].as_ref())
                .is_encompassed(&chain)
        );
        assert!(
            !OwnedChain::from([(3,9)].as_ref())
                .is_encompassed(&chain)
        );
    }

    #[test]
    fn trim() {
        let chain = OwnedChain::from([(1,4), (11,18), (23,48)].as_ref());
        assert!(
            OwnedChain::from([(1,4), (11,18), (23,48)].as_ref())
                .trim(&chain).is_ok()
        );
        assert!(
            OwnedChain::from([(13,18)].as_ref())
                .trim(&chain).is_ok()
        );
        assert!(
            OwnedChain::from([(30,38)].as_ref())
                .trim(&chain).is_ok()
        );
        assert_eq!(
            OwnedChain::from([(1,6), (13,45)].as_ref())
                .trim(&chain).unwrap_err().as_slice(),
            &[(1,4), (13,18), (23,45)][..]
        );
        assert_eq!(
            OwnedChain::from([(1,4), (13,45)].as_ref())
                .trim(&chain).unwrap_err().as_slice(),
            &[(1,4), (13,18), (23,45)][..]
        );
        assert_eq!(
            OwnedChain::from([(13,45)].as_ref())
                .trim(&chain).unwrap_err().as_slice(),
            &[(13,18), (23,45)][..]
        );
        
        let chain = OwnedChain::from([(1,4), (11,18), (23,255)].as_ref());
        assert_eq!(
            OwnedChain::from([(13,255)].as_ref())
                .trim(&chain).unwrap_err().as_slice(),
            &[(13,18), (23,255)][..]
        );
    }
}
