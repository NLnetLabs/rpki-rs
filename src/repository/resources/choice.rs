/// An enum offering the choice between inherited and included resources.
///
/// This is a private module used only internally.

use std::fmt;


//------------ ResourcesChoice -----------------------------------------------

/// The option to either include or inherit resources.
///
/// This is generic over the type of included resources.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ResourcesChoice<T> {
    /// There are no resources of this type.
    ///
    /// This is a special case since creating an empty `T` may still be pricy.
    Missing,

    /// Resources are to be inherited from the issuer.
    Inherit,

    /// The resources are provided as a set of blocks.
    Blocks(T),
}

impl<T> ResourcesChoice<T> {
    /// Returns whether the resources are of the inherited variant.
    pub fn is_inherited(&self) -> bool {
        matches!(self, ResourcesChoice::Inherit)
    }

    /// Returns whether the resources are present.
    pub fn is_present(&self) -> bool {
        !matches!(self, ResourcesChoice::Missing)
    }

    /// Converts the resources into blocks or returns an error.
    ///
    /// In case the resources are missing, returns a default `T`.
    pub fn to_blocks(&self) -> Result<T, InheritedResources>
    where T: Clone + Default {
        match self {
            ResourcesChoice::Missing => Ok(Default::default()),
            ResourcesChoice::Inherit => Err(InheritedResources),
            ResourcesChoice::Blocks(ref some) => Ok(some.clone()),
        }
    }

    /// Converts the choice into a different choice via a closure.
    ///
    /// If this value is of the included variant, runs the blocks through
    /// the provided closure and returns a new choice with the result. If
    /// this value is of the inherit or missing variant, does nothing and
    /// simply returns the choice.
    pub fn map_blocks<U, F>(self, f: F) -> ResourcesChoice<U>
    where F: FnOnce(T) -> U {
        match self {
            ResourcesChoice::Missing => ResourcesChoice::Missing,
            ResourcesChoice::Inherit => ResourcesChoice::Inherit,
            ResourcesChoice::Blocks(t) => ResourcesChoice::Blocks(f(t))
        }
    }
}


//--- Display

impl<T: fmt::Display> fmt::Display for ResourcesChoice<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ResourcesChoice::Missing => Ok(()),
            ResourcesChoice::Inherit => write!(f, "inherit"),
            ResourcesChoice::Blocks(ref inner) => inner.fmt(f)
        }
    }
}


//------------ InheritedResources --------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct InheritedResources;

