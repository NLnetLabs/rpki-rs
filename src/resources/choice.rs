/// An enum offering the choice between inherited and included resources.
///
/// This is a private module used only internally.

use crate::x509::ValidationError;


//------------ ResourcesChoice -----------------------------------------------

/// The option to either include or inherit resources.
///
/// This is generic over the type of included resources.
#[derive(Clone, Debug)]
pub enum ResourcesChoice<T> {
    /// Resources are to be inherited from the issuer.
    Inherit,

    /// The resources are provided as a set of blocks.
    Blocks(T),
}

impl<T> ResourcesChoice<T> {
    /// Returns whether the resources are of the inherited variant.
    pub fn is_inherited(&self) -> bool {
        match self {
            ResourcesChoice::Inherit => true,
            _ =>  false
        }
    }

    /// Returns a reference to the blocks if there are any.
    pub fn as_blocks(&self) -> Option<&T> {
        match self {
            ResourcesChoice::Inherit => None,
            ResourcesChoice::Blocks(ref some) => Some(some)
        }
    }

    /// Returns a mutable reference to the blocks if there are any.
    pub fn as_blocks_mut(&mut self) -> Option<&mut T> {
        match self {
            ResourcesChoice::Inherit => None,
            ResourcesChoice::Blocks(ref mut some) => Some(some)
        }
    }

    /// Converts the resources into blocks or returns an error.
    pub fn to_blocks(&self) -> Result<T, ValidationError>
    where T: Clone {
        match self {
            ResourcesChoice::Inherit => Err(ValidationError),
            ResourcesChoice::Blocks(ref some) => Ok(some.clone()),
        }
    }

    /// Converts the choice into a different choice via a closure.
    ///
    /// If this value is of the included variant, runs the blocks through
    /// the provided closure and returns a new choice with the result. If
    /// this value is of the inherit variant, does nothing and simply
    /// returns the choice.
    pub fn map_blocks<U, F>(self, f: F) -> ResourcesChoice<U>
    where F: FnOnce(T) -> U {
        match self {
            ResourcesChoice::Inherit => ResourcesChoice::Inherit,
            ResourcesChoice::Blocks(t) => ResourcesChoice::Blocks(f(t))
        }
    }
}

