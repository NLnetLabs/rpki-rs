//! Types for AS and IP adress resources.
//!
//! This module cotains the basic types for representing resources protected
//! by RPKI: [`Asn`] for autonomous system numbers, [`Prefix`] for IP address
//! prefixes, and [`MaxLenPrefix`] for prefixes with a prefix length range.

pub use self::addr::{MaxLenPrefix, Prefix};
pub use self::asn::{Asn, SmallAsnSet};

pub mod addr;
pub mod asn;
