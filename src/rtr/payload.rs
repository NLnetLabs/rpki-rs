//! The data being transmitted via RTR.
//!
//! The types in here provide a more compact representation than the PDUs.
//! They also implement all the traits to use them as keys in collections to
//! be able to perform difference processing.
//!
//! The types are currently not very rich. They will receive more methods as
//! they become necessary. So don’t hesitate to ask for them!

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;


//------------ IPv4Prefix ----------------------------------------------------

/// An IPv4 route origin authorisation.
///
/// Values of this type authorise the autonomous system given in `asn` to
/// announce routes for the prefixes covered via the three other fields.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv4Prefix {
    /// The IPv4 address of the prefix.
    ///
    /// Only the most significant `prefix_len` bits are used. All other bits
    /// should be zero.
    pub prefix: Ipv4Addr,

    /// The prefix length.
    ///
    /// The number of bits in `prefix` that are used. Obviously, this cannot
    /// be larger than 32.
    pub prefix_len: u8,

    /// The maximum length of an more specific prefix covered.
    ///
    /// The value will cover all prefixes that are covered by
    /// `prefix`/`prefix_len` and have a prefix length of up to this value.
    pub max_len: u8,

    /// The autonomous system allowed to announce the prefixes.
    pub asn: u32
}


//------------ IPv6Prefix ----------------------------------------------------

/// An IPv6 route origin authorisation.
///
/// Values of this type authorise the autonomous system given in `asn` to
/// announce routes for the prefixes covered via the three other fields.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv6Prefix {
    /// The IPv4 address of the prefix.
    ///
    /// Only the most significant `prefix_len` bits are used. All other bits
    /// should be zero.
    pub prefix: Ipv6Addr,

    pub prefix_len: u8,

    /// The maximum length of an more specific prefix covered.
    ///
    /// The value will cover all prefixes that are covered by
    /// `prefix`/`prefix_len` and have a prefix length of up to this value.
    pub max_len: u8,

    /// The autonomous system allowed to announce the prefixes.
    pub asn: u32
}


//------------ Payload -------------------------------------------------------

/// All payload types supported by RTR and this crate.
///
/// There is at least one more payload type – BGPSEC router keys – that is not
/// currently supported by the crate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Payload {
    /// An IPv4 route origin authorisation.
    V4(Ipv4Prefix),

    /// An IPv6 route origin authorisation.
    V6(Ipv6Prefix)
}


//------------ Action --------------------------------------------------------

/// What to do with a given payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Action {
    /// Announce the payload.
    ///
    /// In other words, add the payload to your set of VRPs.
    Announce,

    /// Withdraw the payload.
    /// In other words, re move the payload to your set of VRPs.
    Withdraw,
}

impl Action {
    /// Returns whether the action is to announce.
    pub fn is_announce(self) -> bool {
        matches!(self, Action::Announce)
    }

    /// Returns whether the action is to withdraw.
    pub fn is_withdraw(self) -> bool {
        matches!(self, Action::Withdraw)
    }

    /// Creates the action from the flags field of an RTR PDU.
    pub fn from_flags(flags: u8) -> Self {
        if flags & 1 == 1 {
            Action::Announce
        }
        else {
            Action::Withdraw
        }
    }

    /// Converts the action into the flags field of an RTR PDU.
    pub fn into_flags(self) -> u8 {
        match self {
            Action::Announce => 1,
            Action::Withdraw => 0
        }
    }
}


//------------ Timing --------------------------------------------------------

/// The timing parameters of a data exchange.
///
/// These three values are included in the end-of-data PDU of version 1
/// onwards.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// The number of seconds until a client should refresh its data.
    pub refresh: u32,

    /// The number of seconds a client whould wait before retrying to connect.
    pub retry: u32,

    /// The number of secionds before data expires if not refreshed.
    pub expire: u32
}

impl Timing {
    pub fn refresh_duration(self) -> Duration {
        Duration::from_secs(u64::from(self.refresh))
    }
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            refresh: 3600,
            retry: 600,
            expire: 7200
        }
    }
}

