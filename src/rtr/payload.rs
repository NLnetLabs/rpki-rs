//! The data being transmitted via RTR.
//!
//! The types in here provide a more compact representation than the PDUs.
//! They also implement all the traits to use them as keys in collections to
//! be able to perform difference processing.
//!
//! The types are currently not very rich. They will receive more methods as
//! they become necessary. So don’t hesitate to ask for them!

use std::time::Duration;
use bytes::Bytes;
use routecore::addr::MaxLenPrefix;
use routecore::asn::Asn;
use routecore::bgpsec::KeyIdentifier;


//------------ RouteOrigin ---------------------------------------------------

/// A route origin authorization.
///
/// Values of this type authorize the autonomous system given in the `asn`
/// field to routes for the IP address prefixes given in the `prefix` field.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteOrigin {
    /// The address prefix to authorize.
    pub prefix: MaxLenPrefix,

    /// The autonomous system allowed to announce the prefixes.
    pub asn: Asn, 
}

impl RouteOrigin {
    /// Creates a new value from a prefix and an ASN.
    pub fn new(prefix: MaxLenPrefix, asn: Asn) -> Self {
        RouteOrigin { prefix, asn }
    }
}


//------------ RouterKey -----------------------------------------------------

/// A BGPsec router key.
///
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouterKey {
    /// The subject key identifier of the router key.
    pub key_identifier: KeyIdentifier,

    /// The autonomous system authorized to use the key.
    pub asn: Asn,

    /// The actual key.
    pub key_info: Bytes,
}

impl RouterKey {
    /// Creates a new value from the various components.
    pub fn new(
        key_identifier: KeyIdentifier, asn: Asn, key_info: Bytes
    ) -> Self {
        RouterKey { key_identifier, asn, key_info }
    }
}


//------------ Payload -------------------------------------------------------

/// All payload types supported by RTR and this crate.
///
/// There is at least one more payload type – BGPSEC router keys – that is not
/// currently supported by the crate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Payload {
    /// A route origin authorisation.
    Origin(RouteOrigin),

    /// A BGPsec router key.
    RouterKey(RouterKey),
}

impl Payload {
    /// Creates a new prefix origin payload.
    pub fn origin(prefix: MaxLenPrefix, asn: Asn) -> Self {
        Payload::Origin(RouteOrigin::new(prefix, asn))
    }

    /// Creates a new router key payload.
    pub fn router_key(
        key_identifier: KeyIdentifier, asn: Asn, key_info: Bytes
    ) -> Self {
        Payload::RouterKey(RouterKey::new(key_identifier, asn, key_info))
    }

    /// Returns the origin prefix if the value is of the origin variant.
    pub fn to_origin(&self) -> Option<RouteOrigin> {
        match *self {
            Payload::Origin(origin) => Some(origin),
            _ => None
        }
    }

    /// Returns the router key if the value is of the router key variant.
    pub fn as_router_key(&self) -> Option<&RouterKey> {
        match *self {
            Payload::RouterKey(ref key) => Some(key),
            _ => None
        }
    }
}


//--- From

impl From<RouteOrigin> for Payload {
    fn from(src: RouteOrigin) -> Self {
        Payload::Origin(src)
    }
}

impl From<RouterKey> for Payload {
    fn from(src: RouterKey) -> Self {
        Payload::RouterKey(src)
    }
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

