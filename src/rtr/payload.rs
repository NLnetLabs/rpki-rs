//! The data being transmitted via RTR.
//!
//! The types in here provide a more compact representation than the PDUs.
//! They also implement all the traits to use them as keys in collections to
//! be able to perform difference processing.
//!
//! The types are currently not very rich. They will receive more methods as
//! they become necessary. So don’t hesitate to ask for them!

use std::hash;
use std::cmp::Ordering;
use std::time::Duration;
use routecore::addr::MaxLenPrefix;
use routecore::asn::Asn;
use routecore::bgpsec::KeyIdentifier;
use super::pdu::{RouterKeyInfo, ProviderAsns};


//------------ RouteOrigin ---------------------------------------------------

/// A route origin authorization.
///
/// Values of this type authorize the autonomous system given in the `asn`
/// field to routes for the IP address prefixes given in the `prefix` field.
///
/// The type includes authorizations for both IPv4 and IPv6 prefixes which
/// are separate payload types in RTR.
#[derive(Clone, Copy, Debug)]
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


//--- PartialEq and Eq
impl PartialEq for RouteOrigin {
    fn eq(&self, other: &Self) -> bool {
        self.prefix.prefix() == other.prefix.prefix()
        && self.prefix.resolved_max_len() == other.prefix.resolved_max_len()
        && self.asn == other.asn
    }
}

impl Eq for RouteOrigin { }


//--- PartialOrd and Ord

impl PartialOrd for RouteOrigin {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RouteOrigin {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.prefix.prefix().cmp(&other.prefix.prefix()) {
            Ordering::Equal => { }
            other => return other
        }
        match self.prefix.resolved_max_len().cmp(
            &other.prefix.resolved_max_len()
        ) {
            Ordering::Equal => { }
            other => return other
        }
        self.asn.cmp(&other.asn)
    }
}


//--- Hash

impl hash::Hash for RouteOrigin {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.prefix.prefix().hash(state);
        self.prefix.resolved_max_len().hash(state);
        self.asn.hash(state);
    }
}


//------------ RouterKey -----------------------------------------------------

/// A BGPsec router key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouterKey {
    /// The subject key identifier of the router key.
    pub key_identifier: KeyIdentifier,

    /// The autonomous system authorized to use the key.
    pub asn: Asn,

    /// The actual key.
    pub key_info: RouterKeyInfo,
}

impl RouterKey {
    /// Creates a new value from the various components.
    pub fn new(
        key_identifier: KeyIdentifier, asn: Asn, key_info: RouterKeyInfo
    ) -> Self {
        RouterKey { key_identifier, asn, key_info }
    }
}


//------------ Aspa ----------------------------------------------------------

/// An ASPA ... unit.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Aspa {
    /// The customer ASN.
    pub customer: Asn,

    /// The address family this ASPA pertains to.
    pub afi: Afi,

    /// The provider ASNs.
    pub providers: ProviderAsns,
}

impl Aspa {
    /// Crates a new ASPA unt from its components.
    pub fn new(
        customer: Asn, afi: Afi, providers: ProviderAsns,
    ) -> Self {
        Self { customer, afi, providers }
    }
}


//------------ Payload -------------------------------------------------------

/// All payload types supported by RTR and this crate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Payload {
    /// A route origin authorisation.
    Origin(RouteOrigin),

    /// A BGPsec router key.
    RouterKey(RouterKey),

    /// An ASPA unit.
    Aspa(Aspa),
}

impl Payload {
    /// Creates a new prefix origin payload.
    pub fn origin(prefix: MaxLenPrefix, asn: Asn) -> Self {
        Payload::Origin(RouteOrigin::new(prefix, asn))
    }

    /// Creates a new router key payload.
    pub fn router_key(
        key_identifier: KeyIdentifier, asn: Asn, key_info: RouterKeyInfo
    ) -> Self {
        Payload::RouterKey(RouterKey::new(key_identifier, asn, key_info))
    }

    /// Creates a new ASPA unit.
    pub fn aspa(
        customer: Asn, afi: Afi, providers: ProviderAsns,
    ) -> Self {
        Payload::Aspa(Aspa::new(customer, afi, providers))
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

    /// Returns the ASPA unit if the value is of the ASPA variant.
    pub fn as_aspa(&self) -> Option<&Aspa> {
        match *self {
            Payload::Aspa(ref key) => Some(key),
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


//------------ Afi -----------------------------------------------------------

/// The RTR represenation of an address family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Afi(u8);

impl Afi {
    pub fn ipv4() -> Self {
        Self(0)
    }

    pub fn ipv6() -> Self {
        Self(1)
    }

    pub fn is_ipv4(self) -> bool {
        self.0 & 0x01 == 0
    }

    pub fn is_ipv6(self) -> bool {
        self.0 & 0x01 == 1
    }

    pub fn into_u8(self) -> u8 {
        self.0
    }

    pub fn from_u8(src: u8) -> Self {
        Self(src)
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

