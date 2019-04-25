//! Handling of IP and AS resources.
//!
//! The types in this module implement the certificate extensions defined in
//! [RFC 3779] for including IP address and autonomous system resources in
//! certificates in the restricted form specified by [RFC 6487] for use in
//! RPKI.
//!
//! There are two such resources: [`IpResources`] implements the IP Address
//! Delegation Extension and [`AsResources`] implements the Autonomous System
//! Identifier Delegation Extension.
//!
//! [`AsResources`]: struct.AsResources.html
//! [`IpResources`]: struct.IpResources.html
//! [RFC 3779]: https://tools.ietf.org/html/rfc3779
//! [RFC 6487]: https://tools.ietf.org/html/rfc6487

pub use self::asres::{
    AsBlocks, AsBlocksBuilder, AsId, AsResources, AsResourcesBuilder
};
pub use self::choice::ResourcesChoice;
pub use self::ipres::{
    Addr, AddressFamily, IpBlocks, IpBlocksBuilder, IpBlocksForFamily,
    IpResources, IpResourcesBuilder, Ipv4Resources, Ipv6Resources, Prefix
};

mod asres;
mod chain;
mod choice;
mod ipres;
