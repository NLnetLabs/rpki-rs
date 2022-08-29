use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use routecore::asn::Asn;

use crate::repository::resources::{AsResources, IpResources};
use crate::repository::Cert;
use crate::repository::{
    resources::{AsBlock, AsBlocks, AsBlocksBuilder, Ipv4Blocks, Ipv6Blocks},
    roa::RoaIpAddress,
};

//------------ ResourceSet ---------------------------------------------------

/// A set of ASN, IPv4 and IPv6 resources.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct ResourceSet {
    asn: AsBlocks,

    #[cfg_attr(feature = "serde", serde(alias = "v4"))]
    ipv4: Ipv4Blocks,

    #[cfg_attr(feature = "serde", serde(alias = "v6"))]
    ipv6: Ipv6Blocks,
}

impl ResourceSet {
    pub fn new(asn: AsBlocks, ipv4: Ipv4Blocks, ipv6: Ipv6Blocks) -> Self {
        ResourceSet { asn, ipv4, ipv6 }
    }

    pub fn from_strs(asn: &str, ipv4: &str, ipv6: &str) -> Result<Self, FromStrError> {
        let asn = AsBlocks::from_str(asn).map_err(FromStrError::asn)?;
        let ipv4 = Ipv4Blocks::from_str(ipv4).map_err(FromStrError::ipv4)?;
        let ipv6 = Ipv6Blocks::from_str(ipv6).map_err(FromStrError::ipv6)?;

        Ok(ResourceSet { asn, ipv4, ipv6 })
    }

    pub fn empty() -> ResourceSet {
        Self::default()
    }

    pub fn all() -> ResourceSet {
        ResourceSet {
            asn: AsBlocks::all(),
            ipv4: Ipv4Blocks::all(),
            ipv6: Ipv6Blocks::all(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.asn.is_empty() && self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    pub fn set_asn(&mut self, asn: AsBlocks) {
        self.asn = asn;
    }

    pub fn set_ipv4(&mut self, ipv4: Ipv4Blocks) {
        self.ipv4 = ipv4;
    }

    pub fn set_ipv6(&mut self, ipv6: Ipv6Blocks) {
        self.ipv6 = ipv6;
    }

    pub fn asn(&self) -> &AsBlocks {
        &self.asn
    }

    pub fn to_as_resources(&self) -> AsResources {
        AsResources::blocks(self.asn.clone())
    }

    pub fn ipv4(&self) -> &Ipv4Blocks {
        &self.ipv4
    }

    pub fn to_ip_resources_v4(&self) -> IpResources {
        self.ipv4.to_ip_resources()
    }
    
    pub fn ipv6(&self) -> &Ipv6Blocks {
        &self.ipv6
    }

    pub fn to_ip_resources_v6(&self) -> IpResources {
        self.ipv6.to_ip_resources()
    }

    /// Returns None if there are no ASNs in this ResourceSet.
    pub fn asn_opt(&self) -> Option<&AsBlocks> {
        if self.asn.is_empty() {
            None
        } else {
            Some(&self.asn)
        }
    }

    /// Returns None if there is no IPv4 in this ResourceSet.
    pub fn ipv4_opt(&self) -> Option<&Ipv4Blocks> {
        if self.ipv4.is_empty() {
            None
        } else {
            Some(&self.ipv4)
        }
    }

    /// Returns None if there is no IPv6 in this ResourceSet.
    pub fn ipv6_opt(&self) -> Option<&Ipv6Blocks> {
        if self.ipv6.is_empty() {
            None
        } else {
            Some(&self.ipv6)
        }
    }

    /// Check of the other set is contained by this set. If this set
    /// contains inherited resources, then any explicit corresponding
    /// resources in the other set will be considered to fall outside of
    /// this set.
    pub fn contains(&self, other: &ResourceSet) -> bool {
        self.asn.contains(other.asn())
            && self.ipv4.contains(&other.ipv4)
            && self.ipv6.contains(&other.ipv6)
    }

    /// Check if the resource set contains the given Asn
    pub fn contains_asn(&self, asn: Asn) -> bool {
        let mut blocks = AsBlocksBuilder::new();
        blocks.push(AsBlock::Id(asn));
        let blocks = blocks.finalize();
        self.asn.contains(&blocks)
    }

    /// Check if the resource set contains the given ROA address
    pub fn contains_roa_address(&self, roa_address: &RoaIpAddress) -> bool {
        self.ipv4.contains_roa(roa_address) || self.ipv6.contains_roa(roa_address)
    }

    /// Returns the union of this ResourceSet and the other. I.e. a new
    /// ResourceSet containing all resources found in one or both.
    pub fn union(&self, other: &ResourceSet) -> Self {
        let asn = self.asn.union(&other.asn);
        let ipv4 = self.ipv4.union(&other.ipv4).into();
        let ipv6 = self.ipv6.union(&other.ipv6).into();
        ResourceSet { asn, ipv4, ipv6 }
    }

    /// Returns the intersection of this ResourceSet and the other. I.e. a new
    /// ResourceSet containing all resources found in both sets.
    pub fn intersection(&self, other: &ResourceSet) -> Self {
        let asn = self.asn.intersection(&other.asn);
        let ipv4 = self.ipv4.intersection(&other.ipv4).into();
        let ipv6 = self.ipv6.intersection(&other.ipv6).into();
        ResourceSet { asn, ipv4, ipv6 }
    }

    /// Returns the difference from another ResourceSet towards `self`.
    pub fn difference(&self, other: &ResourceSet) -> ResourceDiff {
        let added = ResourceSet {
            asn: self.asn.difference(&other.asn),
            ipv4: self.ipv4.difference(&other.ipv4).into(),
            ipv6: self.ipv6.difference(&other.ipv6).into(),
        };
        let removed = ResourceSet {
            asn: other.asn.difference(&self.asn),
            ipv4: other.ipv4.difference(&self.ipv4).into(),
            ipv6: other.ipv6.difference(&self.ipv6).into(),
        };
        ResourceDiff { added, removed }
    }
}

impl Default for ResourceSet {
    fn default() -> Self {
        ResourceSet {
            asn: AsBlocks::empty(),
            ipv4: Ipv4Blocks::empty(),
            ipv6: Ipv6Blocks::empty(),
        }
    }
}

//--- Display

impl fmt::Display for ResourceSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "asn: '{}', ipv4: '{}', ipv6: '{}'",
            self.asn,
            self.ipv4,
            self.ipv6
        )
    }
}

impl TryFrom<&Cert> for ResourceSet {
    type Error = InheritError;

    fn try_from(cert: &Cert) -> Result<Self, Self::Error> {
        let asn = match cert.as_resources().to_blocks() {
            Ok(as_blocks) => as_blocks,
            Err(_) => return Err(InheritError),
        };

        let ipv4 = match cert.v4_resources().to_blocks() {
            Ok(blocks) => blocks,
            Err(_) => return Err(InheritError),
        }
        .into();

        let ipv6 = match cert.v6_resources().to_blocks() {
            Ok(blocks) => blocks,
            Err(_) => return Err(InheritError),
        }
        .into();

        Ok(ResourceSet { asn, ipv4, ipv6 })
    }
}


//------------ ResourceDiff --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct ResourceDiff {
    added: ResourceSet,
    removed: ResourceSet,
}

impl ResourceDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

impl fmt::Display for ResourceDiff {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_empty() {
            write!(f, "<no changes in resources>")?;
        }
        if !self.added.is_empty() {
            write!(f, "Added:")?;
            if !self.added.asn.is_empty() {
                write!(f, " asn: {}", self.added.asn)?;
            }
            if !self.added.ipv4.is_empty() {
                write!(f, " ipv4: {}", self.added.ipv4())?;
            }
            if !self.added.ipv6.is_empty() {
                write!(f, " ipv6: {}", self.added.ipv6())?;
            }

            if !self.removed.is_empty() {
                write!(f, " ")?;
            }
        }
        if !self.removed.is_empty() {
            write!(f, "Removed:")?;

            if !self.removed.asn.is_empty() {
                write!(f, " asn: {}", self.removed.asn)?;
            }
            if !self.removed.ipv4.is_empty() {
                write!(f, " ipv4: {}", self.removed.ipv4())?;
            }
            if !self.removed.ipv6.is_empty() {
                write!(f, " ipv6: {}", self.removed.ipv6())?;
            }
        }

        Ok(())
    }
}

//------------ InheritError --------------------------------------------------

#[derive(Clone, Debug)]
pub struct InheritError;

impl fmt::Display for InheritError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cannot determine resources for certificate using inherit")
    }
}

impl std::error::Error for InheritError {}


//------------ FromStrError --------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FromStrError {
    Asn(String),
    Ipv4(String),
    Ipv6(String)
}

impl FromStrError {
    fn asn(e: super::asres::FromStrError) -> Self {
        FromStrError::Asn(e.to_string())
    }
    
    fn ipv4(e: super::ipres::FromStrError) -> Self {
        FromStrError::Ipv4(e.to_string())
    }
    
    fn ipv6(e: super::ipres::FromStrError) -> Self {
        FromStrError::Ipv6(e.to_string())
    }
}

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FromStrError::Asn(e)
                => write!(f, "cannot parse ASN resources: {}", e),
            FromStrError::Ipv4(e)
                => write!(f, "cannot parse IPv4 resources: {}", e),
            FromStrError::Ipv6(e)
                => write!(f, "cannot parse IPv6 resources: {}", e),
        }
    }
}

impl std::error::Error for FromStrError {}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_resource_set_intersection() {
        let child_resources = ResourceSet::from_strs("AS65000", "10.0.0.0/8", "fd00::/8").unwrap();

        let parent_resources = ResourceSet::all();

        let intersection = parent_resources.intersection(&child_resources);

        assert_eq!(intersection, child_resources);
    }

    #[test]
    fn resource_set_difference() {
        let set1_asns = "AS65000-AS65003, AS65005";
        let set2_asns = "AS65000, AS65003, AS65005";
        let asn_added = "AS65001-AS65002";

        let set1_ipv4s = "10.0.0.0-10.4.5.6, 192.168.0.0";
        let set2_ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv4_removed = "10.4.5.7-10.255.255.255";

        let set1_ipv6s = "::1, 2001:db8::/32";
        let set2_ipv6s = "::1, 2001:db8::/56";
        let ipv6_added = "2001:db8:0:100::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";

        let set1 = ResourceSet::from_strs(set1_asns, set1_ipv4s, set1_ipv6s).unwrap();
        let set2 = ResourceSet::from_strs(set2_asns, set2_ipv4s, set2_ipv6s).unwrap();

        let diff = set1.difference(&set2);

        let expected_diff = ResourceDiff {
            added: ResourceSet::from_strs(asn_added, "", ipv6_added).unwrap(),
            removed: ResourceSet::from_strs("", ipv4_removed, "").unwrap(),
        };

        assert!(!diff.is_empty());
        assert_eq!(expected_diff, diff);
    }

    #[test]
    fn resource_set_eq() {
        let asns = "AS65000-AS65003, AS65005";
        let ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv6s = "::1, 2001:db8::/32";

        let resource_set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();

        let asns_2 = "AS65000-AS65003";
        let ipv4s_2 = "192.168.0.0";
        let ipv6s_2 = "2001:db8::/32";

        let resource_set_asn_differs = ResourceSet::from_strs(asns_2, ipv4s, ipv6s).unwrap();
        let resource_set_v4_differs = ResourceSet::from_strs(asns, ipv4s_2, ipv6s).unwrap();
        let resource_set_v6_differs = ResourceSet::from_strs(asns, ipv4s, ipv6s_2).unwrap();
        let resource_set_2 = ResourceSet::from_strs(asns_2, ipv4s_2, ipv6s_2).unwrap();

        assert_ne!(resource_set, resource_set_asn_differs);
        assert_ne!(resource_set, resource_set_v4_differs);
        assert_ne!(resource_set, resource_set_v6_differs);
        assert_ne!(resource_set, resource_set_2);

        let default_set = ResourceSet::default();
        let certified = ResourceSet::from_strs(
            "",
            "10.0.0.0/16, 192.168.0.0/16",
            "2001:db8::/32, 2000:db8::/32",
        )
        .unwrap();
        assert_ne!(default_set, certified);
        assert_ne!(resource_set, certified);
    }

    #[test]
    fn resource_set_equivalent() {
        // Data may be unordered on input, or not use ranges etc. But
        // if the resources are the same then we should get equal
        // sets in the end.

        let asns_1 = "AS65000-AS65003, AS65005";
        let ipv4_1 = "10.0.0.0/8, 192.168.0.0";
        let ipv6_1 = "::1, 2001:db8::/32";

        let asns_2 = "AS65005, AS65001-AS65003, AS65000";
        let ipv4_2 = "192.168.0.0, 10.0.0.0/8, ";
        let ipv6_2 = "2001:db8::/32, ::1";

        let set_1 = ResourceSet::from_strs(asns_1, ipv4_1, ipv6_1).unwrap();
        let set_2 = ResourceSet::from_strs(asns_2, ipv4_2, ipv6_2).unwrap();

        assert_eq!(set_1, set_2);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize_deserialize_resource_set() {
        let asns = "AS65000-AS65003, AS65005";
        let ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv6s = "::1, 2001:db8::/32";

        let set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();

        let json = serde_json::to_string(&set).unwrap();
        let deser_set = serde_json::from_str(&json).unwrap();

        assert_eq!(set, deser_set);
    }
}
