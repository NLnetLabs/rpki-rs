//! Route Origin Authorizations.
//!
//! For details, see RFC 6482.

use std::net::IpAddr;
use std::sync::Arc;
use bcder::{decode, encode};
use bcder::{Captured, Mode, Tag};
use bcder::decode::Source;
use bcder::encode::PrimitiveContent;
use super::asres::AsId;
use super::cert::{Cert, ResourceCert};
use super::ipres::{AddressFamily, Prefix};
use super::sigobj::SignedObject;
use super::tal::TalInfo;
use super::x509::ValidationError;


//------------ Roa -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Roa {
    signed: SignedObject,
    content: RouteOriginAttestation,
}

impl Roa {
    pub fn decode<S: decode::Source>(
        source: S,
        strict: bool
    ) -> Result<Self, S::Err> {
        let signed = SignedObject::decode(source, strict)?;
        let content = signed.decode_content(|cons| {
            RouteOriginAttestation::take_from(cons)
        })?;
        Ok(Roa { signed, content })
    }

    pub fn process<F>(
        mut self,
        issuer: &ResourceCert,
        strict: bool,
        check_crl: F
    ) -> Result<RouteOriginAttestation, ValidationError>
    where F: FnOnce(&Cert) -> Result<(), ValidationError> {
        let cert = self.signed.validate(issuer, strict)?;
        check_crl(cert.as_ref())?;
        self.content.validate(cert)?;
        Ok(self.content)
    }
}


//------------ RouteOriginAttestation ----------------------------------------

#[derive(Clone, Debug)]
pub struct RouteOriginAttestation {
    as_id: AsId,
    v4_addrs: RoaIpAddresses,
    v6_addrs: RoaIpAddresses,
    status: RoaStatus,
}

impl RouteOriginAttestation {
    pub fn as_id(&self) -> AsId {
        self.as_id
    }

    pub fn v4_addrs(&self) -> &RoaIpAddresses {
        &self.v4_addrs
    }

    pub fn v6_addrs(&self) -> &RoaIpAddresses {
        &self.v6_addrs
    }

    pub fn status(&self) -> &RoaStatus {
        &self.status
    }

    pub fn iter<'a>(
        &'a self
    ) -> impl Iterator<Item=FriendlyRoaIpAddress> + 'a {
        self.v4_addrs.iter().map(|addr| FriendlyRoaIpAddress::new(addr, true))
            .chain(
                self.v6_addrs.iter()
                    .map(|addr| FriendlyRoaIpAddress::new(addr, false))
            )
    }
}

impl RouteOriginAttestation {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.take_opt_primitive_if(Tag::CTX_0, |prim| {
                if prim.take_u8()? != 0 {
                    xerr!(Err(decode::Malformed.into()))
                }
                else {
                    Ok(())
                }
            })?;
            let as_id = AsId::take_from(cons)?;
            let mut v4 = None;
            let mut v6 = None;
            cons.take_sequence(|cons| {
                while let Some(()) = cons.take_opt_sequence(|cons| {
                    match AddressFamily::take_from(cons)? {
                        AddressFamily::Ipv4 => {
                            if v4.is_some() {
                                xerr!(return Err(decode::Malformed.into()));
                            }
                            v4 = Some(RoaIpAddresses::take_from(cons)?);
                        }
                        AddressFamily::Ipv6 => {
                            if v6.is_some() {
                                xerr!(return Err(decode::Malformed.into()));
                            }
                            v6 = Some(RoaIpAddresses::take_from(cons)?);
                        }
                    }
                    Ok(())
                })? { }
                Ok(())
            })?;
            Ok(RouteOriginAttestation {
                as_id,
                v4_addrs: match v4 {
                    Some(addrs) => addrs,
                    None => RoaIpAddresses(Captured::empty(Mode::Der))
                },
                v6_addrs: match v6 {
                    Some(addrs) => addrs,
                    None => RoaIpAddresses(Captured::empty(Mode::Der))
                },
                status: RoaStatus::Unknown,
            })
        })
    }

    fn validate(
        &mut self,
        cert: ResourceCert
    ) -> Result<(), ValidationError> {
        if !self.v4_addrs.is_empty() {
            let blocks = match cert.ip_resources().v4() {
                Some(blocks) => blocks,
                None => return Err(ValidationError)
            };
            for addr in self.v4_addrs.iter() {
                if !blocks.contain(&addr) {
                    return Err(ValidationError)
                }
            }
        }
        if !self.v6_addrs.is_empty() {
            let blocks = match cert.ip_resources().v6() {
                Some(blocks) => blocks,
                None => return Err(ValidationError)
            };
            for addr in self.v6_addrs.iter() {
                if !blocks.contain(&addr) {
                    return Err(ValidationError)
                }
            }
        }
        self.status = RoaStatus::Valid { cert };
        Ok(())
    }
}


//------------ RoaIpAddresses ------------------------------------------------

#[derive(Clone, Debug)]
pub struct RoaIpAddresses(Captured);

impl RoaIpAddresses {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.capture(|cons| {
                while let Some(()) = RoaIpAddress::skip_opt_in(cons)? { }
                Ok(())
            })
        }).map(RoaIpAddresses)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> RoaIpAddressIter {
        RoaIpAddressIter(self.0.as_ref())
    }
}


//------------ RoaIpAddressIter ----------------------------------------------

#[derive(Clone, Debug)]
pub struct RoaIpAddressIter<'a>(&'a [u8]);

impl<'a> Iterator for RoaIpAddressIter<'a> {
    type Item = RoaIpAddress;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        }
        else {
            Mode::Der.decode(&mut self.0, |cons| {
                RoaIpAddress::take_opt_from(cons)
            }).unwrap()
        }
    }
}


//------------ RoaIpAddressesBuilder -----------------------------------------

#[derive(Clone, Debug)]
pub struct RoaIpAddressesBuilder {
    addrs: Vec<RoaIpAddress>,
}

impl RoaIpAddressesBuilder {
    pub fn new() -> Self {
        RoaIpAddressesBuilder {
            addrs: Vec::new()
        }
    }

    pub fn push(&mut self, addr: RoaIpAddress) {
        self.addrs.push(addr)
    }

    pub fn push_addr(&mut self, addr: IpAddr, len: u8, max_len: Option<u8>) {
        self.push(RoaIpAddress::new_addr(addr, len, max_len))
    }

    pub fn extend_from_slice(&mut self, addrs: &[RoaIpAddress]) {
        self.addrs.extend_from_slice(addrs)
    }

    pub fn finalize(self) -> RoaIpAddresses {
        RoaIpAddresses(Captured::from_values(Mode::Der, self.encode()))
    }

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence(
            encode::Iter::new(self.addrs.iter().map(|v| v.encode()))
        )
    }
}

impl Default for RoaIpAddressesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Extend<RoaIpAddress> for RoaIpAddressesBuilder {
    fn extend<T>(&mut self, iter: T)
    where T: IntoIterator<Item=RoaIpAddress> {
        self.addrs.extend(iter)
    }
}


//------------ RoaIpAddress --------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RoaIpAddress {
    prefix: Prefix,
    max_length: Option<u8>
}

impl RoaIpAddress {
    pub fn new(prefix: Prefix, max_length: Option<u8>) -> Self {
        RoaIpAddress { prefix, max_length }
    }

    pub fn new_addr(addr: IpAddr, len: u8, max_len: Option<u8>) -> Self {
        RoaIpAddress::new(Prefix::new(addr, len), max_len)
    }

    pub fn range(&self) -> (u128, u128) {
        self.prefix.range()
    }
}

impl RoaIpAddress {
    // Section 3 of RFC 6482 defines  ROAIPAddress as
    //
    // ```txt
    // ROAIPAddress ::= SEQUENCE {
    //    address       IPAddress,
    //    maxLength     INTEGER OPTIONAL }
    //
    // IPAddress    ::= BIT STRING
    // ```
    //
    // The address is the same as in section 2.1.1 of RFC 3779, that is, it
    // is a bit string with all the bits of the prefix.

    fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_sequence(|cons| {
            Ok(RoaIpAddress {
                prefix: Prefix::take_from(cons)?,
                max_length: cons.take_opt_u8()?,
            })
        })
    }

    fn skip_opt_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<()>, S::Err> {
        Self::take_opt_from(cons).map(|res| res.map(|_| ()))
    }

    fn encode(&self) -> impl encode::Values {
        encode::sequence((
            self.prefix.encode(),
            self.max_length.map(|v| v.encode())
        ))
    }
}


//------------ FriendlyRoaIpAddress ------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FriendlyRoaIpAddress {
    addr: RoaIpAddress,
    v4: bool
}

impl FriendlyRoaIpAddress {
    fn new(addr: RoaIpAddress, v4: bool) -> Self {
        FriendlyRoaIpAddress { addr, v4 }
    }

    pub fn address(&self) -> IpAddr {
        if self.v4 {
            self.addr.prefix.to_v4().into()
        }
        else {
            self.addr.prefix.to_v6().into()
        }
    }

    pub fn address_length(&self) -> u8 {
        self.addr.prefix.addr_len()
    }

    pub fn max_length(&self) -> u8 {
        self.addr.max_length.unwrap_or_else(||
            self.addr.prefix.addr_len()
        )
    }
}


//------------ RoaStatus -----------------------------------------------------

#[derive(Clone, Debug)]
pub enum RoaStatus {
    Valid {
        cert: ResourceCert,
    },
    Invalid {
        // XXX Add information for why this is invalid.
    },
    Unknown
}

impl RoaStatus {
    pub fn tal(&self) -> Option<&Arc<TalInfo>> {
        match *self {
            RoaStatus::Valid { ref cert, .. } => Some(cert.tal()),
            _ => None
        }
    }
}

