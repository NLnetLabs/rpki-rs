//! Route Origin Authorizations.
//!
//! For details, see RFC 6482.

use std::mem;
use std::iter::FromIterator;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use bcder::{decode, encode};
use bcder::{Captured, Mode, OctetString, Oid, Tag, xerr};
use bcder::encode::{PrimitiveContent, Values};
use bytes::Bytes;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use crate::oid;
use crate::cert::{Cert, ResourceCert};
use crate::crypto::{Signer, SigningError};
use crate::resources::{
    Addr, AddressFamily, AsId, IpBlocks, IpResources, Prefix
};
use crate::sigobj::{SignedObject, SignedObjectBuilder};
use crate::tal::TalInfo;
use crate::x509::ValidationError;


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
        if signed.content_type().ne(&oid::ROUTE_ORIGIN_AUTHZ) {
            return Err(decode::Malformed.into())
        }
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

    /// Returns a value encoder for a reference to a ROA.
    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        self.signed.encode_ref()
    }

    /// Returns a DER encoded Captured for this ROA.
    pub fn to_captured(&self) -> Captured {
        self.encode_ref().to_captured(Mode::Der)
    }

    /// Returns a reference to the EE certificate of this ROA.
    pub fn cert(&self) -> &Cert {
        self.signed.cert()
    }
}


//--- Deserialize and Serialize

impl Serialize for Roa {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let bytes = self.to_captured().into_bytes();
        let b64 = base64::encode(&bytes);
        b64.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Roa {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        use serde::de;

        let string = String::deserialize(deserializer)?;
        let decoded = base64::decode(&string).map_err(de::Error::custom)?;
        let bytes = Bytes::from(decoded);
        Roa::decode(bytes, true).map_err(de::Error::custom)
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

    pub fn take_cert(&mut self) -> Option<ResourceCert> {
        self.status.take_cert()
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
            // version [0] EXPLICIT INTEGER DEFAULT 0
            cons.take_opt_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(0))?;
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
            let blocks = cert.v4_resources();
            if blocks.is_empty() {
                return Err(ValidationError)
            }
            for addr in self.v4_addrs.iter() {
                if !blocks.contains_roa(&addr) {
                    return Err(ValidationError)
                }
            }
        }
        if !self.v6_addrs.is_empty() {
            let blocks = cert.v6_resources();
            if blocks.is_empty() {
                return Err(ValidationError)
            }
            for addr in self.v6_addrs.iter() {
                if !blocks.contains_roa(&addr) {
                    return Err(ValidationError)
                }
            }
        }
        self.status = RoaStatus::Valid { cert };
        Ok(())
    }

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            // version is DEFAULT
            self.as_id.encode(),
            encode::sequence((
                self.v4_addrs.encode_ref_family([0x00, 0x01]),
                self.v6_addrs.encode_ref_family([0x00, 0x02]),
            ))
        ))
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

    fn encode_ref_family<'a>(
        &'a self,
        family: [u8; 2]
    ) -> Option<impl encode::Values + 'a> {
        if self.0.is_empty() {
            None
        }
        else {
            Some(encode::sequence((
                OctetString::encode_slice(family),
                &self.0
            )))
        }
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

    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    pub fn range(&self) -> (Addr, Addr) {
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

    pub fn prefix(&self) -> Prefix {
        self.addr.prefix
    }

    pub fn is_v4(&self) -> bool {
        self.v4
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
#[allow(clippy::large_enum_variant)]
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
    pub fn take_cert(&mut self) -> Option<ResourceCert> {
        let res = mem::replace(self, RoaStatus::Unknown);
        match res {
            RoaStatus::Valid { cert, .. } => Some(cert),
            RoaStatus::Invalid { .. } => {
                *self = RoaStatus::Invalid { };
                None
            }
            RoaStatus::Unknown => None
        }
    }

    pub fn tal(&self) -> Option<&Arc<TalInfo>> {
        match *self {
            RoaStatus::Valid { ref cert, .. } => Some(cert.tal()),
            _ => None
        }
    }
}


//------------ RoaBuilder ----------------------------------------------------

pub struct RoaBuilder {
    as_id: AsId,
    v4: RoaIpAddressesBuilder,
    v6: RoaIpAddressesBuilder,
}

impl RoaBuilder {
    pub fn new(as_id: AsId) -> Self {
        Self::with_addresses(
            as_id,
            RoaIpAddressesBuilder::new(),
            RoaIpAddressesBuilder::new(),
        )
    }

    pub fn with_addresses(
        as_id: AsId,
        v4: RoaIpAddressesBuilder,
        v6: RoaIpAddressesBuilder
    ) -> Self {
        Self { as_id, v4, v6 }
    }

    pub fn as_id(&self) -> AsId {
        self.as_id
    }

    pub fn set_as_id(&mut self, as_id: AsId) {
        self.as_id = as_id
    }

    pub fn v4(&self) -> &RoaIpAddressesBuilder {
        &self.v4
    }

    pub fn v4_mut(&mut self) -> &mut RoaIpAddressesBuilder {
        &mut self.v4
    }

    pub fn v6(&self) -> &RoaIpAddressesBuilder {
        &self.v6
    }

    pub fn v6_mut(&mut self) -> &mut RoaIpAddressesBuilder {
        &mut self.v6
    }
    
    pub fn push_addr(
        &mut self, addr: IpAddr, len: u8, max_len: Option<u8>
    ) {
        match addr {
            IpAddr::V4(addr) => self.push_v4_addr(addr, len, max_len),
            IpAddr::V6(addr) => self.push_v6_addr(addr, len, max_len)
        }
    }

    pub fn push_v4(&mut self, addr: RoaIpAddress) {
        self.v4_mut().push(addr)
    }

    pub fn push_v4_addr(
        &mut self, addr: Ipv4Addr, len: u8, max_len: Option<u8>
    ) {
        self.v4_mut().push_addr(IpAddr::V4(addr), len, max_len)
    }

    pub fn extend_v4_from_slice(&mut self, addrs: &[RoaIpAddress]) {
        self.v4_mut().extend_from_slice(addrs)
    }

    pub fn push_v6(&mut self, addr: RoaIpAddress) {
        self.v6_mut().push(addr)
    }

    pub fn push_v6_addr(
        &mut self, addr: Ipv6Addr, len: u8, max_len: Option<u8>
    ) {
        self.v6_mut().push_addr(IpAddr::V6(addr), len, max_len)
    }

    pub fn extend_v6_from_slice(&mut self, addrs: &[RoaIpAddress]) {
        self.v6_mut().extend_from_slice(addrs)
    }

    pub fn to_attestation(&self) -> RouteOriginAttestation {
        RouteOriginAttestation {
            as_id: self.as_id,
            v4_addrs: self.v4.to_addresses(),
            v6_addrs: self.v6.to_addresses(),
            status: RoaStatus::Unknown,
        }
    }

    /// Finalizes the builder into a ROA.
    ///
    /// # Panic
    ///
    /// This method will panic if both the IPv4 and IPv6 addresses are empty
    /// as that is not allowed and would lead to a malformed ROA.
    pub fn finalize<S: Signer>(
        self,
        mut sigobj: SignedObjectBuilder,
        signer: &S,
        issuer_key: &S::KeyId,
    ) -> Result<Roa, SigningError<S::Error>> {
        let content = self.to_attestation();
        let v4 = self.v4.to_resources();
        let v6 = self.v6.to_resources();
        // There must be some resources in order to make a valid ROA.
        assert!(v4.is_present() || v6.is_present());
        sigobj.set_v4_resources(v4);
        sigobj.set_v6_resources(v6);
        let signed = sigobj.finalize(
            Oid(oid::ROUTE_ORIGIN_AUTHZ.0.into()),
            content.encode_ref().to_captured(Mode::Der).into_bytes(),
            signer,
            issuer_key,
        )?;
        Ok(Roa { signed, content })
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

    pub fn to_addresses(&self) -> RoaIpAddresses {
        RoaIpAddresses(
            if self.addrs.is_empty() {
                Captured::empty(Mode::Der)
            }
            else {
                Captured::from_values(Mode::Der, self.encode_ref())
            }
       )
    }

    pub fn to_resources(&self) -> IpResources {
        IpResources::blocks(IpBlocks::from_iter(
            self.addrs.iter().map(|addr| addr.prefix.into())
        ))
    }

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence(
            encode::slice(self.addrs.as_slice(), |v: &RoaIpAddress| v.encode())
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


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn decode_roa() {
        assert!(
            Roa::decode(
                include_bytes!("../test-data/example-ripe.roa").as_ref(),
                false
            ).is_ok()
        )
    }
}

#[cfg(all(test, feature="softkeys"))]
mod signer_test {
    use std::str::FromStr;
    use bcder::encode::Values;
    use crate::cert::{KeyUsage, Overclaim, TbsCert};
    use crate::crypto::{PublicKeyFormat, Signer};
    use crate::crypto::softsigner::OpenSslSigner;
    use crate::resources::{AsId, Prefix};
    use crate::uri;
    use crate::x509::Validity;
    use super::*;

    fn make_roa() -> Roa {
        let mut signer = OpenSslSigner::new();
        let key = signer.create_key(PublicKeyFormat::default()).unwrap();
        let pubkey = signer.get_key_info(&key).unwrap();
        let uri = uri::Rsync::from_str("rsync://example.com/m/p").unwrap();

        let mut cert = TbsCert::new(
            12u64.into(), pubkey.to_subject_name(),
            Validity::from_secs(86400), None, pubkey, KeyUsage::Ca,
            Overclaim::Trim
        );
        cert.set_basic_ca(Some(true));
        cert.set_ca_repository(Some(uri.clone()));
        cert.set_rpki_manifest(Some(uri.clone()));
        cert.build_v4_resource_blocks(|b| b.push(Prefix::new(0, 0)));
        cert.build_v6_resource_blocks(|b| b.push(Prefix::new(0, 0)));
        cert.build_as_resource_blocks(|b| b.push((AsId::MIN, AsId::MAX)));
        let cert = cert.into_cert(&signer, &key).unwrap();

        let mut roa = RoaBuilder::new(64496.into());
        roa.push_v4_addr(Ipv4Addr::new(192, 0, 2, 0), 24, None);

        let roa = roa.finalize(
            SignedObjectBuilder::new(
                12u64.into(), Validity::from_secs(86400), uri.clone(),
                uri.clone(), uri.clone()
            ),
            &signer, &key
        ).unwrap();
        let roa = roa.encode_ref().to_captured(Mode::Der);

        let roa = Roa::decode(roa.as_slice(), true).unwrap();
        let cert = cert.validate_ta(
            TalInfo::from_name("foo".into()).into_arc(), true
        ).unwrap();
        roa.clone().process(&cert, true, |_| Ok(())).unwrap();

        roa
    }

    #[test]
    fn encode_roa() {
        make_roa();
    }
        

    #[test]
    fn serde_roa() {
        let roa = make_roa();

        let serialized = serde_json::to_string(&roa).unwrap();
        let deser_roa: Roa = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            roa.to_captured().into_bytes(),
            deser_roa.to_captured().into_bytes()
        )
    }
}


//============ Specification Documentation ===================================

/// ROA Specification.
///
/// This is a documentation-only module. It summarizes the specification for
/// ROAs, how they are parsed and constructed.
///
/// A Route Origin Authorization (ROA) is a [signed object] that assigns a
/// number of route prefixes to an AS number. It is specified in [RFC 6482].
///
/// The content of a ROA signed object is of type `RouteOriginAttestation`
/// which is defined as follows:
///
/// ```txt
/// RouteOriginAttestation  ::= SEQUENCE {
///     version                 [0] INTEGER DEFAULT 0,
///     asID                    ASID,
///     ipAddrBlocks            SEQUENCE (SIZE(1..MAX)) OF ROAIPAddressFamily
/// }
///
/// ASID                    ::= INTEGER
///
/// ROAIPAddressFamily      ::= SEQUENCE {
///     addressFamily           OCTET STRING (SIZE (2..3)),
///     addresses               SEQUENCE (SIZE (1..MAX)) OF ROAIPAddress
/// }
///
/// ROAIPAddress            ::= SEQUENCE {
///     address                 IPAddress,
///     maxLength               INTEGER OPTIONAL
/// }
///
/// IPAddress               ::= BIT STRING
/// ```
///
/// The _version_ must be 0. The _addressFamily_ is identical to the field
/// used in RPKI certificate IP resources, i.e, `"\0\x01"` for IPv4 and
/// `"\0\x02"` for IPv6.
///
/// [signed object]: ../../sigobj/spec/index.html
/// [RFC 6482]: https://tools.ietf.org/html/rfc6482
pub mod spec { }

