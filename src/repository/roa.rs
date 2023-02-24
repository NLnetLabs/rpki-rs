//! Route Origin Authorizations.
//!
//! For details, see RFC 6482.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use bcder::{decode, encode};
use bcder::{Captured, Mode, OctetString, Oid, Tag};
use bcder::decode::{
    ContentError, DecodeError, IntoSource, SliceSource, Source,
};
use bcder::encode::{PrimitiveContent, Values};
use crate::oid;
use crate::crypto::{Signer, SigningError};
use super::cert::{Cert, ResourceCert};
use super::error::{ValidationError, VerificationError};
use super::resources::{Addr, AddressFamily, Asn, IpResources, Prefix};
use super::sigobj::{SignedObject, SignedObjectBuilder};


//------------ Roa -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Roa {
    pub signed: SignedObject,
    pub content: RouteOriginAttestation,
}

impl Roa {
    pub fn decode<S: IntoSource>(
        source: S,
        strict: bool
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        let signed = SignedObject::decode_if_type(
            source, &oid::ROUTE_ORIGIN_AUTHZ, strict,
        )?;
        let content = signed.decode_content(|cons| {
            RouteOriginAttestation::take_from(cons)
        }).map_err(DecodeError::convert)?;
        Ok(Roa { signed, content })
    }

    pub fn process<F>(
        mut self,
        issuer: &ResourceCert,
        strict: bool,
        check_crl: F
    ) -> Result<(ResourceCert, RouteOriginAttestation), ValidationError>
    where F: FnOnce(&Cert) -> Result<(), ValidationError> {
        let cert = self.signed.validate(issuer, strict)?;
        check_crl(cert.as_ref())?;
        self.content.verify(&cert)?;
        Ok((cert, self.content))
    }

    /// Returns a value encoder for a reference to a ROA.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
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

#[cfg(feature = "serde")]
impl serde::Serialize for Roa {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let bytes = self.to_captured().into_bytes();
        let b64 = base64::encode(&bytes);
        b64.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Roa {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        let string = String::deserialize(deserializer)?;
        let decoded = base64::decode(string).map_err(de::Error::custom)?;
        let bytes = bytes::Bytes::from(decoded);
        Roa::decode(bytes, true).map_err(de::Error::custom)
    }
}


//------------ RouteOriginAttestation ----------------------------------------

#[derive(Clone, Debug)]
pub struct RouteOriginAttestation {
    as_id: Asn,
    v4_addrs: RoaIpAddresses,
    v6_addrs: RoaIpAddresses,
}

impl RouteOriginAttestation {
    pub fn as_id(&self) -> Asn {
        self.as_id
    }

    pub fn v4_addrs(&self) -> &RoaIpAddresses {
        &self.v4_addrs
    }

    pub fn v6_addrs(&self) -> &RoaIpAddresses {
        &self.v6_addrs
    }

    pub fn iter(
        &self
    ) -> impl Iterator<Item = FriendlyRoaIpAddress> + '_ {
        self.v4_addrs.iter().map(|addr| FriendlyRoaIpAddress::new(addr, true))
            .chain(
                self.v6_addrs.iter()
                    .map(|addr| FriendlyRoaIpAddress::new(addr, false))
            )
    }

    /// Returns an iterator over the route origins contained in the ROA.
    #[cfg(feature = "rtr")]
    pub fn iter_origins(
        &self
    ) -> impl Iterator<Item = crate::rtr::payload::RouteOrigin> + '_ {
        use routecore::addr::{MaxLenPrefix, Prefix as PayloadPrefix};
        use crate::rtr::payload::RouteOrigin;

        self.v4_addrs.iter().filter_map(move |addr| {
            PayloadPrefix::new(
                addr.prefix.to_v4().into(),
                addr.prefix.addr_len()
            ).ok().and_then(|prefix| {
                MaxLenPrefix::new(prefix, addr.max_length).ok()
            }).map(|prefix| RouteOrigin::new(prefix, self.as_id))
        }).chain(
            self.v6_addrs.iter().filter_map(move |addr| {
                PayloadPrefix::new(
                    addr.prefix.to_v6().into(),
                    addr.prefix.addr_len()
                ).ok().and_then(|prefix| {
                    MaxLenPrefix::new(prefix, addr.max_length).ok()
                }).map(|prefix| RouteOrigin::new(prefix, self.as_id))
            })
        )
    }
}

impl RouteOriginAttestation {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            // version [0] EXPLICIT INTEGER DEFAULT 0
            cons.take_opt_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(0))?;
            let as_id = Asn::take_from(cons)?;
            let mut v4 = None;
            let mut v6 = None;
            cons.take_sequence(|cons| {
                while let Some(()) = cons.take_opt_sequence(|cons| {
                    match AddressFamily::take_from(cons)? {
                        AddressFamily::Ipv4 => {
                            if v4.is_some() {
                                return Err(cons.content_err(
                                    "multiple IPv4 blocks in ROA prefixes"
                                ));
                            }
                            v4 = Some(RoaIpAddresses::take_from(
                                cons, AddressFamily::Ipv4
                            )?);
                        }
                        AddressFamily::Ipv6 => {
                            if v6.is_some() {
                                return Err(cons.content_err(
                                    "multiple IPv6 blocks in ROA prefixes"
                                ));
                            }
                            v6 = Some(RoaIpAddresses::take_from(
                                cons, AddressFamily::Ipv6
                            )?);
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
            })
        })
    }

    fn verify(
        &mut self,
        cert: &ResourceCert
    ) -> Result<(), VerificationError> {
        if !self.v4_addrs.is_empty() {
            let blocks = cert.v4_resources();
            if blocks.is_empty() {
                return Err(VerificationError::new(
                    "no IPv4 ROA prefix covered by certificate"
                ))
            }
            for addr in self.v4_addrs.iter() {
                if !blocks.contains_roa(&addr) {
                    return Err(UncoveredPrefix::new(addr, true).into())
                }
            }
        }
        if !self.v6_addrs.is_empty() {
            let blocks = cert.v6_resources();
            if blocks.is_empty() {
                return Err(VerificationError::new(
                    "no IPv6 ROA prefix covered by certificate"
                ))
            }
            for addr in self.v6_addrs.iter() {
                if !blocks.contains_roa(&addr) {
                    return Err(UncoveredPrefix::new(addr, false).into())
                }
            }
        }
        Ok(())
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
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
        cons: &mut decode::Constructed<S>,
        family: AddressFamily,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            cons.capture(|cons| {
                while RoaIpAddress::skip_opt_in(cons, family)?.is_some() { }
                Ok(())
            })
        }).map(RoaIpAddresses)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> RoaIpAddressIter {
        RoaIpAddressIter(self.0.as_slice().into_source())
    }

    fn encode_ref_family(
        &self,
        family: [u8; 2]
    ) -> Option<impl encode::Values + '_> {
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
pub struct RoaIpAddressIter<'a>(SliceSource<'a>);

impl<'a> Iterator for RoaIpAddressIter<'a> {
    type Item = RoaIpAddress;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        }
        else {
            Mode::Der.decode(&mut self.0, |cons| {
                RoaIpAddress::take_opt_from_unchecked(cons)
            }).unwrap()
        }
    }
}


//------------ RoaIpAddress --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

    pub fn prefix(self) -> Prefix {
        self.prefix
    }

    pub fn range(self) -> (Addr, Addr) {
        self.prefix.range()
    }

    pub fn max_length(self) -> Option<u8> {
        self.max_length
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

    fn take_opt_from_unchecked<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            Ok(RoaIpAddress {
                prefix: Prefix::take_from(cons)?,
                max_length: cons.take_opt_u8()?,
            })
        })
    }

    /// Skips one address in a source.
    ///
    /// In order to check that the address is correctly formatted, this
    /// function needs to know the address family of the address.
    fn skip_opt_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        family: AddressFamily,
    ) -> Result<Option<()>, DecodeError<S::Error>> {
        let addr = match Self::take_opt_from_unchecked(cons)? {
            Some(addr) => addr,
            None => return Ok(None)
        };

        // Check that the prefix length fits the address family.
        if addr.prefix.addr_len() > family.max_addr_len() {
            return Err(cons.content_err(
                "prefix length too large in ROA prefix"
            ))
        }

        // Check that a max length fits both family and prefix length.
        if let Some(max_length) = addr.max_length {
            if max_length > family.max_addr_len() 
                || max_length < addr.prefix.addr_len()
            {
                return Err(cons.content_err(
                    "max length too large in ROA prefix"
                ))
            }
        }

        Ok(Some(()))
    }

    fn encode(&self) -> impl encode::Values {
        encode::sequence((
            self.prefix.encode(),
            self.max_length.map(|v| v.encode())
        ))
    }
}


//------------ FriendlyRoaIpAddress ------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FriendlyRoaIpAddress {
    addr: RoaIpAddress,
    v4: bool
}

impl FriendlyRoaIpAddress {
    fn new(addr: RoaIpAddress, v4: bool) -> Self {
        FriendlyRoaIpAddress { addr, v4 }
    }

    pub fn prefix(self) -> Prefix {
        self.addr.prefix
    }

    pub fn is_v4(self) -> bool {
        self.v4
    }

    pub fn address(self) -> IpAddr {
        if self.v4 {
            self.addr.prefix.to_v4().into()
        }
        else {
            self.addr.prefix.to_v6().into()
        }
    }

    pub fn address_length(self) -> u8 {
        self.addr.prefix.addr_len()
    }

    pub fn max_length(self) -> u8 {
        self.addr.max_length.unwrap_or_else(||
            self.addr.prefix.addr_len()
        )
    }
}

impl fmt::Display for FriendlyRoaIpAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.v4 {
            self.addr.prefix.fmt_v4(f)?;
        }
        else {
            self.addr.prefix.fmt_v6(f)?;
        }
        write!(f, "/{}", self.addr.prefix.addr_len())?;
        if let Some(max_len) = self.addr.max_length {
            write!(f, "-{}", max_len)?;
        }
        Ok(())
    }
}


//------------ RoaBuilder ----------------------------------------------------

pub struct RoaBuilder {
    as_id: Asn,
    v4: RoaIpAddressesBuilder,
    v6: RoaIpAddressesBuilder,
}

impl RoaBuilder {
    pub fn new(as_id: Asn) -> Self {
        Self::with_addresses(
            as_id,
            RoaIpAddressesBuilder::new(),
            RoaIpAddressesBuilder::new(),
        )
    }

    pub fn with_addresses(
        as_id: Asn,
        v4: RoaIpAddressesBuilder,
        v6: RoaIpAddressesBuilder
    ) -> Self {
        Self { as_id, v4, v6 }
    }

    pub fn as_id(&self) -> Asn {
        self.as_id
    }

    pub fn set_as_id(&mut self, as_id: Asn) {
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
        IpResources::blocks(
            self.addrs.iter().map(|addr| addr.prefix.into()).collect()
        )
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
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


//============ Errors ========================================================

/// A ROA prefix wasn’t covered by the certificate’s IP resources.
#[derive(Clone, Debug)]
struct UncoveredPrefix {
    prefix: FriendlyRoaIpAddress,
}

impl UncoveredPrefix {
    fn new(addr: RoaIpAddress, v4: bool) -> Self {
        UncoveredPrefix { prefix: FriendlyRoaIpAddress::new(addr, v4) }
    }
}

impl fmt::Display for UncoveredPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ROA prefix {} not covered by certificate", self.prefix)
    }
}

impl From<UncoveredPrefix> for VerificationError {
    fn from(err: UncoveredPrefix) -> Self {
        ContentError::from_boxed(Box::new(err)).into()
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
                include_bytes!("../../test-data/example-ripe.roa").as_ref(),
                false
            ).is_ok()
        )
    }

    #[test]
    fn decode_illegal_roas() {
        assert!(
            Roa::decode(
                include_bytes!(
                    "../../test-data/prefix-len-overflow.roa"
                ).as_ref(),
                false
            ).is_err()
        );
        assert!(
            Roa::decode(
                include_bytes!("../../test-data/maxlen-overflow.roa").as_ref(),
                false
            ).is_err()
        );
        assert!(
            Roa::decode(
                include_bytes!("../../test-data/maxlen-underflow.roa").as_ref(),
                false
            ).is_err()
        );
    }
}

#[cfg(all(test, feature="softkeys"))]
mod signer_test {
    use std::str::FromStr;
    use bcder::encode::Values;
    use crate::uri;
    use crate::crypto::{PublicKeyFormat, Signer};
    use crate::crypto::softsigner::OpenSslSigner;
    use crate::repository::cert::{KeyUsage, Overclaim, TbsCert};
    use crate::repository::resources::{Asn, Prefix};
    use crate::repository::tal::TalInfo;
    use crate::repository::x509::Validity;
    use super::*;

    fn make_roa() -> Roa {
        let signer = OpenSslSigner::new();
        let key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
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
        cert.build_as_resource_blocks(|b| b.push((Asn::MIN, Asn::MAX)));
        let cert = cert.into_cert(&signer, &key).unwrap();

        let mut roa = RoaBuilder::new(64496.into());
        roa.push_v4_addr(Ipv4Addr::new(192, 0, 2, 0), 24, None);

        let roa = roa.finalize(
            SignedObjectBuilder::new(
                12u64.into(), Validity::from_secs(86400), uri.clone(),
                uri.clone(), uri
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
    #[cfg(feature = "serde")]
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

