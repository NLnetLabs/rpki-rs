//! Certificate Revocation Lists for RPKI.
//!
//! Much like for certificates, RPKI reuses X.509 for its certificate
//! revocation lists (CRLs), limiting the values that are allowed in the
//! various fields.
//!
//! This module implements the CRLs themselves via the type [`Crl`] as well
//! as a [`CrlStore`] that can keep several CRLs which may be helpful during
//! validation.
//!
//! The RPKI CRL profile is defined in RFC 6487 based on the Internet RPIX
//! profile defined in RFC 5280.
//!
//! [`Crl`]: struct.Crl.html
//! [`CrlStore`]: struct.CrlStore.html

use std::ops;
use std::collections::HashSet;
use std::str::FromStr;
use bcder::{decode, encode};
use bcder::{Captured, Mode, OctetString, Oid, Tag, xerr};
use bcder::encode::PrimitiveContent;
use bytes::Bytes;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use crate::{oid, uri};
use crate::crypto::{
    KeyIdentifier, PublicKey, SignatureAlgorithm, Signer, SigningError
};
use crate::x509::{
    Name, RepresentationError, Serial, SignedData, Time, ValidationError,
    encode_extension, update_once
};


//------------ Crl -----------------------------------------------------------

/// An RPKI certificate revocation list.
///
/// A value of this type is the result of parsing a CRL file found in the
/// RPKI repository. You can use the `decode` function for parsing a CRL out
/// of such a file.
#[derive(Clone, Debug)]
pub struct Crl {
    /// The outer structure of the CRL.
    signed_data: SignedData,

    /// The payload of the CRL.
    tbs: TbsCertList<RevokedCertificates>,

    /// An optional cache of the serial numbers in the CRL.
    serials: Option<HashSet<Serial>>,
}

/// # Data Access
///
impl Crl {
    /// Returns a reference to the signed data wrapper.
    pub fn signed_data(&self) -> &SignedData {
        &self.signed_data
    }

    /// Returns a reference to the payload.
    ///
    /// This also available via the `AsRef` and `Deref` impls.
    pub fn as_cert_list(&self) -> &TbsCertList<RevokedCertificates> {
        &self.tbs
    }

    /// Caches the serial numbers in the CRL.
    ///
    /// Doing this will speed up calls to `contains` later on at the price
    /// of additional memory consumption.
    pub fn cache_serials(&mut self) {
        self.serials = Some(
            self.tbs.revoked_certs.iter().map(|entry| entry.user_certificate)
                .collect()
        );
    }

    /// Returns whether the given serial number is on this revocation list.
    pub fn contains(&self, serial: Serial) -> bool {
        match self.serials {
            Some(ref set) => set.contains(&serial),
            None => self.tbs.revoked_certs.contains(serial)
        }
    }
}


/// # Decode, Validate, and Encode
///
impl Crl {
    /// Parses a source as a certificate revocation list.
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    /// Takes an encoded CRL from the beginning of a constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the content of a certificate revocation list.
    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let signed_data = SignedData::from_constructed(cons)?;
        let tbs = signed_data.data().clone().decode(TbsCertList::take_from)?;
        Ok(Self { signed_data, tbs, serials: None })
    }

    /// Validates the certificate revocation list.
    ///
    /// The list’s signature is validated against the provided public key.
    pub fn validate(
        &self,
        public_key: &PublicKey
    ) -> Result<(), ValidationError> {
        if self.tbs.signature != self.signed_data.signature().algorithm() {
            return Err(ValidationError)
        }
        self.signed_data.verify_signature(public_key)
    }

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        self.signed_data.encode_ref()
    }

    /// Returns a captured encoding of the CRL.
    pub fn to_captured(&self) -> Captured {
        Captured::from_values(Mode::Der, self.encode_ref())
    }
}


//--- Deref and AsRef

impl ops::Deref for Crl {
    type Target = TbsCertList<RevokedCertificates>;

    fn deref(&self) -> &Self::Target {
        &self.tbs
    }
}

impl AsRef<TbsCertList<RevokedCertificates>> for Crl {
    fn as_ref(&self) -> &TbsCertList<RevokedCertificates> {
        &self.tbs
    }
}


//--- Deserialize and Serialize

impl Serialize for Crl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let bytes = self.to_captured().into_bytes();
        let b64 = base64::encode(&bytes);
        b64.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Crl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        use serde::de;

        let string = String::deserialize(deserializer)?;
        let decoded = base64::decode(&string).map_err(de::Error::custom)?;
        let bytes = Bytes::from(decoded);
        Crl::decode(bytes).map_err(de::Error::custom)
    }
}


//------------ TbsCertList ---------------------------------------------------

/// The payload of a certificate revocation list.
///
/// This type is generic over the list of revoked certificates.
#[derive(Clone, Debug)]
pub struct TbsCertList<C> {
    /// The algorithm used for signing the certificate.
    signature: SignatureAlgorithm,

    /// The name of the issuer.
    ///
    /// This isn’t really used in RPKI at all.
    issuer: Name,

    /// The time this version of the CRL was created.
    this_update: Time,

    /// The time the next version of the CRL is likely to be created.
    next_update: Time,

    /// The list of revoked certificates.
    revoked_certs: C,

    /// Authority Key Identifier
    authority_key_id: KeyIdentifier,

    /// CRL Number
    crl_number: Serial,
}

/// # Creating and Converting
///
impl<C> TbsCertList<C> {
    /// Creates a new value from the necessary data.
    pub fn new(
        signature: SignatureAlgorithm,
        issuer: Name,
        this_update: Time,
        next_update: Time,
        revoked_certs: C,
        authority_key_id: KeyIdentifier,
        crl_number: Serial
    ) -> Self {
        Self {
            signature,
            issuer,
            this_update,
            next_update,
            revoked_certs,
            authority_key_id,
            crl_number
        }
    }

    /// Converts the value into a signed CRL.
    pub fn into_crl<S: Signer>(
        self,
        signer: &S,
        key: &S::KeyId
    ) -> Result<Crl, SigningError<S::Error>>
    where
        C: IntoIterator<Item=CrlEntry>,
        <C as IntoIterator>::IntoIter: Clone
    {
        let tbs: TbsCertList<RevokedCertificates> = self.into();
        let data = Captured::from_values(Mode::Der, tbs.encode_ref());
        let signature = signer.sign(key, tbs.signature, &data)?;
        Ok(Crl {
            signed_data: SignedData::new(data, signature),
            tbs,
            serials: None,
        })
    }
}

/// # Data Access
///
impl<C> TbsCertList<C> {
    /// Returns the algorithm used by the issuer to sign the CRL.
    pub fn signature(&self) -> SignatureAlgorithm {
        self.signature
    }

    /// Sets the signature algorithm.
    pub fn set_signature(&mut self, signature: SignatureAlgorithm) {
        self.signature = signature
    }

    /// Returns a reference to the issuer name of the CRL.
    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    /// Sets the issuer name.
    pub fn set_issuer(&mut self, issuer: Name) {
        self.issuer = issuer
    }

    /// Returns the update time of this CRL.
    pub fn this_update(&self) -> Time {
        self.this_update
    }

    /// Sets the update time of this CRL.
    pub fn set_this_update(&mut self, this_update: Time) {
        self.this_update = this_update
    }

    /// Returns the time of next update if present.
    pub fn next_update(&self) -> Time {
        self.next_update
    }

    /// Returns whether the CRL’s nextUpdate time has passed.
    pub fn is_stale(&self) -> bool {
        self.next_update < Time::now()
    }

    /// Sets the time of next update.
    pub fn set_next_update(&mut self, next_update: Time) {
        self.next_update = next_update
    }

    /// Returns a reference to the list of revoked certificates.
    pub fn revoked_certs(&self) -> &C {
        &self.revoked_certs
    }

    /// Returns a mutable reference to the list of revoked certificates.
    pub fn revoked_certs_mut(&mut self) -> &mut C {
        &mut self.revoked_certs
    }

    /// Sets the list of revoked certificates.
    pub fn set_revoked_certs(&mut self, revoked_certs: C) {
        self.revoked_certs = revoked_certs
    }

    /// Returns a reference to the authority key identifier if present.
    pub fn authority_key_identifier(&self) -> &KeyIdentifier {
        &self.authority_key_id
    }

    /// Sets the authority key identifer.
    pub fn set_authority_key_identifier(&mut self, id: KeyIdentifier) {
        self.authority_key_id = id
    }

    /// Returns the CRL number.
    pub fn crl_number(&self) -> Serial {
        self.crl_number
    }

    /// Sets the CRL number.
    pub fn set_crl_number(&mut self, crl_number: Serial) {
        self.crl_number = crl_number
    }
}


/// # Decoding and Encoding
///
impl TbsCertList<RevokedCertificates> {
    /// Takes a value from the beginning of a encoded constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            // version. Technically it is optional but we need v2, so it must
            // actually be there. v2 is encoded as an integer of value 1.
            cons.skip_u8_if(1)?;
            let signature = SignatureAlgorithm::x509_take_from(cons)?;
            let issuer = Name::take_from(cons)?;
            let this_update = Time::take_from(cons)?;
            let next_update = Time::take_from(cons)?;
            let revoked_certs = RevokedCertificates::take_from(cons)?;
            let mut authority_key_id = None;
            let mut crl_number = None;
            cons.take_constructed_if(Tag::CTX_0, |cons| {
                cons.take_sequence(|cons| {
                    while let Some(()) = cons.take_opt_sequence(|cons| {
                        let id = Oid::take_from(cons)?;
                        let _critical = cons.take_opt_bool()?.unwrap_or(false);
                        let value = OctetString::take_from(cons)?;
                        Mode::Der.decode(value.to_source(), |content| {
                            if id == oid::CE_AUTHORITY_KEY_IDENTIFIER {
                                Self::take_authority_key_identifier(
                                    content, &mut authority_key_id
                                )
                            }
                            else if id == oid::CE_CRL_NUMBER {
                                Self::take_crl_number(
                                    content, &mut crl_number
                                )
                            }
                            else {
                                // RFC 6487 says that no other extensions are
                                // allowed. So we fail even if there is only
                                // non-critical extension.
                                xerr!(Err(decode::Malformed))
                            }
                        }).map_err(Into::into)
                    })? { }
                    Ok(())
                })
            })?;
            let authority_key_id = authority_key_id.ok_or(decode::Malformed)?;
            let crl_number = crl_number.ok_or(decode::Malformed)?;
            Ok(Self {
                signature,
                issuer,
                this_update,
                next_update,
                revoked_certs,
                authority_key_id,
                crl_number
            })
        })
    }

    /// Parses the Authority Key Identifier extension.
    fn take_authority_key_identifier<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        authority_key_id: &mut Option<KeyIdentifier>,
    ) -> Result<(), S::Err> {
        update_once(authority_key_id, || {
            cons.take_sequence(|cons| {
                cons.take_value_if(Tag::CTX_0, KeyIdentifier::from_content)
            })
        })
    }

    /// Parses the CRL Number extension.
    fn take_crl_number<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        crl_number: &mut Option<Serial>,
    ) -> Result<(), S::Err> {
        update_once(crl_number, || {
            Serial::take_from(cons)
        })
    }

    /// Returns a value encoder for a reference to this value.
    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            1.encode(), // version
            self.signature.x509_encode(),
            self.issuer.encode_ref(),
            self.this_update.encode_varied(),
            self.next_update.encode_varied(),
            self.revoked_certs.encode_ref(),
            encode::sequence_as(Tag::CTX_0, 
                encode::sequence((
                    encode_extension(
                        &oid::CE_AUTHORITY_KEY_IDENTIFIER, false,
                        encode::sequence(
                            self.authority_key_id.encode_ref_as(Tag::CTX_0)
                        )
                    ),
                    encode_extension(
                        &oid::CE_CRL_NUMBER, false,
                        self.crl_number.encode()
                    ),
                ))
            )
        ))
    }
}


//--- From

impl<C> From<TbsCertList<C>> for TbsCertList<RevokedCertificates>
where
    C: IntoIterator<Item = CrlEntry>,
    <C as IntoIterator>::IntoIter: Clone
{
    fn from(list: TbsCertList<C>) -> Self {
        Self {
            signature: list.signature,
            issuer: list.issuer,
            this_update: list.this_update,
            next_update: list.next_update,
            revoked_certs: RevokedCertificates::from_iter(list.revoked_certs),
            authority_key_id: list.authority_key_id,
            crl_number: list.crl_number,
        }
    }
}

//------------ RevokedCertificates ------------------------------------------

/// The list of revoked certificates.
///
/// A value of this type wraps the bytes of the DER encoded list. You can
/// check whether a certain serial number is part of this list via the
/// `contains` method.
#[derive(Clone, Debug)]
pub struct RevokedCertificates(Captured);

impl RevokedCertificates {
    /// Takes a revoked certificates list from the beginning of a value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let res = cons.take_opt_sequence(|cons| {
            cons.capture(|cons| {
                while let Some(_) = CrlEntry::take_opt_from(cons)? { }
                Ok(())
            })
        })?;
        Ok(RevokedCertificates(match res {
            Some(res) => res,
            None => Captured::empty(Mode::Der)
        }))
    }

    /// Returns whether the given serial number is contained on this list.
    ///
    /// The method walks over the list, decoding it on the fly and checking
    /// each entry.
    pub fn contains(&self, serial: Serial) -> bool {
        Mode::Der.decode(self.0.as_ref(), |cons| {
            while let Some(entry) = CrlEntry::take_opt_from(cons).unwrap() {
                if entry.user_certificate == serial {
                    return Ok(true)
                }
            }
            Ok(false)
        }).unwrap()
    }

    /// Returns an iterator over the entries in the list.
    pub fn iter(&self) -> RevokedCertificatesIter {
        RevokedCertificatesIter(self.0.clone())
    }

    /// Returns a value encoder for a reference to the value.
    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence(&self.0)
    }

    /// Create a value from an iterator over CRL entries.
    ///
    /// This can’t be the `FromIterator` trait because of the `Clone`
    /// requirement on `I::IntoIter`
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = CrlEntry>,
        <I as IntoIterator>::IntoIter: Clone
    {
        RevokedCertificates(Captured::from_values(
            Mode::Der, encode::iter(
                iter.into_iter().map(CrlEntry::encode)
            )
        ))
    }
}


//------------ RevokedCertificatesIter ---------------------------------------

/// An iterator over the entries in the list of revoked certificates.
#[derive(Clone, Debug)]
pub struct RevokedCertificatesIter(Captured);

impl Iterator for RevokedCertificatesIter {
    type Item = CrlEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.decode_partial(|cons| CrlEntry::take_opt_from(cons)).unwrap()
    }
}


//------------ CrlEntry ------------------------------------------------------

/// An entry in the revoked certificates list.
#[derive(Clone, Copy, Debug)]
pub struct CrlEntry {
    /// The serial number of the revoked certificate.
    user_certificate: Serial,

    /// The time of revocation.
    revocation_date: Time,
}

impl CrlEntry {
    /// Creates a new CrlEntry for inclusion on a new Crl
    pub fn new(user_certificate: Serial, revocation_date: Time) -> Self {
        CrlEntry { user_certificate, revocation_date }
    }

    /// Takes a single CRL entry from the beginning of a constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Takes an optional CRL entry from the beginning of a contructed value.
    pub fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, S::Err> {
        cons.take_opt_sequence(Self::from_constructed)
    }

    /// Parses the content of a CRL entry.
    pub fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        Ok(CrlEntry {
            user_certificate: Serial::take_from(cons)?,
            revocation_date: Time::take_from(cons)?,
            // crlEntryExtensions are forbidden by RFC 6487.
        })
    }

    /// Returns a value encoder for the entry.
    pub fn encode(self) -> impl encode::Values {
        encode::sequence((
            self.user_certificate.encode(),
            self.revocation_date.encode_varied(),
        ))
    }
}


//--- FromStr

impl FromStr for CrlEntry {
    type Err = RepresentationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(pos) = s.find('@') {
            Ok(CrlEntry::new(
                Serial::from_str(&s[..pos])?,
                Time::from_str(&s[pos + 1..]).map_err(|_| RepresentationError)?
            ))
        }
        else {
            Serial::from_str(s).map(|serial| {
                CrlEntry::new(serial, Time::now())
            })
        }
    }
}


//------------ CrlStore ------------------------------------------------------

/// A place to cache CRLs for reuse.
///
/// This type allows to store CRLs you have seen in case you may need them
/// again soon. This is useful when validating the objects issued by a CA as
/// they likely all refer to the same CRL, so keeping it around makes sense.
#[derive(Clone, Debug)]
pub struct CrlStore {
    /// The CRLs in the store.
    ///
    /// This is a simple vector because most likely we’ll only ever have one.
    crls: Vec<(uri::Rsync, Crl)>,

    /// Should we cache the serials in our CRLs?
    cache_serials: bool,
}

impl CrlStore {
    /// Creates a new CRL store.
    pub fn new() -> Self {
        CrlStore {
            crls: Vec::new(),
            cache_serials: false,
        }
    }

    /// Enables caching of serial numbers in the stored CRLs.
    pub fn enable_serial_caching(&mut self) {
        self.cache_serials = true
    }

    /// Adds an entry to the CRL store.
    ///
    /// The CRL is keyed by its rsync `uri`.
    pub fn push(&mut self, uri: uri::Rsync, mut crl: Crl) {
        if self.cache_serials {
            crl.cache_serials()
        }
        self.crls.push((uri, crl))
    }

    /// Returns a reference to a CRL if it is available in the store.
    pub fn get(&self, uri: &uri::Rsync) -> Option<&Crl> {
        for &(ref stored_uri, ref crl) in &self.crls {
            if *stored_uri == *uri {
                return Some(crl)
            }
        }
        None
    }
}

impl Default for CrlStore {
    fn default() -> Self {
        Self::new()
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn decode_certs() {
        Crl::decode(
            include_bytes!("../test-data/ta.crl").as_ref()
        ).unwrap();
        Crl::decode(
            include_bytes!("../test-data/ca1.crl").as_ref()
        ).unwrap();
    }

    #[test]
    fn serde_crl() {
        let der = include_bytes!("../test-data/ta.crl");
        let crl = Crl::decode(Bytes::from_static(der)).unwrap();

        let serialized = serde_json::to_string(&crl).unwrap();
        let deser_crl: Crl = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            crl.to_captured().into_bytes(),
            deser_crl.to_captured().into_bytes()
        );
    }
}

#[cfg(all(test, feature="softkeys"))]
mod signer_test {
    use super::*;
    use crate::crypto::PublicKeyFormat;
    use crate::crypto::softsigner::OpenSslSigner;

    #[test]
    fn build_ta_cert() {
        let mut signer = OpenSslSigner::new();
        let key = signer.create_key(PublicKeyFormat::default()).unwrap();
        let pubkey = signer.get_key_info(&key).unwrap();
        let crl = TbsCertList::new(
            Default::default(),
            pubkey.to_subject_name(),
            Time::now(),
            Time::tomorrow(),
            vec![CrlEntry::new(12u64.into(), Time::now())],
            KeyIdentifier::from_public_key(&pubkey),
            12u64.into()
        );
        let crl = crl.into_crl(&signer, &key).unwrap().to_captured();
        let _crl = Crl::decode(crl.as_slice()).unwrap();
    }
}

