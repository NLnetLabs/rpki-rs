//! Certificate Revocation Lists for RPKI.
//!
//! Much like for certificates, RPKI reuses X.509 for its certifcate
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

use std::collections::HashSet;
use bcder::{decode, encode};
use bcder::{Captured, Mode, OctetString, Oid, Tag, Unsigned};
use crate::uri;
use crate::x509::{Name, SignedData, Time, ValidationError};
use crate::signing::SignatureAlgorithm;
use crate::cert::ext::{AuthorityKeyIdentifier, CrlNumber};
use crate::cert::ext::oid;
use crate::cert::SubjectPublicKeyInfo;


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

    /// The algorithm used for signing the certificate.
    signature: SignatureAlgorithm,

    /// The name of the issuer.
    ///
    /// This isn’t really used in RPKI at all.
    issuer: Name,

    /// The time this version of the CRL was created.
    this_update: Time,

    /// The time the next version of the CRL is likely to be created.
    next_update: Option<Time>,

    /// The list of revoked certificates.
    revoked_certs: RevokedCertificates,

    /// The CRL extensions.
    extensions: Extensions,

    /// An optional cache of the serial numbers in the CRL.
    serials: Option<HashSet<Unsigned>>,
}

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

        signed_data.data().clone().decode(|cons| {
            cons.take_sequence(|cons| {
                cons.skip_u8_if(1)?; // v2 => 1
                Ok(Crl {
                    signed_data,
                    signature: SignatureAlgorithm::take_from(cons)?,
                    issuer: Name::take_from(cons)?,
                    this_update: Time::take_from(cons)?,
                    next_update: Time::take_opt_from(cons)?,
                    revoked_certs: RevokedCertificates::take_from(cons)?,
                    extensions: cons.take_constructed_if(
                        Tag::CTX_0,
                        Extensions::take_from
                    )?,
                    serials: None,
                })
            })
        }).map_err(Into::into)
    }

    /// Validates the certificate revocation list.
    ///
    /// The list’s signature is validated against the provided public key.
    pub fn validate(
        &self,
        public_key: &SubjectPublicKeyInfo
    ) -> Result<(), ValidationError> {
        self.signed_data.verify_signature(public_key)
    }

    /// Caches the serial numbers in the CRL.
    ///
    /// Doing this will speed up calls to `contains` later on at the price
    /// of additional memory consumption.
    pub fn cache_serials(&mut self) {
        self.serials = Some(
            self.revoked_certs.iter().map(|entry| entry.user_certificate)
                .collect()
        );
    }

    /// Returns whether the given serial number is on this revocation list.
    pub fn contains(&self, serial: &Unsigned) -> bool {
        match self.serials {
            Some(ref set) => {
                set.contains(serial)
            }
            None => self.revoked_certs.contains(serial)
        }
    }

    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {
        // This relies on signed_data always being in sync with the other
        // elements!
        self.signed_data.encode()
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
    pub fn contains(&self, serial: &Unsigned) -> bool {
        Mode::Der.decode(self.0.as_ref(), |cons| {
            while let Some(entry) = CrlEntry::take_opt_from(cons).unwrap() {
                if entry.user_certificate == *serial {
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
#[derive(Clone, Debug)]
pub struct CrlEntry {
    /// The serial number of the revoked certificate.
    user_certificate: Unsigned,

    /// The time of revocation.
    revocation_date: Time,
}

impl CrlEntry {
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
            user_certificate: Unsigned::take_from(cons)?,
            revocation_date: Time::take_from(cons)?,
            // crlEntryExtensions are forbidden by RFC 6487.
        })
    }
}


//------------ Extensions ----------------------------------------------------

/// Extensions of a RPKI certificate revocation list.
///
/// Only two extension are allowed to be present: the authority key
/// identifier extension which contains the key identifier of the certificate
/// this CRL is associated with, and the CRL number which is the serial
/// number of this version of the CRL.
#[derive(Clone, Debug)]
pub struct Extensions {
    /// Authority Key Identifier
    ///
    /// May be omitted in CRLs included in protocol messages.
    authority_key_id: Option<AuthorityKeyIdentifier>,

    /// CRL Number
    crl_number: CrlNumber,
}

impl Extensions {
    /// Takes the CRL extension from the beginning of a constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            let mut authority_key_id = None;
            let mut crl_number = None;
            while let Some(()) = cons.take_opt_sequence(|cons| {
                let id = Oid::take_from(cons)?;
                let critical = cons.take_opt_bool()?.unwrap_or(false);
                let value = OctetString::take_from(cons)?;
                Mode::Der.decode(value.to_source(), |cons| {
                    if id == oid::CE_AUTHORITY_KEY_IDENTIFIER {
                        AuthorityKeyIdentifier::take(
                            cons, critical, &mut authority_key_id
                        )
                    }
                    else if id == oid::CE_CRL_NUMBER {
                        CrlNumber::take(cons, critical, &mut crl_number)
                    }
                    else {
                        // RFC 6487 says that no other extensions are
                        // allowed. So we fail even if there is only
                        // non-critical extension.
                        xerr!(Err(decode::Malformed))
                    }
                }).map_err(Into::into)
            })? { }
            let crl_number = match crl_number {
                Some(some) => some,
                None => return Err(decode::Malformed.into())
            };
            Ok(Extensions {
                authority_key_id,
                crl_number
            })
        })
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

