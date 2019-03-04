//! All things RPKI.
//!
//! The _Resource Public Key Infrastructure_ (RPKI) is an application of
//! PKI to Internet routing security. It allows owners of IP address prefixes
//! and AS numbers to publish cryptographically signed information about
//! these resources. In particular, RPKI is currently used for route origin
//! validation where these statements list the AS numbers that are allowed
//! to originate routes for prefixes.
//!
//! This crate will eventually implement all functionality necessary to both
//! produce and validate RPKI data. It currently implements everything
//! necessary for validation and is slowly gaining the ability to produce
//! objects as well.
//!
//! Documentation for the items in this crate is currently somewhat sparse.
//! This will be rectified in upcoming releases.
#![allow(renamed_and_removed_lints, unknown_lints)]

extern crate base64;
#[macro_use] extern crate bcder;
extern crate bytes;
extern crate chrono;
#[macro_use] extern crate derive_more;
extern crate hex;
#[macro_use] extern crate log;
#[cfg(feature = "softkeys")] extern crate openssl;
extern crate ring;
#[cfg(feature = "softkeys")] extern crate slab;
extern crate untrusted;

pub mod cert;
pub mod crl;
pub mod crypto;
pub mod manifest;
pub mod oid;
pub mod resources;
pub mod roa;
pub mod uri;
pub mod sigobj;
pub mod tal;
pub mod x509;

