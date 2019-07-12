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

// We have seemingly redundant closures (i.e., closures where just providing
// a function would also work) that cannot be removed due to lifetime issues.
// (This has since been corrected but is still present in 1.34.0.)
#![allow(clippy::redundant_closure)]

pub mod cert;
pub mod crl;
pub mod crypto;
pub mod csr;
pub mod manifest;
pub mod oid;
pub mod resources;
pub mod roa;
pub mod rrdp;
pub mod sigobj;
pub mod tal;
pub mod uri;
pub mod x509;
pub mod xml;

mod util;
