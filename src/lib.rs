//! All things RPKI.
//!
//! The _Resource Public Key Infrastructure_ (RPKI) is an application of
//! PKI to Internet routing security. It allows owners of IP address prefixes
//! and AS numbers to publish cryptographically signed information about
//! these resources. In particular, RPKI is currently used for route origin
//! validation where these statements list the AS numbers that are allowed
//! to originate routes for prefixes.

#![allow(renamed_and_removed_lints)]
#![allow(clippy::unknown_clippy_lints)]

pub mod payload;
pub mod repository;
pub mod rrdp;
pub mod rtr;
pub mod slurm;
pub mod uri;
pub mod xml;

