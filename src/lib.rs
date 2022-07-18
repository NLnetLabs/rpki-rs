//! All things RPKI.
//!
//! The _Resource Public Key Infrastructure_ (RPKI) is an application of
//! PKI to Internet routing security. It allows owners of IP address prefixes
//! and AS numbers to publish cryptographically signed information about
//! these resources. In particular, RPKI is currently used for route origin
//! validation where these statements list the AS numbers that are allowed
//! to originate routes for prefixes.
//!
//! # Features
//!
//! The crate uses the features to enable functionality that isn’t necessary
//! for all use cases. Currently, the following features are defined:
//!
//! * `"repository"`: support for creating, validating, and processing of
//!   repository objects, such as certificates, manifests, or ROAs;
//! * `"rrdp"`: support for the RRDP protocol for synchronising RPKI
//!   repositories;
//! * `"rtr"`: support for the RPKI-to-router protocol (RTR);
//! * `"slurm"`: support for local exceptions aka SLURM;
//! * `"serde-support"`: support for Serde serialization and deserialization
//!   for many of the crate’s types;
//! * `"softkeys"`: enables an OpenSSL-based signer for creating repository
//!   objects – enabling this feature also enables the `"repository"`
//!   feature;
//! * `"extra-debug"`: enables printing stack traces when parsing of a
//!   repository object fails – this feature should only be used during
//!   debugging and must not be enabled in release builds.

#![allow(renamed_and_removed_lints)]
#![allow(clippy::unknown_clippy_lints)]


pub mod ca;
pub mod crypto;
pub mod oid;
pub mod repository;
pub mod rrdp;
pub mod rtr;
pub mod slurm;
pub mod uri;
pub mod xml;

