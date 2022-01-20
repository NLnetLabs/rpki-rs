//! Remote access protocols.
//!
//! This module contains types and procedures to support the communication
//! protocols used between CAs and their parents and publication server.
//! 
//! Relevant RFCs:
//! RFC 8183 out-of-band ID exchanges
//! RFC 8181 publication protocol
//! RFC 6492 provisioning protocol (up/down)
//! 
//! In addition to this there is an ongoing effort to make new version
//! standards for these protocols in order to support needed features
//! which are currently missing.

#![cfg(feature = "remote")]

//--- Modules
//
pub mod error;
pub mod idcert;
pub mod idexchange;
pub mod sigmsg;