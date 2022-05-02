//! CA Support.
//!
//! This module contains support for the communication protocol used between
//! CAs, their parents and the publication server.
//! 
//! Relevant RFCs:
//! RFC 8183 out-of-band ID exchanges
//! RFC 8181 publication protocol
//! RFC 6492 provisioning protocol (up/down)     [todo]

#![cfg(feature = "ca")]

//--- Modules
//
pub mod idcert;
pub mod idexchange;

pub mod sigmsg;

pub mod provisioning;
pub mod publication;
