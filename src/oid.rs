//! The object identifiers used in this crate.
//!
//! This module collects all the object indentifiers used at various places
//! in this crate in one central place. They are public so you can refer to
//! them should that ever become necessary.

use bcder::{ConstOid, Oid};

/// [RFC 4055](https://tools.ietf.org/html/rfc4055) `id-sha256`
///
/// Identifies the SHA-256 one-way hash function.
pub const SHA256: ConstOid
    = Oid(&[96, 134, 72, 1, 101, 3, 4, 2, 1]);

/// [RFC 4055](https://tools.ietf.org/html/rfc4055) `rsaEncryption`
///
/// Identifies an RSA public key with no limitation to either RSASSA-PSS or
/// RSAES-OEAP.
pub const RSA_ENCRYPTION: ConstOid
    = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]);

/// [RFC 4055](https://tools.ietf.org/html/rfc4055) `sha256WithRSAEncryption`
///
/// Identifies the PKCS #1 version 1.5 signature algorithm with SHA-256.
pub const SHA256_WITH_RSA_ENCRYPTION: ConstOid
        = Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 11]);

