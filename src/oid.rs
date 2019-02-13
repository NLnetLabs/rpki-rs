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


pub const SIGNED_DATA: Oid<&[u8]>
    = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 2]);
pub const CONTENT_TYPE: Oid<&[u8]>
    = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 3]);
pub const PROTOCOL_CONTENT_TYPE: Oid<&[u8]>
    = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 28]);
pub const MESSAGE_DIGEST: Oid<&[u8]>
    = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 4]);
pub const SIGNING_TIME: Oid<&[u8]>
    = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 5]);
pub const AA_BINARY_SIGNING_TIME: Oid<&[u8]> =
    Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 46]);


pub const AD_CA_ISSUERS: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 2]);
pub const AD_CA_REPOSITORY: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 5]);
pub const AD_RPKI_MANIFEST: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 10]);
pub const AD_RPKI_NOTIFY: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 13]);
pub const AD_SIGNED_OBJECT: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 48, 11]);

pub const AT_COMMON_NAME: Oid<&[u8]> = Oid(&[85, 4, 3]); // 2 5 4 3
pub const AT_SERIAL_NUMBER: Oid<&[u8]> = Oid(&[85, 4, 5]); // 2 5 4 5

pub const CE_AUTHORITY_KEY_IDENTIFIER: Oid<&[u8]> = Oid(&[85, 29, 35]);
pub const CE_BASIC_CONSTRAINTS: Oid<&[u8]> = Oid(&[85, 29, 19]);
pub const CE_CERTIFICATE_POLICIES: Oid<&[u8]> = Oid(&[85, 29, 32]);
pub const CE_CRL_DISTRIBUTION_POINTS: Oid<&[u8]> = Oid(&[85, 29, 31]);
pub const CE_CRL_NUMBER: Oid<&[u8]> = Oid(&[85, 29, 20]);
pub const CE_EXTENDED_KEY_USAGE: Oid<&[u8]> = Oid(&[85, 29, 37]);
pub const CE_KEY_USAGE: Oid<&[u8]> = Oid(&[85, 29, 15]);
pub const CE_SUBJECT_KEY_IDENTIFIER: Oid<&[u8]> = Oid(&[85, 29, 14]);

pub const CP_IPADDR_ASNUMBER: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 14, 2]);
pub const CP_IPADDR_ASNUMBER_V2: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 14, 3]);

pub const PE_AUTHORITY_INFO_ACCESS: Oid<&[u8]>
    = Oid(&[43, 6, 1, 5, 5, 7, 1, 1]);
pub const PE_IP_ADDR_BLOCK: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 1, 7]);
pub const PE_IP_ADDR_BLOCK_V2: Oid<&[u8]> = Oid(&[43, 6, 1, 5, 5, 7, 1, 28]);
pub const PE_AUTONOMOUS_SYS_IDS: Oid<&[u8]>
    = Oid(&[43, 6, 1, 5, 5, 7, 1, 8]);
pub const PE_AUTONOMOUS_SYS_IDS_V2: Oid<&[u8]>
    = Oid(&[43, 6, 1, 5, 5, 7, 1, 29]);
pub const PE_SUBJECT_INFO_ACCESS: Oid<&[u8]>
    = Oid(&[43, 6, 1, 5, 5, 7, 1, 11]);


