//! Test data for RPKI certificates.
#![cfg(feature = "softkeys")]

use std::collections::HashMap;
use std::io;
use std::str::FromStr;
use bcder::encode;
use bcder::{
    BitString, Captured, ConstOid, Mode, OctetString, PrintableString, Tag,
    Unsigned,
};
use bcder::decode::IntoSource;
use bcder::encode::PrimitiveContent;
use bytes::Bytes;
use crate::oid;
use crate::crypto::Signer;
use crate::crypto::keys::{PublicKey, PublicKeyFormat};
use crate::crypto::signature::RpkiSignatureAlgorithm;
use crate::crypto::softsigner::OpenSslSigner;
use crate::repository::cert::{Cert, KeyUsage, ResourceCert};
use crate::repository::resources::Prefix;
use crate::repository::tal::TalInfo;
use crate::repository::x509::Time;

//------------ Test Function(s) ----------------------------------------------

#[test]
fn validate_certs() {
    CertMap::new(generate_certs()).test()
}


//------------ generate_certs ------------------------------------------------

/// Generates the test certificates.
///
/// Each item in the returned vec contains the raw data of the certificate,
/// the type of certificate,
/// and whether parsing should succeed.
fn generate_certs() -> Vec<TestCertificate> {
    let signer = OpenSslSigner::new();
    let ta_key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
    let ca_key = signer.create_key(PublicKeyFormat::Rsa).unwrap();
    vec![
        TestCertificate::sign_tbs("working-ta",
            TbsBuilder::v3()
                .serial_number(&12u8.to_be_bytes())
                .issuer(rpki_name("My First Trust Anchor", None))
                .subject(rpki_name("My First Trust Anchor", None))
                .public_key(signer.get_key_info(&ta_key).unwrap())
                .basic_constraints(true)
                .subject_key_id(signer.get_key_info(&ta_key).unwrap())
                .authority_key_id(signer.get_key_info(&ta_key).unwrap())
                .key_usage(KeyUsage::Ca)
                .rpki_ca_subject_info_access(
                    "rsync://example.com/module/dir",
                    "rsync://example.com/module/dir/manifest.mft",
                )
                .rpki_cert_policies()
                .ip_resources(
                    Some(DerData::sequence(&[ip_address("0.0.0.0/0")])),
                    Some(DerData::sequence(&[ip_address("::/0")])),
                )
                .as_resources(
                    DerData::sequence(&[as_range(0, u32::MAX)])
                )
                .finalize(),
            &signer, &ta_key,
            None,
            CertificateClass::Ta, Fail::None, true
        ),
        TestCertificate::sign_tbs("working-ca-top",
            TbsBuilder::v3()
                .serial_number(&13u8.to_be_bytes())
                .issuer(rpki_name("My First Trust Anchor", None))
                .subject(rpki_name("My First CA", None))
                .public_key(signer.get_key_info(&ca_key).unwrap())
                .basic_constraints(true)
                .subject_key_id(signer.get_key_info(&ca_key).unwrap())
                .authority_key_id(signer.get_key_info(&ta_key).unwrap())
                .key_usage(KeyUsage::Ca)
                .crl_uri("rsync://example.com/module/dir/ca.crl")
                .rpki_authority_info_access(
                    "rsync://example.com/module/dir",
                )
                .rpki_ca_subject_info_access(
                    "rsync://example.com/module/dir",
                    "rsync://example.com/module/dir/manifest.mft",
                )
                .rpki_cert_policies()
                .ip_resources(
                    Some(DerData::sequence(&[ip_address("0.0.0.0/0")])),
                    Some(DerData::sequence(&[ip_address("::/0")])),
                )
                .as_resources(
                    DerData::sequence(&[as_range(0, u32::MAX)])
                )
                .finalize(),
            &signer, &ta_key,
            Some("working-ta"),
            CertificateClass::Ca, Fail::None, true
        ),
    ]
}


//------------ CertMap ------------------------------------------------------

pub struct CertMap {
    certs: HashMap<
        &'static str,
        Result<TestCertificate, Option<ResourceCert>>
    >
}

impl CertMap {
    pub fn new(certs: Vec<TestCertificate>) -> Self {
        CertMap {
            certs: certs.into_iter().map(|cert|
                (cert.name, Ok(cert))
            ).collect(),
        }
    }

    pub fn test(mut self) {
        // This is super inefficient, but it works and I don’t quite care.
        loop {
            // Find the name of the first unprocessed cert or we are done.
            let name = match self.certs.iter().find_map(|(name, value)| {
                value.as_ref().ok().map(|_| name.clone())
            }) {
                Some(name) => name,
                None => break
            };

            // Now process the cert by that name.
            self.test_cert(name);
        }
    }

    fn test_cert(&mut self, name: &'static str) {
        println!("Trying '{}'", name);
        let cert = match self.certs.get(name).unwrap() {
            Ok(cert) => cert.clone(),
            Err(_) => return, // cert has been done already.
        };
        let issuer = match cert.issuer {
            Some(issuer) => {
                self.test_cert(issuer);
                self.certs.get(
                    issuer
                ).unwrap().as_ref().unwrap_err().as_ref()
            }
            None => None
        };
        let res = cert.test(issuer, Time::now());
        self.certs.insert(name, Err(res));
    }
}


//------------ TestCertificate ----------------------------------------------

/// An encoded certificate and data needed for testing it.
#[derive(Clone, Debug)]
pub struct TestCertificate {
    /// The name of this certificate.
    ///
    /// This is used in printing information about failed tests.
    pub name: &'static str,

    /// The encoded data of the certificate.
    pub octets: DerData,

    /// If this isn’t a trust anchor, this is the name of the issuer cert.
    pub issuer: Option<&'static str>,

    /// The type of certificate.
    pub class: CertificateClass,

    /// How far testing should succeed.
    pub fail: Fail,

    /// Should we use strict mode for testing?
    pub strict: bool,
}

impl TestCertificate {
    /// Creates and signes a test certificate from the encoded TBS part.
    pub fn sign_tbs<S: Signer>(
        name: &'static str,
        tbs: DerData,
        signer: &S, key: &S::KeyId,
        issuer: Option<&'static str>,
        class: CertificateClass,
        fail: Fail,
        strict: bool,
    ) -> Self {
        let (alg, signature) = signer.sign(
            key, RpkiSignatureAlgorithm::default(), &tbs
        ).unwrap().unwrap();
        let signature = BitString::new(0, signature);
        TestCertificate {
            name,
            octets: DerData::encode(
                encode::sequence((
                    tbs, alg.x509_encode(), signature.encode()
                ))
            ),
            issuer, class, fail, strict,
        }
    }

    /// Tests decoding and validating the certificate.
    pub fn test(
        self, issuer: Option<&ResourceCert>, now: Time,
    ) -> Option<ResourceCert> {
        let cert = match (
            Cert::decode(self.octets), matches!(self.fail, Fail::Decode)
        ) {
            (Ok(_), true) => {
                panic!("{}: should have failed decoding", self.name);
            }
            (Ok(cert), false) => cert,
            (Err(_), true) => return None,
            (Err(err), false) => {
                panic!("{}: decoding failed: {}", self.name, err);
            }
        };
        
        match self.class {
            CertificateClass::Ta => {
                match (
                    cert.inspect_ta(self.strict),
                    matches!(self.fail, Fail::Inspect)
                ) {
                    (Ok(()), true) => {
                        panic!(
                            "{}: should have failed inspection.",
                            self.name
                        );
                    }
                    (Ok(()), false) => { }
                    (Err(_), true) => return None,
                    (Err(err), false) => {
                        panic!("{}: inspection failed: {}", self.name, err);
                    }
                }
                match (
                    cert.verify_ta_at(
                        TalInfo::from_name("foo".into()).into_arc(),
                        self.strict, now
                    ),
                    matches!(self.fail, Fail::Verify)
                ) {
                    (Ok(_), true) => {
                        panic!(
                            "{}: should have failed verification.",
                            self.name
                        );
                    }
                    (Ok(res), false) => Some(res),
                    (Err(_), true) => None,
                    (Err(err), false) => {
                        panic!(
                            "{}: verification failed: {}",
                            self.name, err
                        );
                    }
                }
            }
            CertificateClass::Ca => {
                match (
                    cert.inspect_ca(self.strict),
                    matches!(self.fail, Fail::Inspect)
                ) {
                    (Ok(()), true) => {
                        panic!(
                            "{}: should have failed inspection.",
                            self.name
                        );
                    }
                    (Ok(()), false) => { }
                    (Err(_), true) => return None,
                    (Err(err), false) => {
                        panic!("{}: inspection failed: {}", self.name, err);
                    }
                }
                match (
                    cert.verify_ca_at(
                        issuer.unwrap(), self.strict, now
                    ),
                    matches!(self.fail, Fail::Verify)
                ) {
                    (Ok(_), true) => {
                        panic!(
                            "{}: should have failed verification.",
                            self.name
                        );
                    }
                    (Ok(res), false) => Some(res),
                    (Err(_), true) => None,
                    (Err(err), false) => {
                        panic!(
                            "{}: verification failed: {}",
                            self.name, err
                        );
                    }
                }
            }
            CertificateClass::Ee => {
                match (
                    cert.inspect_ee(self.strict),
                    matches!(self.fail, Fail::Inspect)
                ) {
                    (Ok(()), true) => {
                        panic!(
                            "{}: should have failed inspection.",
                            self.name
                        );
                    }
                    (Ok(()), false) => { }
                    (Err(_), true) => return None,
                    (Err(err), false) => {
                        panic!("{}: inspection failed: {}", self.name, err);
                    }
                }
                match (
                    cert.verify_ee_at(
                        issuer.unwrap(), self.strict, now
                    ),
                    matches!(self.fail, Fail::Verify)
                ) {
                    (Ok(_), true) => {
                        panic!(
                            "{}: should have failed verification.",
                            self.name
                        );
                    }
                    (Ok(res), false) => Some(res),
                    (Err(_), true) => None,
                    (Err(err), false) => {
                        panic!(
                            "{}: verification failed: {}",
                            self.name, err
                        );
                    }
                }
            }
            CertificateClass::DetachedEe => {
                match (
                    cert.inspect_detached_ee(self.strict),
                    matches!(self.fail, Fail::Inspect)
                ) {
                    (Ok(()), true) => {
                        panic!(
                            "{}: should have failed inspection.",
                            self.name
                        );
                    }
                    (Ok(()), false) => { }
                    (Err(_), true) => return None,
                    (Err(err), false) => {
                        panic!("{}: inspection failed: {}", self.name, err);
                    }
                }
                match (
                    cert.verify_ee_at(
                        issuer.unwrap(), self.strict, now
                    ),
                    matches!(self.fail, Fail::Verify)
                ) {
                    (Ok(_), true) => {
                        panic!(
                            "{}: should have failed verification.",
                            self.name
                        );
                    }
                    (Ok(res), false) => Some(res),
                    (Err(_), true) => None,
                    (Err(err), false) => {
                        panic!(
                            "{}: verification failed: {}",
                            self.name, err
                        );
                    }
                }
            }
            CertificateClass::Router => {
                match (
                    cert.inspect_router(self.strict),
                    matches!(self.fail, Fail::Inspect)
                ) {
                    (Ok(()), true) => {
                        panic!(
                            "{}: should have failed inspection.",
                            self.name
                        );
                    }
                    (Ok(()), false) => { }
                    (Err(_), true) => return None,
                    (Err(err), false) => {
                        panic!("{}: inspection failed: {}", self.name, err);
                    }
                }
                match (
                    cert.verify_router_at(
                        issuer.unwrap(), self.strict, now
                    ),
                    matches!(self.fail, Fail::Verify)
                ) {
                    (Ok(_), true) => {
                        panic!(
                            "{}: should have failed verification.",
                            self.name
                        );
                    }
                    (Ok(_), false) | (Err(_), true) => None,
                    (Err(err), false) => {
                        panic!(
                            "{}: verification failed: {}",
                            self.name, err
                        );
                    }
                }
            }
        }
    }
}


/// The type of a certificate.
///
/// This releates to the various options to inspect and verify a certificate.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum CertificateClass {
    Ta,
    Ca,
    Ee,
    DetachedEe,
    Router
}

/// Should the certificate fail testing and if so when?
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum Fail {
    Decode,
    Inspect,
    Verify,
    None
}


//------------ TbsBuilder ---------------------------------------------------

/// Helps creating the TBS portion of a certficate.
pub struct TbsBuilder {
    version: Option<DerData>,
    serial_number: Option<DerData>,
    signature: DerData,
    issuer: Option<DerData>,
    validity: DerData,
    subject: Option<DerData>,
    subject_public_key_info: Option<DerData>,
    issuer_unique_id: Option<DerData>,
    subject_unique_id: Option<DerData>,
    extensions: Option<Vec<DerData>>,
}

impl Default for TbsBuilder {
    fn default() -> Self {
        TbsBuilder {
            version: None,
            serial_number: None,
            signature: DerData::encode(
                RpkiSignatureAlgorithm::default().x509_encode()
            ),
            issuer: None,
            validity: DerData::encode(
                encode::sequence((
                    Time::five_minutes_ago().encode_varied(),
                    Time::next_year().encode_varied()
                ))
            ),
            subject: None,
            subject_public_key_info: None,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        }
    }
}

impl TbsBuilder {
    pub fn v3(
    ) -> Self {
        TbsBuilder {
            version: Some(DerData::encode(2u8.encode())),
            .. Default::default()
        }
    }

    pub fn finalize(self) -> DerData {
        DerData::encode(encode::sequence((
            self.version.map(|ver| encode::sequence_as(Tag::CTX_0, ver)),
            self.serial_number.unwrap(),
            self.signature,
            self.issuer.unwrap(),
            self.validity,
            self.subject.unwrap(),
            self.subject_public_key_info.unwrap(),
            self.issuer_unique_id.map(|id| {
                encode::sequence_as(Tag::CTX_1, id)
            }),
            self.subject_unique_id.map(|id| {
                encode::sequence_as(Tag::CTX_2, id)
            }),
            self.extensions.map(|ext| {
                encode::sequence_as(Tag::CTX_3, encode::sequence(ext))
            }),
        )))
    }
}

#[allow(dead_code)]
impl TbsBuilder {
    pub fn version(mut self, version: u128) -> Self {
        self.version = Some(DerData::encode(version.encode()));
        self
    }

    pub fn serial_number(mut self, bits: &[u8]) -> Self {
        self.serial_number = Some(DerData::encode(
            Unsigned::from_slice(bits).unwrap().encode()
        ));
        self
    }

    pub fn rpki_signature_no_null(mut self) -> Self {
        self.signature = DerData::encode(
            encode::sequence(oid::SHA256_WITH_RSA_ENCRYPTION.encode())
        );
        self
    }
    
    pub fn issuer(mut self, issuer: DerData) -> Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn validity(mut self, not_before: Time, not_after: Time) -> Self {
        self.validity = DerData::encode(
            encode::sequence((
                not_before.encode_varied(), not_after.encode_varied()
            ))
        );
        self
    }
    
    pub fn subject(mut self, subject: DerData) -> Self {
        self.subject = Some(subject);
        self
    }

    pub fn public_key(mut self, key: PublicKey) -> Self {
        self.subject_public_key_info = Some(DerData::encode(key.encode()));
        self
    }

    pub fn empty_extensions(mut self) -> Self {
        self.extensions = Some(Vec::new());
        self
    }

    pub fn extension(mut self, extension: DerData) -> Self {
        self.extensions.get_or_insert_with(Vec::new).push(extension.into());
        self
    }

    fn encoded_extension(
        self, oid: ConstOid, critical: bool, value: DerData
    ) -> Self {
        self.extension(
            DerData::encode(
                encode::sequence((
                    oid.encode(),
                    if critical { Some(true.encode()) } else { None },
                    OctetString::new(value.0).encode()
                ))
            )
        )
    }

    pub fn basic_constraints(self, ca: bool) -> Self {
        self.encoded_extension(
            oid::CE_BASIC_CONSTRAINTS, true,
            DerData::encode(
                encode::sequence(
                    if ca { Some(true.encode()) } else { None }
                )
            )
        )
    }

    pub fn subject_key_id(self, key: PublicKey) -> Self {
        self.encoded_extension(
            oid::CE_SUBJECT_KEY_IDENTIFIER, false,
            DerData::encode(key.key_identifier().encode())
        )
    }

    pub fn authority_key_id(self, key: PublicKey) -> Self {
        self.encoded_extension(
            oid::CE_AUTHORITY_KEY_IDENTIFIER, false,
            DerData::encode(
                encode::sequence(
                    key.key_identifier().encode_as(Tag::CTX_0)
                )
            )
        )
    }

    pub fn key_usage(self, usage: KeyUsage) -> Self {
        self.encoded_extension(
            oid::CE_KEY_USAGE, true,
            DerData::encode(usage.encode())
        )
    }

    pub fn extended_key_usage(self, oids: &[ConstOid]) -> Self {
        self.encoded_extension(
            oid::CE_EXTENDED_KEY_USAGE, false,
            DerData::encode(
                encode::sequence(
                    encode::iter(
                        oids.iter().map(|oid| oid.encode())
                    )
                )
            )
        )
    }

    pub fn crl_uri(self, uri: &str) -> Self {
        self.encoded_extension(
            oid::CE_CRL_DISTRIBUTION_POINTS, false,
            DerData::encode(
                // XXX This may not be correct ...
                encode::sequence(
                    encode::sequence(
                        encode::sequence_as(Tag::CTX_0,
                            encode::sequence_as(Tag::CTX_0,
                                uri_general_name(uri)
                            )
                        )
                    )
                )
            )
        )
    }

    pub fn authority_info_access(
        self, access: &[(ConstOid, DerData)]
    ) -> Self {
        self.encoded_extension(
            oid::PE_AUTHORITY_INFO_ACCESS, false,
            DerData::encode(
                encode::sequence(
                    encode::iter(access.iter().map(|(oid, data)| {
                        encode::sequence((oid.encode(), data))
                    }))
                )
            )
        )
    }

    pub fn rpki_authority_info_access(self, ca_issuer: &str) -> Self {
        self.authority_info_access(&[
            (oid::AD_CA_ISSUERS, uri_general_name(ca_issuer))
        ])
    }

    pub fn subject_info_access(
        self, access: &[(ConstOid, DerData)]
    ) -> Self {
        self.encoded_extension(
            oid::PE_SUBJECT_INFO_ACCESS, false,
            DerData::encode(
                encode::sequence(
                    encode::iter(access.iter().map(|(oid, data)| {
                        encode::sequence((oid.encode(), data))
                    }))
                )
            )
        )
    }

    pub fn rpki_ca_subject_info_access(
        self, ca_repository: &str, manifest: &str
    ) -> Self {
        self.subject_info_access(&[
            (oid::AD_CA_REPOSITORY, uri_general_name(ca_repository)),
            (oid::AD_RPKI_MANIFEST, uri_general_name(manifest))
        ])
    }

    pub fn rpki_ee_subject_info_access(
        self, signed_object: &str
    ) -> Self {
        self.subject_info_access(&[
            (oid::AD_SIGNED_OBJECT, uri_general_name(signed_object)),
        ])
    }

    pub fn certificate_policies(self, policies: &[DerData]) -> Self {
        self.encoded_extension(
            oid::CE_CERTIFICATE_POLICIES, true,
            DerData::encode(
                encode::sequence(
                    encode::iter(policies.iter())
                )
            )
        )
    }

    pub fn rpki_cert_policies(self) -> Self {
        self.certificate_policies(
            &[
                DerData::encode(
                    encode::sequence(
                        oid::CP_IPADDR_ASNUMBER.encode()
                    )
                )
            ]
        )
    }

    pub fn ip_resources(
        self, v4: Option<DerData>, v6: Option<DerData>
    ) -> Self {
        self.encoded_extension(
            oid::PE_IP_ADDR_BLOCK, true,
            DerData::encode(
                encode::sequence((
                    v4.map(|v4| {
                        encode::sequence((
                            OctetString::encode_slice(b"\x00\x01"),
                            v4
                        ))
                    }),
                    v6.map(|v6| {
                        encode::sequence((
                            OctetString::encode_slice(b"\x00\x02"),
                            v6
                        ))
                    }),
                ))
            )
        )
    }

    pub fn as_resources(self, res: DerData) -> Self {
        self.encoded_extension(
            oid::PE_AUTONOMOUS_SYS_IDS, true,
            DerData::encode(
                encode::sequence(
                    encode::sequence_as(Tag::CTX_0, res)
                )
            )
        )
    }
}


//----------- Helper functions for Certificate Components -------------------

pub fn rpki_name(cn: &str, sn: Option<&str>) -> DerData {
    DerData::encode(
        encode::sequence( // RDNSequence
            encode::set((
                encode::sequence(( // commonName
                    oid::AT_COMMON_NAME.encode(),
                    PrintableString::from_string(
                        cn.into()
                    ).unwrap().encode()
                )),
                sn.map(|sn| {
                    encode::sequence(( // serialNumber
                        oid::AT_SERIAL_NUMBER.encode(),
                        PrintableString::from_string(
                            sn.into()
                        ).unwrap().encode()
                    ))
                })
            ))
        )
    )
}

pub fn uri_general_name(uri: &str) -> DerData {
    DerData::encode(
        OctetString::new(
            Bytes::copy_from_slice(uri.as_bytes())
        ).encode_as(Tag::CTX_6)
    )
}

pub fn ip_address(prefix: &str) -> DerData {
    DerData::encode(Prefix::from_str(prefix).unwrap().encode())
}

#[allow(dead_code)]
pub fn ip_range(min: &str, max: &str) -> DerData {
    DerData::encode(
        encode::sequence((
            Prefix::from_str(min).unwrap().encode(),
            Prefix::from_str(max).unwrap().encode()
        ))
    )
}

#[allow(dead_code)]
pub fn as_id(as_id: u32) -> DerData {
    DerData::encode(as_id.encode())
}

pub fn as_range(min: u32, max: u32) -> DerData {
    DerData::encode(
        encode::sequence((min.encode(), max.encode()))
    )
}


//------------ DerData ------------------------------------------------------

/// A type holding some DER encoded data for testing.
#[derive(Clone, Debug)]
pub struct DerData(Bytes);

impl DerData {
    pub fn encode(values: impl encode::Values) -> Self {
        DerData(values.to_captured(Mode::Der).into_bytes())
    }

    pub fn sequence(values: &[DerData]) -> Self {
        Self::encode(
            encode::sequence(
                encode::iter(values.iter())
            )
        )
    }
}

impl From<Captured> for DerData {
    fn from(data: Captured) -> Self {
        DerData(data.into_bytes())
    }
}

impl encode::Values for DerData {
    fn encoded_len(&self, _mode: Mode) -> usize {
        self.0.len()
    }

    fn write_encoded<W: io::Write>(
        &self, 
        _mode: Mode, 
        target: &mut W
    ) -> Result<(), io::Error> {
        target.write_all(&self.0)
    }
}

impl AsRef<[u8]> for DerData {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl IntoSource for DerData {
    type Source = <Captured as IntoSource>::Source;

    fn into_source(self) -> Self::Source {
        self.0.into_source()
    }
}

