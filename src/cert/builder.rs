
use bcder::encode;
use bcder::{BitString, Captured, ConstOid, Mode, OctetString, Tag};
use bcder::encode::PrimitiveContent;
use crate::crypto::{PublicKey, SignatureAlgorithm, Signer, SigningError};
use crate::oid;
use crate::resources::{
    AsBlocksBuilder, AsResourcesBuilder, IpBlocksBuilder, IpResources,
    IpResourcesBuilder
};
use crate::uri;
use crate::x509::Name;
use super::Validity;


#[derive(Clone, Debug)]
pub struct CertBuilder {
    //  The following lists how all the parts to go into the final certificate
    //  are to be generated. It also mentions all the parts that don’t need to
    //  be stored in the builder.

    //--- Certificate
    //
    //  tbsCertificate: see below,
    //  signatureAlgorithm and signature: generated when signing the final
    //     certificate

    //--- TBSCertificate

    //  Version.
    //
    //  This is always present and v3, which really is 2.

    /// Serial number.
    ///
    /// This is required for all certificates. The standard demands twenty
    /// digits, u128 gives us 38, so this should be fine.
    serial_number: u128,

    /// Signature.
    ///
    /// This is the signature algorithm and must be identical to the one used
    /// on the outer value. Thus, it needs to be set when constructing the
    /// certifcate for signing.

    /// Issuer.
    ///
    /// This needs to be identical to the subject of the issuing certificate.
    /// It needs to be presented when creating the builder.
    issuer: Name,    

    /// Validity.
    ///
    /// This needs to be present for all certificates.
    validity: Validity,

    /// Subject.
    ///
    /// This needs to be present for all certifications. In RPKI, we commonly
    /// derive the name from the public key of the certificate, so this is an
    /// option. If it is not set explicitely, we derive the name.
    subject: Option<Name>, // XXX NameBuilder?

    /// Subject Public Key Info
    ///
    /// This is required for all certificates. However, because we sometimes
    /// use one-off certificates that only receive their key info very late
    /// in the process, we won’t store the key info but take it as an
    /// argument for encoding.

    //  Issuer Unique ID, Subject Unique ID
    //
    //  These must not be present.

    //--- Extensions

    /// Basic Constraints
    ///
    /// Needs to be present and critical and the cA boolean set to true for
    /// a CA and TA certificate. We simply remember whether we are making a
    /// CA certificate here.
    ca: bool,

    //  Subject Key Identifier
    //
    //  Must be present and non-critical. It is the SHA1 of the BIT STRING
    //  of the Subject Public Key, so we take it from
    //  subject_public_key_info.

    /// Authority Key Identifier
    ///
    /// Must be present except in trust-anchor certificates and non-critical.
    /// It must contain the subject key identifier of issuing certificate.
    authority_key_identifier: Option<OctetString>, 

    //  Key Usage.
    //
    //  Must be present and critical. For CA certificates, keyCertSign and
    //  CRLSign are set, for EE certificates, digitalSignature bit is set.

    //  Extended Key Usage
    //
    //  This is only allowed in router keys. For now, we will not support
    //  this.
    
    /// CRL Distribution Points
    ///
    /// Must be present and non-critical except in self-signed certificates.
    /// For RPKI it is very restricted and boils down to a list of URIs. Most
    /// likely, it will be exactly one. So for now, we allow at most one.
    crl_distribution: Option<uri::Rsync>,

    /// Authority Information Access
    ///
    /// Except for self-signed certificates, must be present and non-critical.
    /// There must be one rsync URI as a id-ad-caIssuer. Additional URIs may
    /// be present, but we don’t support that as of now.
    authority_info_access: Option<uri::Rsync>,

    //  Subject Information Access
    // 
    //  Must be present and non-critical. There are essentially three
    //  access methods that may be present. id-ad-rpkiManifest points to the
    //  manifest of a CA, id-ad-signedObject points to the signed object of
    //  an EE certificate. id-ad-rpkiNotify points to the RRDP notification
    //  file of a CA. We only support one of each and simply add whatever is
    //  there.

    /// Subject Information Access of type `id-ad-rpkiManifest`
    rpki_manifest: Option<uri::Rsync>,

    /// Subject Information Access of type `id-ad-signedObject`
    signed_object: Option<uri::Rsync>,

    /// Subject Information Access of type `id-ad-rpkiNotify`
    rpki_notify: Option<uri::Http>,

    //  Certificate Policies
    //
    //  This contains a single policy, id-cp-ipAddr-asNumber, without any
    //  qualifiers.

    /// IPv4 Resources
    ///
    /// One of the resources must be present. The IPv4 resources are part of
    /// the IP resources which, if present, it must be critical.
    v4_resources: IpResourcesBuilder,

    /// IPv6 Resources
    ///
    /// One of the resources must be present. The IPv4 resources are part of
    /// the IP resources which, if present, it must be critical.
    v6_resources: IpResourcesBuilder,

    /// AS Resources
    ///
    /// If present, it must be critical. One of the resources must be
    /// present.
    as_resources: AsResourcesBuilder,
}

impl CertBuilder {
    pub fn new(
        serial_number: u128,
        issuer: Name,
        validity: Validity,
        ca: bool
    ) -> Self {
        CertBuilder {
            serial_number,
            issuer,
            validity,
            subject: None,
            ca,
            authority_key_identifier: None,
            crl_distribution: None,
            authority_info_access: None,
            rpki_manifest: None,
            signed_object: None,
            rpki_notify: None,
            v4_resources: IpResourcesBuilder::new(),
            v6_resources: IpResourcesBuilder::new(),
            as_resources: AsResourcesBuilder::new(),
        }
    }

    pub fn subject(&mut self, name: Name) -> &mut Self {
        self.subject = Some(name);
        self
    }

    pub fn authority_key_identifier(
        &mut self, id: OctetString
    ) -> &mut Self {
        self.authority_key_identifier = Some(id);
        self
    }

    pub fn crl_distribution(&mut self, uri: uri::Rsync) -> &mut Self {
        self.crl_distribution = Some(uri);
        self
    }

    pub fn authority_info_access(&mut self, uri: uri::Rsync) -> &mut Self {
        self.authority_info_access = Some(uri);
        self
    }

    pub fn rpki_manifest(&mut self, uri: uri::Rsync) -> &mut Self {
        self.rpki_manifest = Some(uri);
        self
    }

    pub fn signed_object(&mut self, uri: uri::Rsync) -> &mut Self {
        self.signed_object = Some(uri);
        self
    }

    pub fn rpki_notify(&mut self, uri: uri::Http) -> &mut Self {
        self.rpki_notify = Some(uri);
        self
    }

    pub fn inherit_v4(&mut self) -> &mut Self {
        self.v4_resources.inherit();
        self
    }

    pub fn inherit_v6(&mut self) -> &mut Self {
        self.v6_resources.inherit();
        self
    }

    pub fn inherit_as(&mut self) -> &mut Self {
        self.as_resources.inhert();
        self
    }

    pub fn v4_blocks<F>(&mut self, build: F) -> &mut Self
    where F: FnOnce(&mut IpBlocksBuilder) {
        self.v4_resources.blocks(build);
        self
    }

    pub fn v6_blocks<F>(&mut self, build: F) -> &mut Self
    where F: FnOnce(&mut IpBlocksBuilder) {
        self.v6_resources.blocks(build);
        self
    }

    pub fn as_blocks<F>(&mut self, build: F) -> &mut Self
    where F: FnOnce(&mut AsBlocksBuilder) {
        self.as_resources.blocks(build);
        self
    }
    
    /// Finalizes the certificate and returns an encoder for it.
    pub fn encode<S: Signer>(
        self,
        signer: &S,
        key: &S::KeyId,
        alg: SignatureAlgorithm,
        public_key: &PublicKey,
    ) -> Result<impl encode::Values, SigningError<S::Error>> {
        let tbs_cert = self.encode_tbs_cert(alg, public_key);
        let (alg, signature) = signer.sign(key, alg, &tbs_cert)?.unwrap();
        Ok(encode::sequence((
            tbs_cert,
            alg.x509_encode(),
            BitString::new(0, signature).encode()
        )))
    }

    fn encode_tbs_cert(
        mut self,
        alg: SignatureAlgorithm,
        public_key: &PublicKey,
    ) -> Captured {
        if self.subject.is_none() {
            self.subject = Some(Name::from_pub_key(public_key))
        }
        Captured::from_values(Mode::Der, encode::sequence((
            encode::sequence_as(Tag::CTX_0, 2.encode()), // version
            self.serial_number.encode(),
            alg.x509_encode(),
            self.issuer.encode(),
            self.validity.encode(),
            match self.subject.as_ref() {
                Some(subject) => encode::Choice2::One(subject.encode()),
                None => {
                    encode::Choice2::Two(
                        public_key.encode_subject_name()
                    )
                }
            },
            public_key.encode(),
            // no issuerUniqueID, no subjectUniqueID
            encode::sequence_as(Tag::CTX_3, encode::sequence((
                // Basic Constraints
                if self.ca {
                    Some(extension(
                        &oid::CE_BASIC_CONSTRAINTS, true,
                        encode::sequence(true.encode())
                    ))
                }
                else { None },

                // Subject Key Identifier
                extension(
                    &oid::CE_SUBJECT_KEY_IDENTIFIER, false,
                    OctetString::encode_slice(
                        public_key.key_identifier()
                    )
                ),

                // Authority Key Identifier
                self.authority_key_identifier.as_ref().map(|id| {
                    extension(
                        &oid::CE_AUTHORITY_KEY_IDENTIFIER, false,
                        encode::sequence(id.encode_ref_as(Tag::CTX_0))
                    )
                }),

                // Key Usage
                extension(
                    &oid::CE_KEY_USAGE, true,
                    if self.ca {
                        // Bits 5 and 6 must be set.
                        b"\x01\x06".encode_as(Tag::BIT_STRING)
                    }
                    else {
                        // Bit 0 must be set.
                        b"\x07\x80".encode_as(Tag::BIT_STRING)
                    }
                ),

                // Extented Key Usage: currently not supported.

                // CRL Distribution Points
                self.crl_distribution.as_ref().map(|uri| {
                    extension(
                        &oid::CE_CRL_DISTRIBUTION_POINTS, false,
                        encode::sequence( // CRLDistributionPoints
                            encode::sequence( // DistributionPoint
                                encode::sequence_as(Tag::CTX_0, // distrib.Pt.
                                    encode::sequence_as(Tag::CTX_0, // fullName
                                        encode::sequence( // GeneralNames
                                            uri.encode_general_name()
                                        )
                                    )
                                )
                            )
                        )
                    )
                }),

                // Authority Inforamtion Access
                self.authority_info_access.as_ref().map(|uri| {
                    extension(
                        &oid::PE_AUTHORITY_INFO_ACCESS, false,
                        encode::sequence(
                            encode::sequence((
                                oid::AD_CA_ISSUERS.encode(),
                                uri.encode_general_name()
                            ))
                        )
                    )
                }),

                // Subject Information Access
                extension(
                    &oid::PE_SUBJECT_INFO_ACCESS, false,
                    encode::sequence((
                        self.rpki_manifest.as_ref().map(|uri| {
                            encode::sequence((
                                oid::AD_RPKI_MANIFEST.encode(),
                                uri.encode_general_name()
                            ))
                        }),
                        self.signed_object.as_ref().map(|uri| {
                            encode::sequence((
                                oid::AD_SIGNED_OBJECT.encode(),
                                uri.encode_general_name()
                            ))
                        }),
                        self.rpki_notify.as_ref().map(|uri| {
                            encode::sequence((
                                oid::AD_RPKI_NOTIFY.encode(),
                                uri.encode_general_name()
                            ))
                        })
                    ))
                ),

                // Certificate Policies
                extension(
                    &oid::CE_CERTIFICATE_POLICIES, true,
                    encode::sequence(
                        encode::sequence(
                            oid::CP_IPADDR_ASNUMBER.encode()
                        )
                    )
                ),

                // IP Resources
                IpResources::encode_families(
                    self.v4_resources.finalize(),
                    self.v6_resources.finalize()
                ).map(|res| {
                    extension(&oid::PE_IP_ADDR_BLOCK, true, res)
                }),

                // AS Resources
                self.as_resources.finalize().map(|res| {
                    extension(&oid::PE_AUTONOMOUS_SYS_IDS, true, res.encode())
                })
            )))
        )))
    }
}


fn extension<V: encode::Values>(
    oid: &'static ConstOid,
    critical: bool,
    content: V
) -> impl encode::Values {
    encode::sequence((
        oid.encode(),
        critical.encode(),
        OctetString::encode_wrapped(Mode::Der, content)
    ))
}


//============ Test ==========================================================

#[cfg(test)]
mod test {
}

#[cfg(all(test, feature="softkeys"))]
mod signer_test {
    use bcder::encode::Values;
    use crate::cert::Cert;
    use crate::crypto::PublicKeyFormat;
    use crate::crypto::softsigner::OpenSslSigner;
    use crate::resources::{AsId, Prefix};
    use crate::tal::TalInfo;
    use super::*;
        
    #[test]
    fn ta_cert() {
        let mut signer = OpenSslSigner::new();
        let key = signer.create_key(PublicKeyFormat).unwrap();
        let pubkey = signer.get_key_info(&key).unwrap();
        let uri = uri::Rsync::from_str("rsync://example.com/m/p").unwrap();

        let mut builder = CertBuilder::new(
            12, pubkey.to_subject_name(), Validity::from_secs(86400), true
        );
        builder
            .rpki_manifest(uri.clone())
            .v4_blocks(|blocks| blocks.push(Prefix::new(0, 0)))
            .as_blocks(|blocks| blocks.push((AsId::MIN, AsId::MAX)));
        let captured = builder.encode(
            &signer, &key, SignatureAlgorithm, &pubkey
        ).unwrap().to_captured(Mode::Der);
        let cert = Cert::decode(captured.as_slice()).unwrap();
        let talinfo = TalInfo::from_name("foo".into()).into_arc();
        cert.validate_ta(talinfo, true).unwrap();
    }
}

