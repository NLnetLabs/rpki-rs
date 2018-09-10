//! Support for building RPKI Certificates and Objects

use ber::{BitString, Mode, Tag};
use ber::encode;
use ber::encode::{Constructed, PrimitiveContent, Values};
use bytes::Bytes;
use cert::{SubjectPublicKeyInfo, Validity};
use cert::ext::Extensions;
use remote::idcert::{IdCert, IdExtensions};
use signing::SignatureAlgorithm;
use signing::signer::{KeyId, KeyUseError, Signer};
use x509::Name;


//------------ TbsCertificate ------------------------------------------------

/// The supported extension types for our RPKI TbsCertificate
pub enum RpkiTbsExtension {
    ResourceExtensions(Extensions),
    IdExtensions(IdExtensions)
}

/// This type represents the signed content part of an RPKI Certificate.
pub struct RpkiTbsCertificate {

    // The General structure is documented in section 4.1 or RFC5280
    //
    //    TBSCertificate  ::=  SEQUENCE  {
    //        version         [0]  EXPLICIT Version DEFAULT v1,
    //        serialNumber         CertificateSerialNumber,
    //        signature            AlgorithmIdentifier,
    //        issuer               Name,
    //        validity             Validity,
    //        subject              Name,
    //        subjectPublicKeyInfo SubjectPublicKeyInfo,
    //        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    //                             -- If present, version MUST be v2 or v3
    //        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    //                             -- If present, version MUST be v2 or v3
    //        extensions      [3]  EXPLICIT Extensions OPTIONAL
    //                             -- If present, version MUST be v3
    //        }
    //
    //  In the RPKI we always use Version 3 Certificates with certain
    //  extensions (SubjectKeyIdentifier in particular). issuerUniqueID and
    //  subjectUniqueID are not used.
    //

    // version is always 3
    serial_number: u32,
    // signature is always Sha256WithRsaEncryption
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    // issuerUniqueID is not used
    // subjectUniqueID is not used
    extensions: RpkiTbsExtension,
}

/// # Encoding
///
impl RpkiTbsCertificate {

    /// Encodes this certificate.
    pub fn encode<'a>(&'a self) -> impl encode::Values + 'a {

        match self.extensions {
            RpkiTbsExtension::IdExtensions(ref id_ext) => {
                encode::sequence(
                    (
                        (
                            Constructed::new(Tag::CTX_0, 2.value()), // Version 3 is encoded as 2
                            self.serial_number.value(),
                            SignatureAlgorithm::Sha256WithRsaEncryption.encode(),
                            self.issuer.encode(),
                        ),
                        (
                            self.validity.encode(),
                            self.subject.encode(),
                            self.subject_public_key_info.encode(),
                            id_ext.encode()
                        )
                    )
                )
            },
            RpkiTbsExtension::ResourceExtensions(ref _ext) => {
                unimplemented!()
            }
        }
    }
}

/// # Creating
///
impl RpkiTbsCertificate {
    pub fn new(
        serial_number: u32,
        issuer: Name,
        validity: Validity,
        subject: Name,
        subject_public_key_info: SubjectPublicKeyInfo,
        extensions: RpkiTbsExtension
    ) -> Self {
        Self {
            serial_number,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions
        }
    }
}

//------------ IdCertBuilder -------------------------------------------------

/// An IdCertBuilder to be used with the Signer trait.
pub struct IdCertBuilder;

impl IdCertBuilder {
    /// Creates an IdCertBuilder to be signed with the Signer trait.
    ///
    /// There is some magic here. Since we always use a structure where we
    /// have one self-signed CA certificate used as identity trust anchors,
    /// or EE certificates signed directly below this, we can make some
    /// assumptions and save on method parameters.
    ///
    /// If the issuing_key and the subject_key are the same we will assume
    /// that this is for a self-signed CA (TA even) certificate. So we will
    /// set the appropriate extensions: basic_ca and subject_key_id, but no
    /// authority_key_id.
    ///
    /// If the issuing_key and the subject_key are different then we will use
    /// the extensions: subject_key_id and authority_key_id, but no basic_ca.
    fn make_tbs_certificate_request(
        serial_number: u32,
        duration: ::chrono::Duration,
        issuing_key: &SubjectPublicKeyInfo,
        subject_key: &SubjectPublicKeyInfo,
        ext: IdExtensions
    ) -> RpkiTbsCertificate
    {
        let issuer = Name::from_pub_key(issuing_key);
        let validity = Validity::from_duration(duration);
        let subject = Name::from_pub_key(subject_key);

        RpkiTbsCertificate {
            serial_number,
            issuer,
            validity,
            subject,
            subject_public_key_info: subject_key.clone(),
            extensions: RpkiTbsExtension::IdExtensions(ext)
        }
    }

    /// Creates a new TA IdCertSignRequest to be used with the Signer trait.
    ///
    /// Essentially this all the content that goes into the SignedData
    /// component.
    pub fn new_ta_id_cert(
        key_id: &KeyId,
        signer: &mut impl Signer
    ) -> Result<IdCert, KeyUseError> {

        let key = signer.get_key_info(key_id)?;

        let ext = IdExtensions::for_id_ta_cert(&key);
        let dur = ::chrono::Duration::weeks(52000);

        let tbs = Self::make_tbs_certificate_request(
            1,
            dur,
            &key,
            &key,
            ext
        );

        let enc_cert = tbs.encode();

        let mut v = Vec::new();
        enc_cert.write_encoded(Mode::Der, & mut v)?;
        let bytes = Bytes::from(v);


        let signature = BitString::new(
            0,
            signer.sign(key_id, &bytes)?.to_bytes()
        );

        let mut v = Vec::new();

        encode::sequence (
            (
                enc_cert,
                SignatureAlgorithm::Sha256WithRsaEncryption.encode(),
                signature.encode()
            )
        ).write_encoded(Mode::Der, &mut v)?;

        let b = Bytes::from(v);

        let id_cert = IdCert::decode(b)?;

        Ok(id_cert)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "softkeys")]
pub mod tests {

    use super::*;
    use signing::softsigner::OpenSslSigner;
    use signing::PublicKeyAlgorithm;

    #[test]
    fn should_create_self_signed_ta_id_cert() {
        let mut s = OpenSslSigner::new();
        let key_id = s.create_key(&PublicKeyAlgorithm::RsaEncryption).unwrap();

        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, & mut s).unwrap();
        id_cert.validate_ta().unwrap();
    }
}


