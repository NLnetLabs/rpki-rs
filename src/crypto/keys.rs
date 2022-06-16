//! Types and parameters of keys.

use std::{error, fmt, io};
use std::convert::TryFrom;
use bcder::{decode, encode};
use bcder::{BitString, Mode, Oid, Tag};
use bcder::encode::{PrimitiveContent, Values};
use bytes::Bytes;
use ring::{digest, signature};
use ring::error::Unspecified;
use ring::signature::VerificationAlgorithm;
use untrusted::Input;
use crate::oid;
use super::signature::{RpkiSignatureAlgorithm, Signature, SignatureAlgorithm};


//------------ Re-exports ----------------------------------------------------

pub use routecore::bgpsec::KeyIdentifier;


//------------ PublicKeyFormat -----------------------------------------------

/// The formats of public keys used by RPKI.
///
/// The public key formats are currently defined in section 3 of [RFC 7935]
/// for resource certificates and section 3 of [RFC 8608] for BGPSec router
/// certifcates. A variant is defined for each algorithm described in these
/// documents.
///
/// [RFC 7935]: https://tools.ietf.org/html/rfc7935
/// [RFC 8608]: https://tools.ietf.org/html/rfc8608
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicKeyFormat {
    /// An RSA public key.
    ///
    /// These keys must be used by all RPKI resource certificates.
    Rsa,

    /// An ECDSA public key for the P-256 elliptic curve.
    ///
    /// These keys must be used by all BGPSec router certificates.
    EcdsaP256,
}

impl PublicKeyFormat {
    /// Returns whether the format is acceptable for RPKI-internal certificates.
    ///
    /// RPKI-internal certificates in this context are those used within the
    /// repository itself, i.e., CA certificates and EE certificates for
    /// signed objects.
    pub fn allow_rpki_cert(self) -> bool {
        matches!(self, PublicKeyFormat::Rsa)
    }

    /// Returns whether the format is acceptable for router certificates.
    pub fn allow_router_cert(self) -> bool {
        matches!(self, PublicKeyFormat::EcdsaP256)
    }
}


/// # ASN.1 Algorithm Identifiers
///
/// The format of the public key is identified in certificates through a
/// algorithm identifier defined with this ASN.1:
///
/// ```txt
/// AlgorithmIdentifier ::= SEQUENCE {
///      algorithm          OBJECT IDENTIFIER,
///      parameters         ANY DEFINED BY algorithm OPTIONAL }
/// ```
///
/// The functions and methods in this section allow decoding and encoding of
/// these identifiers.
///
/// For RSA keys, the object identifier needs to be that of `rsaEncryption`
/// defined by [RFC 4055] and the parameters must be present and NULL.
/// When parsing, we generously also allow it to be absent altogether.
///
/// For ECDSA keys, the object identifer needs to be `ecPublicKey` defined
/// in [RFC 5480] with the parameter being the object identifier `secp256r1`
/// defined in the same RFC.
///
/// [RFC 4055]: https://tools.ietf.org/html/rfc4055
/// [RFC 5480]: https://tools.ietf.org/html/rfc5480
impl PublicKeyFormat{
    /// Takes and returns a algorithm identifier.
    ///
    /// Returns a malformed error if the algorithm isn’t one of the allowed
    /// algorithms or if the value isn’t correctly encoded.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the algorithm identifier from the contents of its sequence.
    fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let alg = Oid::take_from(cons)?;
        if alg == oid::RSA_ENCRYPTION {
            cons.take_opt_null()?;
            Ok(PublicKeyFormat::Rsa)
        }
        else if alg == oid::EC_PUBLIC_KEY {
            oid::SECP256R1.skip_if(cons)?;
            Ok(PublicKeyFormat::EcdsaP256)
        }
        else {
            Err(decode::Error::Malformed.into())
        }
    }

    /// Provides an encoder for the algorihm identifier.
    pub fn encode(self) -> impl encode::Values {
        match self {
            PublicKeyFormat::Rsa => {
                encode::Choice2::One(
                    encode::sequence((
                        oid::RSA_ENCRYPTION.encode(),
                        ().encode(),
                    ))
                )
            }
            PublicKeyFormat::EcdsaP256 => {
                encode::Choice2::Two(
                    encode::sequence((
                        oid::EC_PUBLIC_KEY.encode(),
                        oid::SECP256R1.encode(),
                    ))
                )
            }
        }
    }

    fn verify(
        self,
        bits: Input<'_>,
        message: Input<'_>,
        signature: Input<'_>,
    ) -> Result<(), VerificationError> {
        match self {
            PublicKeyFormat::Rsa => {
                signature::RSA_PKCS1_2048_8192_SHA256.verify(
                    bits, message, signature
                ).map_err(Into::into)
            }
            PublicKeyFormat::EcdsaP256 => {
                signature::ECDSA_P256_SHA256_ASN1.verify(
                    bits, message, signature
                ).map_err(Into::into)
            }
        }
    }
}

impl From<RpkiSignatureAlgorithm> for PublicKeyFormat {
    fn from(_: RpkiSignatureAlgorithm) -> Self {
        PublicKeyFormat::Rsa
    }
}


//------------ PublicKey -----------------------------------------------------

/// A public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    algorithm: PublicKeyFormat,
    bits: BitString,
}


impl PublicKey {
    /// Returns the algorithm of this public key.
    pub fn algorithm(&self) -> PublicKeyFormat {
        self.algorithm
    }

    /// Returns the bits of this public key.
    pub fn bits(&self) -> &[u8] {
        // Public keys have to be DER encoded, so `octet_slice` will never
        // return `Err(_)`.
        self.bits.octet_slice().unwrap()
    }

    /// Returns the bits as a `Bytes` value.
    pub fn bits_bytes(&self) -> Bytes {
        self.bits.octet_bytes()
    }

    /// Returns whether the key is acceptable for RPKI-internal certificates.
    ///
    /// RPKI-internal certificates in this context are those used within the
    /// repository itself, i.e., CA certificates and EE certificates for
    /// signed objects.
    pub fn allow_rpki_cert(&self) -> bool {
        self.algorithm.allow_rpki_cert()
    }

    /// Returns whether the key is acceptable for BGPSec router certificates.
    pub fn allow_router_cert(&self) -> bool {
        self.algorithm.allow_router_cert()
    }

    /// Returns a key identifier for this key.
    ///
    /// The identifier will be the SHA1 hash of the key’s bits.
    pub fn key_identifier(&self) -> KeyIdentifier {
        KeyIdentifier::try_from(
            digest::digest(
                &digest::SHA1_FOR_LEGACY_USE_ONLY,
                self.bits.octet_slice().unwrap()
            ).as_ref()
        ).unwrap()
    }

    /// Verifies a signature using this public key.
    pub fn verify<Alg: SignatureAlgorithm>(
        &self, message: &[u8], signature: &Signature<Alg>
    ) -> Result<(), VerificationError> {
        if signature.algorithm().public_key_format() != self.algorithm {
            return Err(VerificationError)
        }
        self.algorithm.verify(
            Input::from(self.bits()),
            Input::from(message),
            Input::from(signature.value().as_ref())
        )
    }
}


/// # As `SubjectPublicKeyInfo`
///
/// Public keys are included in X.509 certificates as `SubjectPublicKeyInfo`
/// structures. As these contain the same information as `PublicKey`,
/// it can be decoded from and encoded to such sequences.
impl PublicKey {
    pub fn decode<S: decode::Source>(source: S) -> Result<Self, S::Err> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            Ok(PublicKey {
                algorithm: PublicKeyFormat::take_from(cons)?,
                bits: BitString::take_from(cons)?
            })
        })
    }

    pub fn encode(self) -> impl encode::Values {
        encode::sequence((
            self.algorithm.encode(),
            self.bits.encode()
        ))
    }

    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        encode::sequence((
            self.algorithm.encode(),
            self.bits.encode_ref()
        ))
    }

    pub fn encode_subject_name(&self) -> impl encode::Values + '_ {
        encode::sequence(
            encode::set(
                encode::sequence((
                    oid::AT_COMMON_NAME.encode(),
                    PublicKeyCn(self.key_identifier()).encode(),
                ))
            )
        )
    }

    #[cfg(feature = "repository")]
    pub fn to_subject_name(&self) -> crate::repository::x509::Name {
        crate::repository::x509::Name::from_captured(
            self.encode_subject_name().to_captured(Mode::Der)
        )
    }

    /// Returns a bytes values of the encoded the *subjectPublicKeyInfo*.
    pub fn to_info_bytes(&self) -> Bytes {
        self.encode_ref().to_captured(Mode::Der).into_bytes()
    }
}


//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let bytes = self.to_info_bytes();
        let b64 = base64::encode(&bytes);
        b64.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;

        let string = String::deserialize(deserializer)?;
        let decoded = base64::decode(&string).map_err(de::Error::custom)?;
        let bytes = Bytes::from(decoded);
        PublicKey::decode(bytes).map_err(de::Error::custom)
    }
}


//------------ PublicKeyCn ---------------------------------------------------

/// Value encoder for a public key as a common name.
///
/// This type encodes the key identifier of a public key in a printable string
/// as a sequence of hex digits as suggested as one option for subject names in
/// RPKI certificates by section 8 of [RFC 6487].
///
/// [RFC 6487]: https://tools.ietf.org/html/rfc6487
#[derive(Clone, Copy, Debug)]
pub struct PublicKeyCn(KeyIdentifier);

impl PrimitiveContent for PublicKeyCn {
    const TAG: Tag = Tag::PRINTABLE_STRING;

    fn encoded_len(&self, _mode: Mode) -> usize {
        self.0.as_slice().len() * 2
    }

    fn write_encoded<W: io::Write>(
        &self, 
        _mode: Mode, 
        target: &mut W
    ) -> Result<(), io::Error> {
        target.write_all(&self.0.into_hex())
    }
}


//------------ VerificationError ---------------------------------------------

/// An error happened while verifying a signature.
///
/// No further information is provided. This is on purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationError;

impl From<Unspecified> for VerificationError {
    fn from(_: Unspecified) -> Self {
        VerificationError
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("signature verification failed")
    }
}

impl error::Error for VerificationError { }


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(feature = "serde")]
    fn serde_pub_key() {
        use crate::repository::Cert;

        let der = include_bytes!("../../test-data/ta.cer");
        let cert = Cert::decode(Bytes::from_static(der)).unwrap();

        let pub_key = cert.subject_public_key_info();

        let ser = serde_json::to_string(pub_key).unwrap();
        let de: PublicKey = serde_json::from_str(&ser).unwrap();

        assert_eq!(pub_key, &de);
    }
}