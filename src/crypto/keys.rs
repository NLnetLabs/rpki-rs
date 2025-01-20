//! Types and parameters of keys.

use std::{error, fmt, io, str};
use std::convert::Infallible;
use std::str::FromStr;
use bcder::{decode, encode};
use bcder::{BitString, Mode, Oid, Tag};
use bcder::decode::{ContentError, DecodeError, Source};
use bcder::int::{InvalidInteger, Unsigned};
use bcder::encode::{PrimitiveContent, Values};
use bytes::Bytes;
use ring::{digest, signature};
use ring::error::Unspecified;
use ring::signature::VerificationAlgorithm;
use untrusted::Input;
use crate::oid;
#[cfg(feature = "serde")] use crate::util::base64;
use crate::util::hex;
use super::signature::{RpkiSignatureAlgorithm, Signature, SignatureAlgorithm};


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
/// For ECDSA keys, the object identifier needs to be `ecPublicKey` defined
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
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::from_constructed)
    }

    /// Parses the algorithm identifier from the contents of its sequence.
    fn from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
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
            Err(cons.content_err("invalid public key format"))
        }
    }

    /// Provides an encoder for the algorithm identifier.
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
    ) -> Result<(), SignatureVerificationError> {
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
    /// Creates an RSA Public Key based on the supplied exponent and modulus.
    /// 
    /// See:
    /// [RFC 4055]: <https://tools.ietf.org/html/rfc4055>
    /// 
    /// An RSA Public Key uses the following DER encoded structure inside its
    /// BitString component:
    /// 
    /// ```txt
    /// RSAPublicKey  ::=  SEQUENCE  {
    ///     modulus            INTEGER,    -- n
    ///     publicExponent     INTEGER  }  -- e
    /// ```
    pub fn rsa_from_components(
        modulus: &[u8], // n
        exponent: &[u8] // e 
    ) -> Result<Self, InvalidInteger> {
        let modulus = Unsigned::from_slice(modulus)?;
        let exponent = Unsigned::from_slice(exponent)?;

        let pub_key_sequence = encode::sequence((
            modulus.encode(),
            exponent.encode()
        ));

        Ok(PublicKey {
            algorithm: PublicKeyFormat::Rsa,
            bits: BitString::new(
                0,
                pub_key_sequence.to_captured(Mode::Der).into_bytes()
            ),
        })
    }

    /// Creates an RSA public key from the key’s bits.
    ///
    /// Note that this is _not_ the DER-encoded public key written by, for
    /// instance, the OpenSSL command line tools. These files contain the
    /// complete public key including the algorithm and need to be read
    /// with [`PublicKey::decode`].
    pub fn rsa_from_bits_bytes(
        bytes: Bytes
    ) -> Result<Self, DecodeError<Infallible>> {
        Mode::Der.decode(bytes.clone(), |cons| {
            cons.take_sequence(|cons| {
                let _ = bcder::Unsigned::take_from(cons)?;
                let _ = bcder::Unsigned::take_from(cons)?;
                Ok(())
            })
        })?;
        Ok(PublicKey {
            algorithm: PublicKeyFormat::Rsa,
            bits: BitString::new(0, bytes)
        })
    }
    
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
    ) -> Result<(), SignatureVerificationError> {
        if signature.algorithm().public_key_format() != self.algorithm {
            return Err(SignatureVerificationError(()))
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
    pub fn decode<S: decode::IntoSource>(
        source: S
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
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
    ///
    /// This returns a newly “allocated” bytes object.
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
        let b64 = base64::Serde.encode(&bytes);
        b64.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        use serde::de;
        use bcder::decode::IntoSource;

        let s = String::deserialize(deserializer)?;
        let decoded = base64::Serde.decode(&s).map_err(de::Error::custom)?;
        let bytes = Bytes::from(decoded);
        PublicKey::decode(bytes.into_source()).map_err(de::Error::custom)
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


//------------ KeyIdentifier -------------------------------------------------

/// A key identifier.
///
/// This is the SHA-1 hash over the public key’s bits.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct KeyIdentifier([u8; 20]);

impl KeyIdentifier {
    /// Returns an octet slice of the key identifier’s value.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Returns a octet array with the hex representation of the identifier.
    pub fn into_hex(self) -> [u8; 40] {
        let mut res = [0u8; 40];
        hex::encode(self.as_slice(), &mut res);
        res
    }
}

#[cfg(feature = "bcder")]
impl KeyIdentifier {
    /// Takes an encoded key identifier from a constructed value.
    ///
    /// ```text
    /// KeyIdentifier ::= OCTET STRING
    /// ```
    ///
    /// The content of the octet string needs to be a SHA-1 hash, so it must
    /// be exactly 20 octets long.
    pub fn take_from<S: Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_value_if(bcder::Tag::OCTET_STRING, Self::from_content)
    }

    pub fn take_opt_from<S: Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_value_if(bcder::Tag::OCTET_STRING, Self::from_content)
    }

    /// Parses an encoded key identifier from encoded content.
    pub fn from_content<S: Source>(
        content: &mut decode::Content<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        let octets = bcder::OctetString::from_content(content)?;
        if let Some(slice) = octets.as_slice() {
            Self::try_from(slice).map_err(|_| {
                content.content_err("invalid key identifier")
            })
        }
        else if octets.len() != 20 {
            Err(content.content_err("invalid key identifier"))
        }
        else {
            let mut res = KeyIdentifier(Default::default());
            let mut pos = 0;
            for slice in &octets {
                let end = pos + slice.len();
                res.0[pos .. end].copy_from_slice(slice);
                pos = end;
            }
            Ok(res)
        }
    }

    /// Skips over an encoded key identifier.
    pub fn skip_opt_in<S: Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<()>, DecodeError<S::Error>> {
        cons.take_opt_value_if(bcder::Tag::OCTET_STRING, |cons| {
            Self::from_content(cons)?;
            Ok(())
        })
    }
}


//--- From, TryFrom and FromStr

impl From<[u8; 20]> for KeyIdentifier {
    fn from(src: [u8; 20]) -> Self {
        KeyIdentifier(src)
    }
}

impl From<KeyIdentifier> for [u8; 20] {
    fn from(src: KeyIdentifier) -> Self {
        src.0
    }
}

impl<'a> TryFrom<&'a [u8]> for KeyIdentifier {
    type Error = KeyIdentifierSliceError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        value.try_into()
            .map(KeyIdentifier)
            .map_err(|_| KeyIdentifierSliceError)
    }
}

impl FromStr for KeyIdentifier {
    type Err = ParseKeyIdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 40 || !value.is_ascii() {
            return Err(ParseKeyIdentifierError)
        }
        let mut res = KeyIdentifier(Default::default());
        for (pos, ch) in value.as_bytes().chunks(2).enumerate() {
            let ch = unsafe { str::from_utf8_unchecked(ch) };
            res.0[pos] = u8::from_str_radix(ch, 16)
                            .map_err(|_| ParseKeyIdentifierError)?;
        }
        Ok(res)
    }
}


//--- AsRef

impl AsRef<[u8]> for KeyIdentifier {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}


//--- PartialEq

impl<T: AsRef<[u8]>> PartialEq<T> for KeyIdentifier {
    fn eq(&self, other: &T) -> bool {
        self.0.as_ref().eq(other.as_ref())
    }
}


//--- Display and Debug

impl fmt::Display for KeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = [0u8; 40];
        write!(f, "{}", hex::encode(self.as_slice(), &mut buf))
    }
}

impl fmt::Debug for KeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyIdentifier({})", self)
    }
}


//--- PrimitiveContent

#[cfg(feature = "bcder")]
impl bcder::encode::PrimitiveContent for KeyIdentifier {
    const TAG: bcder::Tag = bcder::Tag::OCTET_STRING;

    fn encoded_len(&self, _mode: bcder::Mode) -> usize {
        20
    }

    fn write_encoded<W: std::io::Write>(
        &self,
        _mode: bcder::Mode,
        target: &mut W
    ) -> Result<(), std::io::Error> {
        target.write_all(&self.0)
    }
}


//--- Deserialize and Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for KeyIdentifier {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; 40];
        hex::encode(self.as_slice(), &mut buf).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for KeyIdentifier {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        struct KeyIdentifierVisitor;

        impl serde::de::Visitor<'_> for KeyIdentifierVisitor {
            type Value = KeyIdentifier;

            fn expecting(
                &self, formatter: &mut fmt::Formatter
            ) -> fmt::Result {
                write!(formatter,
                    "a string containing a key identifier as hex digits"
                )
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where E: serde::de::Error {
                KeyIdentifier::from_str(s).map_err(serde::de::Error::custom)
            }

            fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
            where E: serde::de::Error {
                KeyIdentifier::from_str(&s).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(KeyIdentifierVisitor)
    }
}


//============ Errors ========================================================

//------------ SignatureVerificationError ------------------------------------

/// An error happened while verifying a signature.
///
/// No further information is provided. This is on purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureVerificationError(());

impl From<Unspecified> for SignatureVerificationError {
    fn from(_: Unspecified) -> Self {
        SignatureVerificationError(())
    }
}

impl From<SignatureVerificationError> for ContentError {
    fn from(_: SignatureVerificationError) -> Self {
        ContentError::from_static("signature verification failed")
    }
}

impl fmt::Display for SignatureVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("signature verification failed")
    }
}

impl error::Error for SignatureVerificationError { }

//------------ ParseKeyIdentifierError ---------------------------------------

/// Creating a prefix has failed.
#[derive(Clone, Debug)]
pub struct ParseKeyIdentifierError;

impl fmt::Display for ParseKeyIdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid key identifier")
    }
}

impl error::Error for ParseKeyIdentifierError { }


//------------ KeyIdentifierSliceError ----------------------------------

/// Creating a prefix has failed.
#[derive(Clone, Debug)]
pub struct KeyIdentifierSliceError;

impl fmt::Display for KeyIdentifierSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid slice for key identifier")
    }
}

impl error::Error for KeyIdentifierSliceError { }


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use bcder::decode::IntoSource;

    #[test]
    #[cfg(all(feature = "serde", feature = "repository"))]
    fn serde_pub_key() {
        use crate::repository::Cert;

        let der = include_bytes!("../../test-data/repository/ta.cer");
        let cert = Cert::decode(Bytes::from_static(der)).unwrap();

        let pub_key = cert.subject_public_key_info();

        let ser = serde_json::to_string(pub_key).unwrap();
        let de: PublicKey = serde_json::from_str(&ser).unwrap();

        assert_eq!(pub_key, &de);
    }

    #[test]
    fn rsa_from_public_key_bytes() {
        let key = PublicKey::decode(
            include_bytes!(
                "../../test-data/crypto/rsa-key.public.der"
            ).as_ref().into_source(),
        ).unwrap();
        assert!(
            PublicKey::rsa_from_bits_bytes(
                key.bits_bytes()
            ).is_ok()
        );
    }
}
