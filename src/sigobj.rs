// Signed objects.

use std::{cmp, io};
use bcder::{decode, encode};
use bcder::{Captured, Mode, OctetString, Oid, Tag, xerr};
use bcder::encode::PrimitiveContent;
use bcder::string::OctetStringSource;
use bytes::Bytes;
use unwrap::unwrap;
use crate::{oid, uri};
use crate::cert::{Cert, KeyUsage, Overclaim, ResourceCert, TbsCert};
use crate::crypto::{
    Digest, DigestAlgorithm, KeyIdentifier, Signature, SignatureAlgorithm,
    Signer, SigningError
};
use crate::resources::{
    AsBlocksBuilder, AsResources, AsResourcesBuilder, IpBlocksBuilder,
    IpResources, IpResourcesBuilder
};
use crate::x509::{Name, Serial, Time, ValidationError, Validity, update_once};


//------------ SignedObject --------------------------------------------------

/// A signed object.
#[derive(Clone, Debug)]
pub struct SignedObject {
    //--- From SignedData
    //
    digest_algorithm: DigestAlgorithm,
    content_type: Oid<Bytes>,
    content: OctetString,
    cert: Cert,

    //--- From SignerInfo
    //
    sid: KeyIdentifier,
    signed_attrs: SignedAttrs,
    signature: Signature,

    //--- SignedAttributes
    //
    message_digest: MessageDigest,
    signing_time: Option<Time>,
    binary_signing_time: Option<u64>,
}

/// # Data Access
///
impl SignedObject {
    /// Returns a reference to the object’s content type.
    pub fn content_type(&self) -> &Oid<Bytes> {
        &self.content_type
    }

    /// Returns a reference to the object’s content.
    pub fn content(&self) -> &OctetString {
        &self.content
    }

    /// Decodes the object’s content.
    pub fn decode_content<F, T>(&self, op: F) -> Result<T, decode::Error>
    where F: FnOnce(&mut decode::Constructed<OctetStringSource>)
                    -> Result<T, decode::Error> {
        // XXX Let’s see if using DER here at least holds.
        Mode::Der.decode(self.content.to_source(), op)
    }

    /// Returns a reference to the certificate the object is signed with.
    pub fn cert(&self) -> &Cert {
        &self.cert
    }
}

/// # Decoding, Validation, and Encoding
///
impl SignedObject {
    /// Decodes a signed object from the given source.
    pub fn decode<S: decode::Source>(
        source: S,
        strict: bool
    ) -> Result<Self, S::Err> {
        if strict { Mode::Der }
        else { Mode::Ber }
            .decode(source, Self::take_from)
    }

    /// Takes a signed object from an encoded constructed value.
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| { // ContentInfo
            oid::SIGNED_DATA.skip_if(cons)?; // contentType
            cons.take_constructed_if(Tag::CTX_0, |cons| { // content
                cons.take_sequence(|cons| { // SignedData
                    cons.skip_u8_if(3)?; // version -- must be 3
                    let digest_algorithm =
                        DigestAlgorithm::take_set_from(cons)?;
                    let (content_type, content) = {
                        cons.take_sequence(|cons| { // encapContentInfo
                            Ok((
                                Oid::take_from(cons)?,
                                cons.take_constructed_if(
                                    Tag::CTX_0,
                                    OctetString::take_from
                                )?
                            ))
                        })?
                    };
                    let cert = cons.take_constructed_if( // certificates
                        Tag::CTX_0,
                        Cert::take_from
                    )?;
                    // no crls
                    let (sid, attrs, signature) = { // signerInfos
                        cons.take_set(|cons| {
                            cons.take_sequence(|cons| {
                                cons.skip_u8_if(3)?;
                                let sid = cons.take_value_if(
                                    Tag::CTX_0, |content| {
                                        KeyIdentifier::from_content(content)
                                    }
                                )?;
                                let alg = DigestAlgorithm::take_from(cons)?;
                                if alg != digest_algorithm {
                                    return Err(decode::Malformed.into())
                                }
                                let attrs = SignedAttrs::take_from(cons)?;
                                if attrs.2 != content_type {
                                    return Err(decode::Malformed.into())
                                }
                                let signature = Signature::new(
                                    SignatureAlgorithm::cms_take_from(cons)?,
                                    OctetString::take_from(cons)?.into_bytes()
                                );
                                // no unsignedAttributes
                                Ok((sid, attrs, signature))
                            })
                        })?
                    };
                    Ok(Self {
                        digest_algorithm,
                        content_type,
                        content,
                        cert,
                        sid,
                        signed_attrs: attrs.0,
                        signature,
                        message_digest: attrs.1,
                        signing_time: attrs.3,
                        binary_signing_time: attrs.4
                    })
                })
            })
        })
    }

    /// Validates the signed object.
    ///
    /// Upon success, the method returns the validated EE certificate of the
    /// object.
    pub fn validate(
        self,
        issuer: &ResourceCert,
        strict: bool,
    ) -> Result<ResourceCert, ValidationError> {
        self.validate_at(issuer, strict, Time::now())
    }

    /// Validates the signed object at he given time.
    pub fn validate_at(
        self,
        issuer: &ResourceCert,
        strict: bool,
        now: Time,
    ) -> Result<ResourceCert, ValidationError> {
        self.verify_compliance(strict)?;
        self.verify_signature(strict)?;
        self.cert.validate_ee_at(issuer, strict, now)
    }

    /// Validates that the signed object complies with the specification.
    ///
    /// This is item 1 of [RFC 6488]`s section 3.
    fn verify_compliance(
        &self,
        _strict: bool
    ) -> Result<(), ValidationError> {
        // Sub-items a, b, d, e, f, g, h, i, j, k, l have been validated while
        // parsing. This leaves these:
        //
        // c. cert is an EE cert with the SubjectKeyIdentifer matching
        //    the sid field of the SignerInfo.
        if self.sid != self.cert.subject_key_identifier() {
            return Err(ValidationError)
        }
        Ok(())
    }

    /// Verifies the signature of the object against contained certificate.
    ///
    /// This is item 2 of [RFC 6488]’s section 3.
    fn verify_signature(&self, _strict: bool) -> Result<(), ValidationError> {
        let digest = {
            let mut context = self.digest_algorithm.start();
            self.content.iter().for_each(|x| context.update(x));
            context.finish()
        };
        if digest.as_ref() != self.message_digest.as_ref() {
            return Err(ValidationError)
        }
        let msg = self.signed_attrs.encode_verify();
        self.cert.subject_public_key_info().verify(
            &msg,
            &self.signature
        ).map_err(Into::into)
    }

    /// Returns a value encoder for a reference to a signed object.
    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence((
            oid::SIGNED_DATA.encode(), // contentType
            encode::sequence_as(Tag::CTX_0, // content
                encode::sequence((
                    3u8.encode(), // version
                    self.digest_algorithm.encode_set(), // digestAlgorithms
                    encode::sequence(( // encapContentInfo
                        self.content_type.encode_ref(),
                        encode::sequence_as(Tag::CTX_0,
                            self.content.encode_ref()
                        ),
                    )),
                    encode::sequence_as(Tag::CTX_0, // certificates
                        self.cert.encode_ref(),
                    ),
                    // crl -- omitted
                    encode::set( // signerInfo
                        encode::sequence(( // SignerInfo
                            3u8.encode(), // version
                            self.sid.encode_ref_as(Tag::CTX_0),
                            self.digest_algorithm.encode(), // digestAlgorithm
                            self.signed_attrs.encode_ref(), // signedAttrs
                            self.signature.algorithm().cms_encode(),
                                                        // signatureAlgorithm
                            OctetString::encode_slice( // signature
                                self.signature.value().as_ref()
                            ),
                            // unsignedAttrs omitted
                        ))
                    )
                ))
            )
        ))
    }
}


//------------ SignedAttrs ---------------------------------------------------

/// A private helper type that contains the raw signed attributes content.
///
/// These attributes, in their DER encoded form, are what the signature is
/// calculated over. Annoyingly, the encoding uses the signed attribute set
/// with a tag for SET OF, not [0] as it would be found in the actual data.
///
/// Technically, signed objects need to be DER encoded, anyway, so we would
/// not need to re-encode the signed attributes other than sticking the SET OF
/// tag and length in front of them. While we do allow BER encoded objects in
/// relaxed mode, those that we have encountered have their signed attributes
/// in DER encoding still, so we don’t re-encode.
///
/// A `SignedAttrs` value contains the captured content of the signed
/// attributes set. That is, it does not contain the tag and length values of
/// the outer set object, only two to four sequences of the actual
/// attributes.
///
/// In order to make sticking tag and length in front of the value easier, we
/// allow a maximum length of the s content of 65536 octets.
#[derive(Clone, Debug)]
pub struct SignedAttrs(Captured);

impl SignedAttrs {
    fn new(
        content_type: &Oid<Bytes>,
        digest: &MessageDigest,
        signing_time: Option<Time>,
        binary_signing_time: Option<u64>,
    ) -> Self {
        // In DER encoding, the values of SET OFs is ordered via the octet
        // string of their DER encoding. Given that all our values are
        // SEQUENCEs, their first octet will always be 30. So we only have to
        // compare the length octets. Unfortunately, two of the values are
        // variable length, so we need to get creative.

        let mut content_type = Some(encode::sequence((
            oid::CONTENT_TYPE.encode(),
            encode::set(
                content_type.encode_ref(),
            )
        )));
        let mut signing_time = signing_time.map(|time| {
            encode::sequence((
                oid::SIGNING_TIME.encode(),
                encode::set(
                    time.encode_varied(),
                    )
            ))
        });
        let mut message_digest = Some(encode::sequence((
            oid::MESSAGE_DIGEST.encode(),
            encode::set(
                digest.encode_ref(),
            )
        )));
        let mut binary_signing_time = binary_signing_time.map(|time| {
            encode::sequence((
                oid::AA_BINARY_SIGNING_TIME.encode(),
                encode::set(
                    time.encode()
                )
            ))
        });

        let mut len = [
            (0, StartOfValue::new(&content_type)),
            (1, StartOfValue::new(&signing_time)),
            (2, StartOfValue::new(&message_digest)),
            (3, StartOfValue::new(&binary_signing_time)),
        ];
        len.sort_by_key(|&(_, len)| len.unwrap());

        let mut res = Captured::empty(Mode::Der);
        for &(idx, _) in &len {
            match idx {
                0 => {
                    if let Some(val) = content_type.take() {
                        res.extend(val)
                    }
                }
                1 => {
                    if let Some(val) = signing_time.take() {
                        res.extend(val)
                    }
                }
                2 => {
                    if let Some(val) = message_digest.take() {
                        res.extend(val)
                    }
                }
                3 => {
                    if let Some(val) = binary_signing_time.take() {
                        res.extend(val)
                    }
                }
                _ => unreachable!()
            }
        }

       SignedAttrs(res) 
    }

    /// Takes the signed attributes from the beginning of a constructed value.
    ///
    /// Returns the raw signed attrs, the message digest, the content type
    /// object identifier, and the two optional signing times.
    ///
    /// If strict is true, any unknown signed attributes are rejected, if
    /// strict is false they will be ignored.
    #[allow(clippy::type_complexity)]
    fn take_from_with_mode<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        strict: bool
    ) -> Result<
        (Self, MessageDigest, Oid<Bytes>, Option<Time>, Option<u64>),
        S::Err
    > {
        let mut message_digest = None;
        let mut content_type = None;
        let mut signing_time = None;
        let mut binary_signing_time = None;
        let raw = cons.take_constructed_if(Tag::CTX_0, |cons| {
            cons.capture(|cons| {
                while let Some(()) = cons.take_opt_sequence(|cons| {
                    let oid = Oid::take_from(cons)?;
                    if oid == oid::CONTENT_TYPE {
                        Self::take_content_type(cons, &mut content_type)
                    }
                    else if oid == oid::MESSAGE_DIGEST {
                        Self::take_message_digest(cons, &mut message_digest)
                    }
                    else if oid == oid::SIGNING_TIME {
                        Self::take_signing_time(cons, &mut signing_time)
                    }
                    else if oid == oid::AA_BINARY_SIGNING_TIME {
                        Self::take_bin_signing_time(
                            cons,
                            &mut binary_signing_time
                        )
                    }
                    else if !strict {
                        cons.skip_all()
                    } else {
                        xerr!(Err(decode::Malformed.into()))
                    }
                })? { }
                Ok(())
            })
        })?;
        if raw.len() > 0xFFFF {
            return Err(decode::Unimplemented.into())
        }
        let message_digest = match message_digest {
            Some(some) => MessageDigest(some.into_bytes()),
            None => return Err(decode::Malformed.into())
        };
        let content_type = match content_type {
            Some(some) => some,
            None => return Err(decode::Malformed.into())
        };
        Ok((
            Self(raw), message_digest, content_type, signing_time,
            binary_signing_time
        ))
    }



    /// Takes the signed attributes from the beginning of a constructed value.
    ///
    /// Returns the raw signed attrs, the message digest, the content type
    /// object identifier, and the two optional signing times.
    #[allow(clippy::type_complexity)]
    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<
        (Self, MessageDigest, Oid<Bytes>, Option<Time>, Option<u64>),
        S::Err
    > {
        Self::take_from_with_mode(cons, true)
    }

    /// Takes the signed attributes from the beginning of a constructed value.
    ///
    /// Note this function should be used for parsing CMS used in RFC6492 and
    /// RFC8181 messages only, as it will ignore any unknown signed attributes.
    /// Unfortunately the profile for the Certificates and CMS used is not
    /// well-defined in these RFCs. So, in this case, we should be more
    /// accepting.
    ///
    /// Returns the raw signed attrs, the message digest, the content type
    /// object identifier, and the two optional signing times.
    #[allow(clippy::type_complexity)]
    pub fn take_from_signed_message<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<
        (Self, MessageDigest, Oid<Bytes>, Option<Time>, Option<u64>),
        S::Err
    > {
        Self::take_from_with_mode(cons, false)
    }

    /// Parses the Content Type attribute.
    ///
    /// This attribute is defined in section 11.1. of RFC 5652. The attribute
    /// value is a SET of exactly one OBJECT IDENTIFIER.
    fn take_content_type<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        content_type: &mut Option<Oid<Bytes>>
    ) -> Result<(), S::Err> {
        update_once(content_type, || {
            cons.take_set(|cons| Oid::take_from(cons))
        })
    }

    fn take_message_digest<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        message_digest: &mut Option<OctetString>
    ) -> Result<(), S::Err> {
        update_once(message_digest, || {
            cons.take_set(|cons| OctetString::take_from(cons))
        })
    }

    fn take_signing_time<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        signing_time: &mut Option<Time>
    ) -> Result<(), S::Err> {
        update_once(signing_time, || {
            cons.take_set(Time::take_from)
        })
    }

    fn take_bin_signing_time<S: decode::Source>(
        cons: &mut decode::Constructed<S>,
        bin_signing_time: &mut Option<u64>
    ) -> Result<(), S::Err> {
        update_once(bin_signing_time, || {
            cons.take_set(|cons| cons.take_u64())
        })
    }

    pub fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        encode::sequence_as(Tag::CTX_0, &self.0)
    }

    /// Creates the message for verification.
    pub fn encode_verify(&self) -> Vec<u8> {
        let len = self.0.len();
        let mut res = Vec::with_capacity(len + 4);
        res.push(0x31); // SET
        if len < 128 {
            res.push(len as u8)
        }
        else if len < 0x10000 {
            res.push(2);
            res.push((len >> 8) as u8);
            res.push(len as u8);
        }
        else {
            panic!("overly long signed attrs");
        }
        res.extend_from_slice(self.0.as_ref());
        res
    }
}

impl AsRef<[u8]> for SignedAttrs {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}


//------------ MessageDigest -------------------------------------------------

/// A private helper type that contains the message digest attribute.
#[derive(Clone, Debug)]
pub struct MessageDigest(Bytes);

impl MessageDigest {
    fn encode_ref<'a>(&'a self) -> impl encode::Values + 'a {
        OctetString::encode_slice(self.0.as_ref())
    }
}

impl From<Digest> for MessageDigest {
    fn from(digest: Digest) -> Self {
        MessageDigest(Bytes::from(digest.as_ref()))
    }
}

impl AsRef<[u8]> for MessageDigest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}


//------------ SignedObjectBuilder -------------------------------------------

#[derive(Clone, Debug)]
pub struct SignedObjectBuilder {
    /// The digest algorithm to be used for the message digest attribute.
    ///
    /// By default, this will be the default algorithm.
    digest_algorithm: DigestAlgorithm,

    /// The serial number of the EE certificate.
    ///
    /// Must be provided.
    serial_number: Serial,

    /// The validity of the EE certificate.
    ///
    /// Must be provided.
    validity: Validity,

    /// The issuer name of the EE certificate.
    ///
    /// If this is `None` (the default), it will be generated from the key
    /// identifier of the EE certificate’s key.
    issuer: Option<Name>,

    /// The subject name of the EE certificate.
    ///
    /// If this is `None` (the default), it will be generated from the key
    /// identifier of the EE certificate’s key.
    subject: Option<Name>,

    /// The URI of CRL for the EE certificate.
    ///
    /// Must be provided.
    crl_uri: uri::Rsync,

    /// The URI of the CA certificate issuing the EE certificate.
    ///
    /// Must be provided.
    ca_issuer: uri::Rsync,

    /// The URI of the signed object itself.
    ///
    /// Must be provided.
    signed_object: uri::Rsync,

    /// The IPv4 resources of the EE certificate.
    ///
    /// Defaults to not having any.
    v4_resources: Option<IpResources>,

    /// The IPv6 resources of the EE certificate.
    ///
    /// Defaults to not having any.
    v6_resources: Option<IpResources>,

    /// The AS resources of the EE certificate.
    ///
    /// Defaults to not having any.
    as_resources: Option<AsResources>,

    /// The signing time attribute of the signed object.
    ///
    /// This is optional and by default omitted.
    signing_time: Option<Time>,

    /// The binary signing time attribute of the signed object.
    ///
    /// This is optional and by default omitted.
    binary_signing_time: Option<u64>,
}

impl SignedObjectBuilder {
    pub fn new(
        serial_number: Serial,
        validity: Validity,
        crl_uri: uri::Rsync,
        ca_issuer: uri::Rsync,
        signed_object: uri::Rsync
    ) -> Self {
        Self {
            digest_algorithm: DigestAlgorithm::default(),
            serial_number,
            validity,
            issuer: None,
            subject: None,
            crl_uri,
            ca_issuer,
            signed_object,
            v4_resources: None,
            v6_resources: None,
            as_resources: None,
            signing_time: None,
            binary_signing_time: None,
        }
    }

    pub fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    pub fn set_digest_algorithm(&mut self, algorithm: DigestAlgorithm) {
        self.digest_algorithm = algorithm
    }

    pub fn serial_number(&self) -> Serial {
        self.serial_number
    }

    pub fn set_serial_number(&mut self, serial: Serial) {
        self.serial_number = serial
    }

    pub fn validity(&self) -> Validity {
        self.validity
    }

    pub fn set_validity(&mut self, validity: Validity) {
        self.validity = validity
    }

    pub fn issuer(&self) -> Option<&Name> {
        self.issuer.as_ref()
    }

    pub fn set_issuer(&mut self, name: Option<Name>) {
        self.issuer = name
    }

    pub fn subject(&self) -> Option<&Name> {
        self.subject.as_ref()
    }

    pub fn set_subject(&mut self, name: Option<Name>) {
        self.subject = name
    }

    pub fn crl_uri(&self) -> &uri::Rsync {
        &self.crl_uri
    }

    pub fn set_crl_uri(&mut self, uri: uri::Rsync) {
        self.crl_uri = uri
    }

    pub fn ca_issuer(&self) -> &uri::Rsync {
        &self.ca_issuer
    }

    pub fn set_ca_issuer(&mut self, uri: uri::Rsync) {
        self.ca_issuer = uri
    }

    pub fn signed_object(&self) -> &uri::Rsync {
        &self.signed_object
    }

    pub fn set_signed_object(&mut self, uri: uri::Rsync) {
        self.signed_object = uri
    }

    /// Returns a reference to the IPv4 address resources if present.
    pub fn v4_resources(&self) -> Option<&IpResources> {
        self.v4_resources.as_ref()
    }

    /// Set the IPv4 address resources.
    pub fn set_v4_resources(&mut self, resources: Option<IpResources>) {
        self.v4_resources = resources
    }

    /// Sets the IPv4 address resources to inherit.
    pub fn set_v4_resources_inherit(&mut self) {
        self.set_v4_resources(Some(IpResources::inherit()))
    }

    /// Builds the blocks IPv4 address resources.
    pub fn build_v4_resource_blocks<F>(&mut self, op: F)
    where F: FnOnce(&mut IpBlocksBuilder) {
        let mut builder = IpResourcesBuilder::new();
        builder.blocks(op);
        self.set_v4_resources(builder.finalize())
    }

    /// Returns a reference to the IPv6 address resources if present.
    pub fn v6_resources(&self) -> Option<&IpResources> {
        self.v6_resources.as_ref()
    }

    /// Set the IPv6 address resources.
    pub fn set_v6_resources(&mut self, resources: Option<IpResources>) {
        self.v6_resources = resources
    }

    /// Sets the IPv6 address resources to inherit.
    pub fn set_v6_resources_inherit(&mut self) {
        self.set_v6_resources(Some(IpResources::inherit()))
    }

    /// Builds the blocks IPv6 address resources.
    pub fn build_v6_resource_blocks<F>(&mut self, op: F)
    where F: FnOnce(&mut IpBlocksBuilder) {
        let mut builder = IpResourcesBuilder::new();
        builder.blocks(op);
        self.set_v6_resources(builder.finalize())
    }

    /// Returns whether the certificate has any IP resources at all.
    pub fn has_ip_resources(&self) -> bool {
        self.v4_resources.is_some() || self.v6_resources().is_some()
    }

    /// Returns a reference to the AS resources if present.
    pub fn as_resources(&self) -> Option<&AsResources> {
        self.as_resources.as_ref()
    }

    /// Set the AS resources.
    pub fn set_as_resources(&mut self, resources: Option<AsResources>) {
        self.as_resources = resources
    }

    /// Sets the AS resources to inherit.
    pub fn set_as_resources_inherit(&mut self) {
        self.set_as_resources(Some(AsResources::inherit()))
    }

    /// Builds the blocks AS resources.
    pub fn build_as_resource_blocks<F>(&mut self, op: F)
    where F: FnOnce(&mut AsBlocksBuilder) {
        let mut builder = AsResourcesBuilder::new();
        builder.blocks(op);
        self.set_as_resources(builder.finalize())
    }

    /// Returns the signing time attribute.
    pub fn signing_time(&self) -> Option<Time> {
        self.signing_time
    }

    /// Sets the signing time attribute.
    pub fn set_signing_time(&mut self, signing_time: Option<Time>) {
        self.signing_time = signing_time
    }

    /// Returns the binary signing time attribute.
    pub fn binary_signing_time(&self) -> Option<u64> {
        self.binary_signing_time
    }

    /// Sets the binary signing time attribute.
    pub fn set_binary_signing_time(&mut self, time: Option<u64>) {
        self.binary_signing_time = time
    }

    pub fn finalize<S: Signer>(
        self,
        content_type: Oid<Bytes>,
        content: Bytes,
        signer: &S,
        issuer_key: &S::KeyId,
    ) -> Result<SignedObject, SigningError<S::Error>> {
        let issuer_pub = signer.get_key_info(issuer_key)?;

        // Produce signed attributes.
        let message_digest = self.digest_algorithm.digest(&content).into();
        let signed_attrs = SignedAttrs::new(
            &content_type,
            &message_digest,
            self.signing_time,
            self.binary_signing_time
        );

        // Sign signed attributes with a one-off key.
        let (signature, key_info) = signer.sign_one_off(
            SignatureAlgorithm::default(), &signed_attrs.encode_verify()
        )?;
        let sid = KeyIdentifier::from_public_key(&key_info);

        // Make the certificate.
        let mut cert = TbsCert::new(
            self.serial_number,
            self.issuer.unwrap_or_else(|| issuer_pub.to_subject_name()),
            self.validity,
            self.subject,
            key_info,
            KeyUsage::Ee,
            Overclaim::Refuse,
        );
        cert.set_authority_key_identifier(Some(issuer_pub.key_identifier()));
        cert.set_crl_uri(Some(self.crl_uri));
        cert.set_ca_issuer(Some(self.ca_issuer));
        cert.set_signed_object(Some(self.signed_object));
        cert.set_v4_resources(self.v4_resources);
        cert.set_v6_resources(self.v6_resources);
        cert.set_as_resources(self.as_resources);
        let cert = cert.into_cert(signer, issuer_key)?;

        Ok(SignedObject {
            digest_algorithm: self.digest_algorithm,
            content_type,
            content: OctetString::new(content),
            cert,
            sid,
            signed_attrs,
            signature,
            message_digest,
            signing_time: self.signing_time,
            binary_signing_time: self.binary_signing_time,
        })
    }


}


//------------ StartOfValue --------------------------------------------------


/// Helper type for ordering signed attributes.
///
/// It keeps the first eight octets of a value which should be enough to
/// cover the length.
#[derive(Clone, Copy, Debug)]
struct StartOfValue {
    res: [u8; 8],
    pos: usize,
}

impl StartOfValue {
    fn new<V: encode::Values>(values: &V) -> Self {
        let mut res = StartOfValue {
            res: [0; 8],
            pos: 0
        };
        unwrap!(values.write_encoded(Mode::Der, &mut res));
        res
    }

    fn unwrap(self) -> [u8; 8] {
        self.res
    }
}

impl io::Write for StartOfValue {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        let slice = &mut self.res[self.pos..];
        let len = cmp::min(slice.len(), buf.len());
        slice[..len].copy_from_slice(&buf[..len]);
        self.pos += len;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use crate::tal::TalInfo;
    use unwrap::unwrap;
    use super::*;

    #[test]
    fn decode() {
        let talinfo = TalInfo::from_name("foo".into()).into_arc();
        let at = Time::utc(2019, 5, 1, 0, 0, 0);
        let issuer = Cert::decode(
            include_bytes!("../test-data/ta.cer").as_ref()
        ).unwrap();
        let issuer = unwrap!(issuer.validate_ta_at(talinfo, false, at));
        let obj = unwrap!(SignedObject::decode(
            include_bytes!("../test-data/ta.mft").as_ref(),
            false
        ));
        unwrap!(obj.validate_at(&issuer, false, at));
        let obj = unwrap!(SignedObject::decode(
            include_bytes!("../test-data/ca1.mft").as_ref(),
            false
        ));
        assert!(obj.validate_at(&issuer, false, at).is_err());
    }
}

#[cfg(all(test, feature="softkeys"))]
mod signer_test {
    use std::str::FromStr;
    use bcder::Oid;
    use bcder::encode::Values;
    use unwrap::unwrap;
    use crate::uri;
    use crate::crypto::PublicKeyFormat;
    use crate::crypto::softsigner::OpenSslSigner;
    use crate::resources::{AsId, Prefix};
    use crate::tal::TalInfo;
    use super::*;
        
    #[test]
    fn encode_signed_object() {
        let mut signer = OpenSslSigner::new();
        let key = unwrap!(signer.create_key(PublicKeyFormat::default()));
        let pubkey = unwrap!(signer.get_key_info(&key));
        let uri = unwrap!(uri::Rsync::from_str("rsync://example.com/m/p"));

        let mut cert = TbsCert::new(
            12u64.into(), pubkey.to_subject_name(),
            Validity::from_secs(86400), None, pubkey, KeyUsage::Ca,
            Overclaim::Trim
        );
        cert.set_basic_ca(Some(true));
        cert.set_ca_repository(Some(uri.clone()));
        cert.set_rpki_manifest(Some(uri.clone()));
        cert.build_v4_resource_blocks(|b| b.push(Prefix::new(0, 0)));
        cert.build_v6_resource_blocks(|b| b.push(Prefix::new(0, 0)));
        cert.build_as_resource_blocks(|b| b.push((AsId::MIN, AsId::MAX)));
        let cert = unwrap!(cert.into_cert(&signer, &key));

        let mut sigobj = SignedObjectBuilder::new(
            12u64.into(), Validity::from_secs(86400), uri.clone(),
            uri.clone(), uri.clone()
        );
        sigobj.set_v4_resources_inherit();
        let sigobj = unwrap!(sigobj.finalize(
            Oid(oid::SIGNED_DATA.0.into()),
            Bytes::from(b"1234".as_ref()),
            &signer,
            &key,
        ));
        let sigobj = sigobj.encode_ref().to_captured(Mode::Der);

        let sigobj = unwrap!(SignedObject::decode(sigobj.as_slice(), true));
        let cert = unwrap!(cert.validate_ta(
            TalInfo::from_name("foo".into()).into_arc(), true
        ));
        unwrap!(sigobj.validate(&cert, true));
    }
}


//============ Specification Documentation ===================================

/// Signed Objects Specification.
///
/// This is a documentation-only module. It summarizes the specification for
/// signed objects, how they are to be parsed and constructed.
///
/// Signed objects are CMS signed objects that have been severly limited in
/// the options of the various fields. They are specified in [RFC 6488] while
/// CMS is specified in [RFC 5652].
///
/// A signed object is a CMS object with a single signed data object in it.
///
/// A CMS object is:
///
/// ```txt
/// ContentInfo             ::= SEQUENCE {
///     contentType             ContentType,
///     content                 [0] EXPLICIT ANY DEFINED BY contentType }
/// ```
///
/// For a signed object, the _contentType_ must be `oid::SIGNED_DATA` and the
/// _content_ a _SignedData_ object (however, note the `[0] EXPLICIT` there)
/// as follows:
///
/// ```txt
/// SignedData              ::= SEQUENCE {
///     version                 CMSVersion,
///     digestAlgorithms        DigestAlgorithmIdentifiers,
///     encapContentInfo        EncapsulatedContentInfo,
///     certificates            [0] IMPLICIT CertificateSet OPTIONAL,
///     crls                    [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///     signerInfos             SignerInfos }
///
/// EncapsulatedContentInfo ::= SEQUENCE {
///     eContentType            ContentType,
///     eContent                [0] EXPLICIT OCTET STRING OPTIONAL }
///
/// CertificateSet          ::= SET OF CertificateChoices
///
/// CertificateChoices      ::= CHOICE {
///     certificate             Certificate,
///     extendedCertificate     [0] IMPLICIT ExtendedCertificate,   -- Obsolete
///     v1AttrCert              [1] IMPLICIT AttributeCertificateV1,-- Obsolete
///     v2AttrCert              [2] IMPLICIT AttributeCertificateV2,
///     other                   [3] IMPLICIT OtherCertificateFormat }
/// ```
///
/// Limitations imposed by [RFC 6488] are as follows:
///
/// * The _version_ must be 3.
/// * The _digestAlgorithms_ set must be exactly one algorithm chosen from
///   those defined in [RFC 7935]. The [`DigestAlgorithm`] type implements
///   both the _DigestAlgorithmIdentifier_ and _DigestAlgorithmIndentifiers_
///   definitions (the latter via `take_set_from` and `encode_set`).
/// * The _eContentType_ field of _encapContentInfo_ defines the type of an
///   object. Check the specific signed objects for their matching object ID.
/// * The _eContent_ field of _encapContentInfo_ must be present and contain
///   the actual content of the signed object.
/// * There must be exactly one certificate in the `certificates` set. It must
///   be of the _certificate_ choice (that’s not exactly in RFC 6488, but it
///   is the only logical choice for ‘the RPKI end-entity (EE) certificate
///   needed to validate this signed object’), which in practice means it is
///   just one [`Cert`].
/// * The _crls_ field must be omitted.
///
/// The _SignerInfos_ structure:
///
/// ```txt
///
/// SignerInfos             ::= SET OF SignerInfo
///
/// SignerInfo              ::= SEQUENCE {
///     version                 CMSVersion,
///     sid                     SignerIdentifier,
///     digestAlgorithm         DigestAlgorithmIdentifier,
///     signedAttrs             [0] IMPLICIT SignedAttributes OPTIONAL,
///     signatureAlgorithm      SignatureAlgorithmIdentifier,
///     signature               SignatureValue,
///     unsignedAttrs           [1] IMPLICIT UnsignedAttributes OPTIONAL }
///
/// SignerIdentifier        ::= CHOICE {
///     issuerAndSerialNumber   IssuerAndSerialNumber,
///     subjectKeyIdentifier    [0] EXPLICIT SubjectKeyIdentifier }
///
/// SubjectKeyIdentifier    ::= OCTET STRING
/// 
/// SignatureValue          ::= OCTET STRING
/// ```
///
/// Limitations are as follows:
///
/// * There must be exactly one _SignerInfo_ present.
/// * The _version_ must be 3.
/// * The _sid_ must be identical to the value of the Subject Key Identifier
///   extension of the included certificate. I.e., it must be the second
///   choice.
/// * The _digestAlgorithm_ must be the same as the only value in the outer
///   _digestAlgorthm_ field.
/// * The _signedAttrs_ field must be present. See below.
/// * For the content of the _signature_ field, see below.
/// * The _unsignedAttrs_ field must be omitted.
///
/// Finally, _SignedAttributes_ is a sequence of attributes keyed by an OID.
/// RPKI has two mandatory and two optional attributes. Definition for all
/// of these is the following:
///
/// ```text
/// SignedAttributes        ::= SET SIZE (1..MAX) OF Attribute
///
/// Attribute               ::= SEQUENCE {
///     attrType                OBJECT IDENTIFIER,
///     attrValues              SET OF AttributeValue }
///
/// ContentType             ::= OBJECT IDENTIFIER
///
/// MessageDigest           ::= OCTET STRING
///
/// SigningTime             ::= Time
///
/// Time                    ::= CHOICE {
///     utcTime                 UTCTime,
///     generalizedTime         GeneralizedTime }
///
/// BinarySigningTime       ::= BinaryTime
///
/// BinaryTime              ::= INTEGER (0..MAX)
/// ```
///
/// The two mandatory attributes are _ContentType_ and _MessageDigest_. The
/// content type attribute must be the same as the _eContentType_ field of
/// the _encapContentInfo_. The message digest attribute contains the digest
/// value of the (actual) content.
///
/// The _SigningTime_ and _BinarySigningTime_ attributes are optional. Their
/// presence is not considered when validating a signed object.
///
/// No other attribute may be present.
///
/// For the object identifiers of the attributes, see the [`oid`] module.
///
/// The _signature_ field of the signed object contains a signature over the
/// DER encoding of the _signedAttrs_ field. When calculating the signature,
/// the normal tag for the SET is used instead of the implicit `[0]`.
///
/// [RFC 5652]: https://tools.ietf.org/html/rfc5652
/// [RFC 6488]: https://tools.ietf.org/html/rfc6488
/// [RFC 7935]: https://tools.ietf.org/html/rfc7935
/// [`Cert`]: ../../cert/struct.Cert.html
/// [`DigestAlgorithm`]: ../../crypto/keys/struct.DigestAlgorithm.html
/// [`oid`]: ../../oid/index.html
pub mod spec { }


