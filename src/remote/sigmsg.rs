//! CMS structure that is used to encompass publication and provisioning
//! messages.

use ber::decode;
use ber::{Mode, Oid, Tag};
use ber::ostring::OctetString;
use bytes::Bytes;
use ring::digest;
use untrusted::Input;

use sigobj::oid;
use sigobj::{DigestAlgorithm, SignedObject, SignerInfo};
use super::idcert::IdCert;
use x509::ValidationError;
use ber::Captured;

//------------ Cms -----------------------------------------------------------

/// A protocol CMS.
///
/// This is a signed CMS object that contains XML messages used in the
/// provisioning and publication protocols, and that is signed using an
/// EE IdCert, signed under a TA IdCert.
#[derive(Clone, Debug)]
pub struct SignedMessage {
    content_type: Oid<Bytes>,
    content: OctetString,
    idcert: IdCert,
    signer_info: SignerInfo,
}

impl SignedMessage {

    pub fn decode<S: decode::Source>(
        source: S,
        strict: bool
    ) -> Result<Self, S::Err> {
        if strict { Mode::Der }
            else { Mode::Ber }
            .decode(source, Self::take_from)
    }

}

/// Cms parsing
impl SignedMessage {

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            oid::SIGNED_DATA.skip_if(cons)?; // contentType
            cons.take_constructed_if(Tag::CTX_0, Self::take_signed_data)
        })
    }

    fn take_signed_data<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(|cons| {
            cons.skip_u8_if(3)?; // version -- must be 3
            DigestAlgorithm::skip_set(cons)?; // digestAlgorithms
            let (content_type, content)
            = SignedObject::take_encap_content_info(cons)?;
            let idcert = Self::take_certificates(cons)?;
            let _crl_bytes = Self::take_crls(cons)?;
            let signer_info = cons.take_set(SignerInfo::take_from)?;

            Ok(SignedMessage {
                content_type, content, idcert, signer_info
            })
        })
    }

    fn take_certificates<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<IdCert, S::Err> {
        cons.take_constructed_if(Tag::CTX_0, |cons| {
            cons.take_constructed(|tag, cons| {
                match tag {
                    Tag::SEQUENCE => IdCert::take_content_from(cons),
                    _ => {
                        xerr!(Err(decode::Unimplemented.into()))
                    }
                }
            })
        })
    }


    fn take_crls<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Captured, S::Err> {
        cons.take_constructed_if(Tag::CTX_1, |cons| {
            // XXX: To do: capture the CRL so we can check that there is no
            //             no regression, and someone is doing a replay attack
            //             using a multi-use EE keypair that is now revoked.
            //
            //             or? Get the WG to mandate single-use EE, and
            //             drop these CRLs altogether?
            cons.capture_all()
        })
    }
}


/// Cms validation
impl SignedMessage {

    /// Validates the signed object.
    ///
    /// The requirements for an object to be valid are given in section 3
    /// of [RFC 6488].
    ///
    /// Upon success, the method returns the validated certificate and the
    /// content.
    pub fn validate(
        self,
        issuer: &IdCert
    ) -> Result<IdCert, ValidationError> {
        self.verify_signature()?;
        self.idcert.validate_ee(issuer)
    }

    /// Verifies the signature of the object against contained certificate.
    ///
    /// This is item 2 of [RFC 6488]’s section 3.
    fn verify_signature(&self) -> Result<(), ValidationError> {
        let digest = {
            let mut context = digest::Context::new(&digest::SHA256);
            self.content.iter().for_each(|x| context.update(x));
            context.finish()
        };
        if digest.as_ref() != self.signer_info.message_digest() {
            return Err(ValidationError)
        }
        let msg = self.signer_info.signed_attrs().encode_verify();
        ::ring::signature::verify(
            &::ring::signature::RSA_PKCS1_2048_8192_SHA256,
            Input::from(self.idcert.public_key().as_ref()),
            Input::from(&msg),
            Input::from(self.signer_info.signature_value().to_bytes().as_ref())
        ).map_err(|_| ValidationError)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use time;
    use chrono::{TimeZone, Utc};

    #[test]
    fn should_parse_and_validate_signed_message() {
        let d = Utc.ymd(2012, 1, 1).and_hms(0, 0, 0);
        time::with_now(d, || {
            let der = include_bytes!("../../test/remote/pdu.200.der");
            let msg = SignedMessage::decode(Bytes::from_static(der), false).unwrap();

            let b = include_bytes!("../../test/remote/cms-ta.cer");
            let id_cert = IdCert::decode(Bytes::from_static(b)).unwrap();

            msg.validate(&id_cert).unwrap();

        });
    }

    #[test]
    fn should_reject_invalid_signed_message() {
        let d = Utc.ymd(2012, 1, 1).and_hms(0, 0, 0);
        time::with_now(d, || {
            let der = include_bytes!("../../test/remote/pdu.200.der");
            let msg = SignedMessage::decode(Bytes::from_static(der), false).unwrap();

            let b = include_bytes!("../../test/oob/id-publisher-ta.cer");
            let id_cert = IdCert::decode(Bytes::from_static(b)).unwrap();

            assert_eq!(ValidationError, msg.validate(&id_cert).unwrap_err());
        });
    }
}