//! Resource Signed Checklists.
//! 
//! For more information see [rfc9323].
//!
//! [rfc9323]: https://datatracker.ietf.org/doc/rfc9323/

use bcder::{Ia5String, decode, encode};
use bcder::{Captured, Mode, OctetString, Tag};
use bcder::decode::{DecodeError, IntoSource, Source};
use bcder::encode::Values;
use bytes::Bytes;
use crate::crypto:: DigestAlgorithm;
use crate::repository::error::VerificationError;
use crate::repository::sigobj::SignedObject;
use super::cert::ResourceCert;
use super::error::ValidationError;
use super::resources::{
    AddressFamily, AsBlocks, IpBlocks,
};
use super::x509::Time;


//------------ Rsc -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Rsc {
    signed: SignedObject,
    content: ResourceSignedChecklist,
}

impl Rsc {
    pub fn content(&self) -> &ResourceSignedChecklist {
        &self.content
    }

    pub fn decode<S: IntoSource>(
        source: S, strict: bool
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        let signed = SignedObject::decode(source, strict)?;
        let content = signed.decode_content(|cons| {
            ResourceSignedChecklist::take_from(cons)
        }).map_err(DecodeError::convert)?;
        Ok(Self { signed, content })
    }

    pub fn signed(&self) -> &SignedObject {
        &self.signed
    }

    /// Returns a value encoder for a reference to a ROA.
    pub fn encode_ref(&self) -> impl encode::Values + '_ {
        self.signed.encode_ref()
    }

    /// Returns a DER encoded Captured for this ROA.
    pub fn to_captured(&self) -> Captured {
        self.encode_ref().to_captured(Mode::Der)
    }
}

impl Rsc {
    /// Validates the RSC.
    ///
    /// You need to pass in the certificate of the issuing CA. If validation
    /// succeeds, the result will be the EE certificate of the manifest and
    /// the manifest content.
    pub fn process(
        self,
        cert: &ResourceCert,
        strict: bool,
    ) -> Result<(ResourceCert, ResourceSignedChecklist), ValidationError> {
        self.process_at(cert, strict, Time::now())
    }

    pub fn process_at(
        self,
        cert: &ResourceCert,
        strict: bool,
        now: Time
    ) -> Result<(ResourceCert, ResourceSignedChecklist), ValidationError> {
        // Check for consistency within the object... If the ResourceBlock
        // exceeds the resources on the certificate, then that's a fail.
        let signed_cert = self.signed().cert();
        self.as_ref().as_resources().verify_covered(signed_cert.as_resources())
            .map_err(|err| VerificationError::new(err.to_string()))?;
        self.as_ref().v4_resources().verify_covered(signed_cert.v4_resources())
            .map_err(|err| VerificationError::new(err.v4().to_string()))?;
        self.as_ref().v6_resources().verify_covered(signed_cert.v6_resources())
            .map_err(|err| VerificationError::new(err.v6().to_string()))?;

        let cert = self.signed.validate_at(cert, strict, now)?;
        Ok((cert, self.content))
    }
}


//--- AsRef
impl AsRef<ResourceSignedChecklist> for Rsc {
    fn as_ref(&self) -> &ResourceSignedChecklist {
        self.content()
    }
}


//------------ ResourceSignedChecklist ---------------------------------------

#[derive(Clone, Debug)]
pub struct ResourceSignedChecklist {
    /// AS Resources
    as_resources: AsBlocks,

    /// IP Resources for the IPv4 address family.
    v4_resources: IpBlocks,

    /// IP Resources for the IPv6 address family.
    v6_resources: IpBlocks,

    digest_algorithm: DigestAlgorithm,

    check_list: Captured,
}

impl ResourceSignedChecklist {
    pub fn as_resources(&self) -> &AsBlocks {
        &self.as_resources
    }

    pub fn v4_resources(&self) -> &IpBlocks {
        &self.v4_resources
    }

    pub fn v6_resources(&self) -> &IpBlocks {
        &self.v6_resources
    }

    pub fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    pub fn iter(&self) -> CheckListIter {
        CheckListIter(self.check_list.clone())
    }
}

impl ResourceSignedChecklist {
    fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            cons.take_opt_constructed_if(Tag::CTX_0, |c| c.skip_u8_if(0))?;
            let (v4res, v6res, asres) = Self::take_resources_from(cons)?;
            let alg = DigestAlgorithm::take_from(cons)?;
            let mut len = 0; // TODO: Do we need this?
            let check_list = cons.take_sequence(|cons| {
                cons.capture(|cons| {
                    while let Some(()) = FileNameAndHash::skip_opt_in(cons)? {
                        len += 1;
                    }
                    Ok(())
                })
            })?;
            Ok(Self {
                v4_resources: v4res,
                v6_resources: v6res,
                as_resources: asres,
                digest_algorithm: alg,
                check_list
            })
        })
    }

    fn take_resources_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<(IpBlocks, IpBlocks, AsBlocks), DecodeError<S::Error>> {
        // ResourceBlock
        cons.take_sequence(|cons| {
            let asres = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
                cons.take_sequence(|cons| {
                    cons.take_constructed_if(Tag::CTX_0, |cons| {
                        AsBlocks::take_from(cons)
                    })
                })
            })?;

            let mut v4 = None;
            let mut v6 = None;
            cons.take_opt_constructed_if(Tag::CTX_1, |cons| {
                cons.take_sequence(|cons| {
                    while let Some(()) = cons.take_opt_sequence(|cons| {
                        match AddressFamily::take_from(cons)? {
                            AddressFamily::Ipv4 => {
                                if v4.is_some() {
                                    return Err(cons.content_err(
                                        "multiple IPv4 blocks in RSC prefixes"
                                    ));
                                }
                                v4 = Some(IpBlocks::take_from_with_family(
                                    cons, AddressFamily::Ipv4
                                )?);
                            }
                            AddressFamily::Ipv6 => {
                                if v6.is_some() {
                                    return Err(cons.content_err(
                                        "multiple IPv6 blocks in RSC prefixes"
                                    ));
                                }
                                v6 = Some(IpBlocks::take_from_with_family(
                                    cons, AddressFamily::Ipv6
                                )?);
                            }
                        }
                        Ok(())
                    })? { }
                    Ok(())
                })
            })?;

            if asres.is_none() && v4.is_none() && v6.is_none() {
                return Err(cons.content_err("no resources in RSC"));
            }
            Ok((
                v4.unwrap_or_default(),
                v6.unwrap_or_default(),
                asres.unwrap_or_default(),
            ))
        })
    }

    // pub fn encode_ref(&self) -> impl encode::Values + '_ {
    //     encode::sequence((
    //         // version is DEFAULT
    //         encode::sequence((
    //             self.encode_as_resources(),
    //             self.encode_ip_resources(),
    //         )),
    //         self.digest_algorithm.encode(),
    //         encode::set(
    //             encode::iter(self.check_list.iter().map(|item| {
    //                 item.encode_ref()
    //             }))
    //         ),
    //     ))
    // }

    // fn encode_as_resources(&self) -> impl encode::Values + '_ {
    //     if self.as_resources.is_empty() {
    //         None
    //     }
    //     else {
    //         Some(encode::sequence_as(Tag::CTX_0,
    //             encode::sequence(
    //                 self.as_resources.encode_ref()
    //             )
    //         ))
    //     }
    // }

    // fn encode_ip_resources(&self) -> impl encode::Values + '_ {
    //     if self.v4_resources.is_empty() && self.v6_resources.is_empty() {
    //         return None
    //     }
    //     Some(encode::sequence_as(Tag::CTX_1,
    //         encode::sequence((
    //             self.v4_resources.encode_family(AddressFamily::Ipv4),
    //             self.v6_resources.encode_family(AddressFamily::Ipv6),
    //         ))
    //     ))
    // }

    // fn to_bytes(&self) -> Bytes {
    //     self.encode_ref().to_captured(Mode::Der).into_bytes()
    // }
}

// ----------- CheckListIter -------------------------------------------------
#[derive(Clone, Debug)]
pub struct CheckListIter(Captured);

impl Iterator for CheckListIter {
    type Item = FileNameAndHash;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.decode_partial(|cons| {
            FileNameAndHash::take_opt_from(cons)
        }).unwrap()
    }
}


// ----------- FileNameAndHash -----------------------------------------------
#[derive(Clone, Debug)]
pub struct FileNameAndHash {
    file_name: Option<Bytes>,
    hash: Bytes,
}

/// # Data Access
impl FileNameAndHash {
    /// Creates a new value.
    pub fn new(file_name: Option<Bytes>, hash: Bytes) -> Self {
        FileNameAndHash { file_name, hash }
    }

    /// Returns a reference to the file name.
    pub fn file_name(&self) -> Option<&Bytes> {
        self.file_name.as_ref()
    }

    /// Returns a reference to the hash.
    pub fn hash(&self) -> &Bytes {
        &self.hash
    }

    /// Returns a pair of the file and the hash.
    pub fn into_pair(self) -> (Option<Bytes>, Bytes) {
        (self.file_name, self.hash)
    }
}

impl FileNameAndHash {
    /// Skips over an optional value in a constructed value.
    fn skip_opt_in<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<()>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let file = Ia5String::take_opt_from(cons)?.map(|f| f.into_bytes());
            if let Some(file) = &file {
                if let Err(err) = Self::validate_file_name(file) {
                    return Err(cons.content_err(err)); 
                }
            }
            OctetString::take_from(cons)?;
            Ok(())
        })
    }

    /// Takes an optional value from the beginning of a constructed value.
    fn take_opt_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let file = Ia5String::take_opt_from(cons)?.map(|f| f.into_bytes());
            if let Some(file) = &file {
                if let Err(err) = Self::validate_file_name(file) {
                    return Err(cons.content_err(err)); 
                }
            }
            Ok(FileNameAndHash {
                file_name: file,
                hash: OctetString::take_from(cons)?.into_bytes(),
            })
        })
    }

    /// Check whether the file name matches RFC 9323:
    /// FROM("a".."z" | "A".."Z" | "0".."9" | "." | "_" | "-"))
    fn validate_file_name(name: &[u8]) -> Result<(), &'static str> {
        fn valid_rfc9323_character(c: u8) -> bool {
            c == b'-' || c == b'_' || c == b'.' || c.is_ascii_alphanumeric()
        }

        let mut n = name;
        while let Some((c, tail)) = n.split_first() {
            n = tail;
            if !valid_rfc9323_character(*c) {
                return Err("rsc filename is not RFC 9323 compliant");
            }
        }

        Ok(())
    }
}

mod tests {
    #[test]
    fn decode_rsc() {
        let data = 
            include_bytes!("../../test-data/rsc/apnictraining-test.sig");
        let data = bytes::Bytes::from(data.to_vec());
        crate::repository::Rsc::decode(data.clone(), false).unwrap();
        let rsc = crate::repository::Rsc::decode(data.clone(), true).unwrap();
        assert!(rsc.as_ref().iter().all(|item| 
            item.file_name() == Some(&bytes::Bytes::from("test.txt"))));
    }
}