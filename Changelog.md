# Change Log

# Unreleased next version

Breaking

* The minimum supported Rust version is now 1.34.0. [(#34)]
* Restructured how certificate’s SubjectAccessInfo is parsed and accessed.
  It now keeps the first mandatory URI of the four relevant access methods
  readily available. [(#34)]
* `Cert` has completely changed, `CertBuilder` is gone and has been
  replaced by `TbsCert` which can be used for building. [(#39)]
* Similarly, `Crl` has completely changed, `CrlBuilder` is gone and has been
  replaced by `TbsCertList` which can be used for building. [(#39)]
* How `SignedObject`, `Manifest`, and `Roa` are being built has completely
  changed. [(#39)]
* `crl::Crl`, `x509::Name`, `x509::SignedData`: `encode` renamed to
  `encode_ref` to comply with standard naming scheme. [(#39)]
* `DigestAlgorithm`, `PublicKeyFormat`, and `SignatureAlgorithm` are not
  unit structs anymore. They impl `Default` which should be used to get
  the recommended (read: only available) values. This is so we can
  transparently change them into enums later on if necessary. [(#39)]
* `cert::Validity` is now `Copy` and isn’t returned or used by reference
  anymore. [(#39)]
* `Signer` has gained another mandatory method `rand` that can be used to
  generate random data. [(#41)]

New

* Conversion from strings and formatting for the various forms of IP
  and AS resources. [(#32)]
* `uri::Rsync` and `uri::Https` now compare the authority part ignoring
  ASCII-case. [(#34)]
* New modules `xml` with support for XML parsing and `rrdp` with support
  for RRDP parsing. [(#34)]
* Implement *serde* traits for URI types. [(#37)]
* Implement *serde* traits, equality comparison, `FromStr` and `Display`
  for resources. [(#38)]
* New constant size type `Serial` wrapping serial numbers. [(#39)]
* Added `serde` traits for certificates, CRLs, manifests, and ROAs via a
  base64 encoded string. [(#42)]

Bug Fixes

* Add `CertBuilder::ca_repository` for the CA Repository Subject
  Information Access value in order to be able to build valid CA
  certificates. [(#34)]
* Fix `uri::Https::encode_general_name` and `uri::Https::encode_general_name`
  to not wrap the URI in a sequence. [(#39)]

Dependencies


[(#32)]: https://github.com/NLnetLabs/rpki-rs/pull/32
[(#34)]: https://github.com/NLnetLabs/rpki-rs/pull/34
[(#37)]: https://github.com/NLnetLabs/rpki-rs/pull/37
[(#38)]: https://github.com/NLnetLabs/rpki-rs/pull/38
[(#41)]: https://github.com/NLnetLabs/rpki-rs/pull/41
[(#42)]: https://github.com/NLnetLabs/rpki-rs/pull/42


## 0.3.3

Bug Fixes

* Fix an unwrap on `Option` in `Chain::is_encompassed` when the other
  chain ends before this block. [(#30)]

[(#30)]: https://github.com/NLnetLabs/rpki-rs/pull/30


## 0.3.2

Dependencies

* Require *bcder* of at least 0.2.1. This was required already but not
  reflected in `Cargo.toml`.


## 0.3.1

New

* `SignedObject::take_from` will now return a malformed error if the
  certificate in the signed object is of any other choice than a plain
  certificate. This was a not implemented error before.
* `RoaBuilder` for making ROAs. [(#25)]
* `ManifestBuilder` for making manifests. [(#26)]

Bug Fixes

* Decoding manifest and ROAs now checks that the content type field in the
  signed object has the correct object identifier. [(#27)]


[(#25)]: https://github.com/NLnetLabs/rpki-rs/pull/25
[(#26)]: https://github.com/NLnetLabs/rpki-rs/pull/26
[(#27)]: https://github.com/NLnetLabs/rpki-rs/pull/27


## 0.3.0

Breaking Changes

* New module `crypto` includes the now removed module `signer` and all
  crypto-related types. The latter have been re-designed as well.

* Resource handling in modules `asres` and `ipres` entirely redesigned
  and moved to a shared `resources` module. [(#17)]

* IP resources in `Cert` and `ResourceCert` broken up into `v4_resources`
  and `v6_resources` handled independently. [(#17)]

* `roa::RoaStatus::Valid` now contains the complete resource certificate
  of the ROA. This change is reflected in the methods of
  `roa::RouteOriginAttestation` that deal with the ROA status.

* `uri::Rsync::from_str` and `uri::Http::from_str` moved to `FromStr`
  implementations. [(#21)]

* `uri::Scheme::to_string` replaced with `into_string`. [(#21)]

*  Drop use of _failure_ crate. Error types now provide a `Display`
   implementation only. [(#22)]


New

* `DigestAlgorithm` allows digesting, `PublicKeyFormat` allows checking
  signatures.

* `cert::CertBuilder` for making certificates. [(#16)]

* `uri::Rsync::relative_to` for finding a relative path.

* Added methods:

  * `cert::ResourceCertificate::into_tal`, `signed_object_uri`,
    `validity`.

  * `cert::Validity::not_before` and `not_after`,

  * `Manifest::is_stale` and `Crl::is_stale`. [(#19)]

  * `uri::Rsync::is_parent`.

* `x509::Time` now derefs to `chrono::DateTime<chrono::Utc>`.


[(#16)]: https://github.com/NLnetLabs/rpki-rs/pull/16
[(#17)]: https://github.com/NLnetLabs/rpki-rs/pull/17
[(#19)]: https://github.com/NLnetLabs/rpki-rs/pull/19
[(#21)]: https://github.com/NLnetLabs/rpki-rs/pull/21
[(#22)]: https://github.com/NLnetLabs/rpki-rs/pull/22
[(#23)]: https://github.com/NLnetLabs/rpki-rs/pull/23


## 0.2.0

Breaking Changes

* `cert::Cert::validate_ta`: new argument for the new `tal::TalInfo` struct
  containing information about the TAL this trust anchor is based on.

New

* `cert::ResourceCert` now provides information about the trust anchor
  this certificate is derived from. This can be used to present the trust
  anchor name in validated output.

  The name will be based on the stem of the file name of the TAL file.

* `roa::RouteOriginAttestation`` now has a `status` function that returns
  a reference to a `RoaStatus` enum with information about the ROA’s
  status.

* `Crl` can now cache the list of serials speeding up its `contain`
  function from O(n) to O(1)~ at the price of preparing a hash set.

* `Manifest` can now tell you how many files there are.

* `cert::ext::UriGeneralName` now implements `Display`.


## 0.1.0

Initial public release.

