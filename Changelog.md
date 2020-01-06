# Change Log

# 0.8.3

Bug Fixes

* Fix an issue in resource range calculation that could result in a range
  added in parts being encoded in multiple ranges. [(#93)]

[(#93)]: https://github.com/NLnetLabs/rpki-rs/pull/93


# 0.8.2

Bug Fixes

* Fix trimming of large resource sets. [(#91)]
* Fix creation of IPv4 resources from strings. [(#91)]

[(#91)]: https://github.com/NLnetLabs/rpki-rs/pull/91


# 0.8.1

New

* `uri::Https::join` [(#87)]

Bug Fixes

* Fix order of signed attributes in created signed objects. (New versions
  of Bouncy Castle insist on that.) [(#88)]

[(#87)]: https://github.com/NLnetLabs/rpki-rs/pull/87
[(#88)]: https://github.com/NLnetLabs/rpki-rs/pull/88


# 0.8.0

Breaking

* Encoding of `x509::Time` values changed since in some cases it needs to
  encode as either UTCTime or GeneralizedTime depending on the year. Thus,
  there is no simple `encode` method anymore but rather, there now is
  `encode_utc_time`, `encode_generalized_time`, or `encode_varied` to make
  the choice explicit. [(#84)]

Bug Fixes

* Stop refusing to make IPv6-only ROAs (this wasn’t on purpose, honest).
  [(#82)]
* Empty `IpBlocks` and `AsBlocks` where equal to everything. [(#83)]
* Don’t include the values that are at their default value in the DER
  encoding. [(#85)]

[(#82)]: https://github.com/NLnetLabs/rpki-rs/pull/82
[(#83)]: https://github.com/NLnetLabs/rpki-rs/pull/83
[(#84)]: https://github.com/NLnetLabs/rpki-rs/pull/84
[(#85)]: https://github.com/NLnetLabs/rpki-rs/pull/85


# 0.7.0

Breaking

* Dot segments (‘.’ and ‘..’) and empty segments (except for the final
  segment) are not allowed anymore in rsync URIs and will lead to URIs being
  rejected. The `uri::Error`  enum has received new variants for these cases.
  [(#77)]

New

* Added access to signing time and binary signing time in signed object
  builder. [(#80)]

Bug Fixes

* Fixed a decoding and encoding error in manifests’ version field which
  caused certain manifests (which don’t seem to be existing in the wild 
  currently) to be rejected and produced manifests to be invalid. [(#78)]
* Don’t include empty address families in a produced ROA. [(#79)]

Other Changes

* Optional versions are not included in encoded ROAs and manifests
  anymore. This fixes some interoperability issues. [(#78)]

[(#77)]: https://github.com/NLnetLabs/rpki-rs/pull/77
[(#78)]: https://github.com/NLnetLabs/rpki-rs/pull/78
[(#79)]: https://github.com/NLnetLabs/rpki-rs/pull/79
[(#80)]: https://github.com/NLnetLabs/rpki-rs/pull/80


# 0.6.0

Breaking

* Hashes in the `rrdp` module are now of a new type `DigestHex` and are
  automatically converted from their hex representation. [(#62)]
* Removed `uri::Http`. [(#63)]
* `tal::Tal::uris` now returns an iterator over `tal::TalUri`s, which can
  be either an rsync or HTTPS URI. [(#63)]
* Removed the ARIN tal workaround. [(#63)]
* Removed the `to_string` methods from URI types as these are available
  via the `ToString` trait which is implemented via `Display`. [(#67)]
* Renamed `IpBlocks::contains` to `IpBlocks::contains_roa`. [(#72)]

New

* Add set operations `union`, `intersection`, and `contains` to `IpBlocks`
  and `AsBlocks`. [(#72)]
* Add various useful impls of `From` for `x509::Time`. [(#69)]

Bug Fixes

* Various improvements to the RRDP implementation. [(#62)]
* Fix a endless loop and an off-by-one error in Chain::trim. [(#64)]
* The `version` field of a ROA’s `RouteOriginAttestation` structure was
  parsed and constructed as implicitly tagged whereas the standard demands
  explicit tagging. This would have lead to a parse error for all ROAs
  that actually contain the (optional) version field. [(#70)]
* Fix encoding of CRLs. [(#73)]

[(#62)]: https://github.com/NLnetLabs/rpki-rs/pull/62
[(#63)]: https://github.com/NLnetLabs/rpki-rs/pull/63
[(#64)]: https://github.com/NLnetLabs/rpki-rs/pull/64
[(#67)]: https://github.com/NLnetLabs/rpki-rs/pull/67
[(#69)]: https://github.com/NLnetLabs/rpki-rs/pull/69
[(#70)]: https://github.com/NLnetLabs/rpki-rs/pull/70
[(#73)]: https://github.com/NLnetLabs/rpki-rs/pull/73


# 0.5.0

Breaking

* Moved `x509::KeyIdentifier` to `crypto::key::KeyIdentifier`. It also
  contains a byte array and is `Copy`. Subsequently,
  `Cert::subject_key_identifier` and `Cert::authority_key_identifier`
  return values instead of references now. [(#51)]
* Explicitly set issuer name in `SignedObjectBuilder`. Drop `cert`
  argument from `SignedObjectBuilder::finalize`, `RoaBuilder::finalize`,
  and `Manifest::finalize`. [(#54)]

New

* Add `CrlEntry::new` so these can actually be created. [(#49)]
* `Manifest` now derefs to `ManifestContent` which adds accessors for its
  attributes. `Manifest` also allows access to the EE certificate via the
  `cert` method. [(#50)].
* Implement serialization for `crypto::keys::KeyIdentifier`,
  `x509::Serial`, `x509::Time`, and `x509::Validity`. [(#51)]
* Add `impl Sub<Duration> for Time`. [(#56)]
* Add `mkrpki`, a command line tool for creating RPKI objects. [(#54)]
* Parse, validate, construct, (de-)serialize `Csr`. [(#58)]
* Parse decimal string format used by RFC6492 for `AsId`. [(#60)]

Bug Fixes

* IP address prefixes (`resources::Prefix`) were encoded wrongly if their
  length was not divisible by 8. ([#55)]

Dependencies

* Update *ring* to 0.14. [(#53)]
* Update *base64* to 0.10. [(#57)]


[(#49)]: https://github.com/NLnetLabs/rpki-rs/pull/49
[(#50)]: https://github.com/NLnetLabs/rpki-rs/pull/50
[(#51)]: https://github.com/NLnetLabs/rpki-rs/pull/51
[(#53)]: https://github.com/NLnetLabs/rpki-rs/pull/53
[(#54)]: https://github.com/NLnetLabs/rpki-rs/pull/54
[(#55)]: https://github.com/NLnetLabs/rpki-rs/pull/55
[(#56)]: https://github.com/NLnetLabs/rpki-rs/pull/56
[(#57)]: https://github.com/NLnetLabs/rpki-rs/pull/57


# 0.4.0

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
* `Crl::next_update` field is now mandatory as per RFC 5280. [(#44)]

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
* More convenience for dealing with `x509::Time`. [(#43)]

Bug Fixes

* Add `CertBuilder::ca_repository` for the CA Repository Subject
  Information Access value in order to be able to build valid CA
  certificates. [(#34)]
* Fix `uri::Https::encode_general_name` and `uri::Https::encode_general_name`
  to not wrap the URI in a sequence. [(#39)]


[(#32)]: https://github.com/NLnetLabs/rpki-rs/pull/32
[(#34)]: https://github.com/NLnetLabs/rpki-rs/pull/34
[(#37)]: https://github.com/NLnetLabs/rpki-rs/pull/37
[(#38)]: https://github.com/NLnetLabs/rpki-rs/pull/38
[(#41)]: https://github.com/NLnetLabs/rpki-rs/pull/41
[(#42)]: https://github.com/NLnetLabs/rpki-rs/pull/42
[(#43)]: https://github.com/NLnetLabs/rpki-rs/pull/43
[(#44)]: https://github.com/NLnetLabs/rpki-rs/pull/44


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

