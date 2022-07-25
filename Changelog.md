# Changelog

## Unreleased future version

Breaking Changes

New

Bug Fixes

* Don’t produce or allow empty Subject Information Access certificate
  extensions. ([#220])

Other Changes

[#220]: https://github.com/NLnetLabs/rpki-rs/pull/220

## 0.15.0

Released 2022-07-18.

Breaking Changes

* Multiple changes to support BGPsec CSRs ([#210]):
  * Moved `repository::crypto` into its own top-level module and added a
    separate `crypto` feature.
  * Added separate signature algorithm types for RPKI and BGPsec and added a
    `SignatureAlgorithm` trait so the two can be used in parallel.
  * Made `crypto::signature::Signature` generic over the signature algorithm.
  * Changed the `Signer` trait and soft-signer implementation to be able to
    deal with both signature algorithm types via an intermediary
    `SigningAlgorithm` enum.
  * Made `repository::x509::SignedData` generic over the signature algorithm
    type so it can be used for both RPKI and BGPsec objects.
  * Moved `repository::oid` into its own top-level module and made it depend
    on the `bcder` feature.
  * Moved `repository::csr` to `ca::csr`.
  * Changes the `ca::csr`’s types to be generic over the signature algorithms
    and CSR attributes.
  * Changed the type of the Extended Key Usage attribute of certificates and
    CSRs into a newtype around the wrapping capture.
  * Add missing functionality to `TbsCert` and `CertBuilder` to be able to
    generate router certificates.
* Completely redesigned error handling ([#211]):
  * Switch decoding errors to the new errors defined in bcder 0.7.
  * Define dedicated error types for the inspection and verification
    phases of object validation with `ValidationError` an umbrella type
    for all three phases.
  * All errors now format into an explanation of the issue.
* In the `repository` module, renamed various methods from `validate_*` to
  either `inspect_*` or `verify_*` for consistency. ([#211])

New

* Added support for RFC 8183 out-of-band XML exchanges between CAs, their
  parents, and their publication server. ([#208])
* Added support for RFC 8181 Publication Protocol exchanges. ([#208])
* Added support for RFC 6492 exchanges between issuer and subject of
  resources. ([#208])
* RSA public keys can now be created from their components and raw key
  bits. ([#212])

Other Changes

* Updated `uuid` crate to version 1.1. ([#215])
* Updated `quick-xml` crate to version 0.23. ([#216])

[#208]: https://github.com/NLnetLabs/rpki-rs/pull/208
[#210]: https://github.com/NLnetLabs/rpki-rs/pull/210
[#211]: https://github.com/NLnetLabs/rpki-rs/pull/211
[#212]: https://github.com/NLnetLabs/rpki-rs/pull/212
[#215]: https://github.com/NLnetLabs/rpki-rs/pull/215
[#216]: https://github.com/NLnetLabs/rpki-rs/pull/216



## 0.14.2

Released 2022-02-10.

New

* Added `Display` impl to `rtr::pdu::RouterKeyInfo`. It outputs the key in
  Base 64 as used by [RFC 8416] local exception files. ([#187])
* Added `repository::roa::RouteOriginAttestation::iter_origins` that
  iterates over the content as `rtr::payload::RouteOrigins`. ([#188])
* Dropped the `non_exhaustive` attribute from `rtr::payload::Payload`.
  ([#189])
* Added `repository::crypto::keys::PublicKey::bit_bytes` which returns
  the key’s bits as a shareable `Bytes` value. ([#193])
* Added iterators over individual ASNs to
  `repository::resources::AsBlock` and `repository::resources::AsBlocks`.
  ([#194])

Bug Fixes

* Added a check to manifest validation that _thisUpdate_ is before
  _nextUpdate_ as mandated by [RFC 6486]. ([#191])
* `rtr::payload::RouteOrigin` now compares considering a missing max
  length equal to a max length set to the prefix length. This is necessary
  to filter out duplicates in RTR where max len is always given. ([#195])
* The RTR client and server now flush their sockets before waiting. This
  is necessary for TLS support where data is buffered. ([#196])

[#187]: https://github.com/NLnetLabs/rpki-rs/pull/187
[#188]: https://github.com/NLnetLabs/rpki-rs/pull/188
[#189]: https://github.com/NLnetLabs/rpki-rs/pull/189
[#191]: https://github.com/NLnetLabs/rpki-rs/pull/191
[#193]: https://github.com/NLnetLabs/rpki-rs/pull/193
[#194]: https://github.com/NLnetLabs/rpki-rs/pull/194
[#195]: https://github.com/NLnetLabs/rpki-rs/pull/195
[#196]: https://github.com/NLnetLabs/rpki-rs/pull/196
[RFC 6486]: https://tools.ietf.org/html/rfc6486


## 0.14.1

Released 2022-01-11.

Bug Fixes

* Removed a left over debug println. ([#185])

[#185]: https://github.com/NLnetLabs/rpki-rs/pull/185


## 0.14.0

Released 2022-01-10. Yanked from crates.io on 2022-01-11.

Breaking Changes

* The type for autonomous system numbers has been renamed from `AsId` to
  `Asn`. In addition, the `Asn` type from [_routecore_] is used rather
  than defining a separate type. It is, however, being re-exported at the
  old location. ([#175])
* The Serde serialization format for `Asn` has changed: it now serializes
  as number rather than a string. The type exposes methods for use with
  Serde’s field attributes to retain the old formatting.
* The type for public key identifier, `KeyIdentifer`, has moved to
  [_routecore_] but is exposed at its old location.
  As a consequence of the move, `KeyIdentifier::from_public_key` has
  been removed. Please use `PublicKey::key_identifier` instead. ([#175])
* The RTR payload types have been revised to use types from [_routecore_].
  Support for BGPsec router keys was added. ([#177])

New

* Added parsing and generation of local exception files defined in [RFC 8416]
  via the new `slurm` module, available if the `"slurm"` feature is
  enabled. ([#178])

[#175]: https://github.com/NLnetLabs/rpki-rs/pull/175
[#177]: https://github.com/NLnetLabs/rpki-rs/pull/177
[#178]: https://github.com/NLnetLabs/rpki-rs/pull/178
[RFC 8416]: https://tools.ietf.org/html/rfc8416
[_routecore_]: https://github.com/NLnetLabs/routecore


## 0.13.1

Released 2021-11-17.

No changes since 0.13.1-rc2.


## 0.13.1-rc2

Released 2021-11-10.

Other Changes

* ASPA: Switch to final content type OID. ([#173])

[#173]: https://github.com/NLnetLabs/rpki-rs/pull/173

## 0.13.1-rc1

Released 2021-11-05.

Other Changes

* ASPA: support empty sequences of provider ASes. ([#171])

[#171]: https://github.com/NLnetLabs/rpki-rs/pull/171


## 0.13.0

Released 2021-11-01.

Breaking Changes

* The minimal supported Rust version is now 1.47. ([#158])
* All methods of the `repository::crypto::signer::Signer` trait are now
  taking a `&self` (some required a `&mut self` before). ([#162])
* The subject name generated by `repository::crypto::keys::PublicKeyCn`
  is now the hex encoded key identifier rather then the full key to
  confirm with length requirements. As a side effect, the type is now
  static and copy. ([#165])

New

* Access methods for the signing time in signed objects and RTA
  multi-signed objects. ([#169])
* Experimental support for ASPA objects. ([#166])

[#158]: https://github.com/NLnetLabs/rpki-rs/pull/158
[#162]: https://github.com/NLnetLabs/rpki-rs/pull/162
[#166]: https://github.com/NLnetLabs/rpki-rs/pull/166
[#169]: https://github.com/NLnetLabs/rpki-rs/pull/169


## 0.12.2

Released 2021-08-02.

New

* Strict checking for address and prefix lengths in certificates, and for
  prefix and max-length in ROAs. ([#154], based on an error report by
  [@job])

[#154]: https://github.com/NLnetLabs/rpki-rs/pull/154
[@job]: https://github.com/job


## 0.12.1

Released 2021-07-26.

Bug Fixes

* `rtr`: Corrected the PDU type of the Cache Reset PDU from 7 to 8.
  ([#151])

[#151]: https://github.com/NLnetLabs/rpki-rs/pull/151


## 0.12.0

Released 2021-07-18.

Breaking

* Added the ability to create and write the various RRDP files. This
  results in various changes to the types for handling RRDP files.
  ([#144]) 

New

* Added a simple XML writer. ([#144])
* Add `uri::Https::{path, canonical_authority, as_slice}`. ([#147])

Bug Fixes

* Accept empty `<publish>` elements in RRDP snapshot and delta files.
  While publishing empty files doesn’t make all that much sense, the
  standard formally allows it, so we shouldn’t reject updates because of
  it. ([#148)]

[#144]: https://github.com/NLnetLabs/rpki-rs/pull/144
[#147]: https://github.com/NLnetLabs/rpki-rs/pull/147
[#148]: https://github.com/NLnetLabs/rpki-rs/pull/148


## 0.11.1

Released 2021-07-08.

This version was yanked 2021-07-18 and re-published as 0.12.0 because it
contained breaking changes.


## 0.11.0

Released 2021-05-17.

Breaking

* Restructured content by moving all modules related to processing RPKI
  repository objects to a new `repository` module. ([#119])
* Introduced features for selecting which parts of the crate are required.
  For the content previously included, these are: `repository` for
  processing of RPKI repository objects, `rrdp` for RRDP support, and
  `serde` for adding serde support to repository objects. ([#119])
* Restructured handling of rsync URIs: There is now only a single type
  `uri::Rsync` for both rsync module URIs and URIs below module level.
  The type `uri::RsyncModule` has been dropped. Instead, `uri::Rsync` now
  allows access to the URI’s content as a single bytes slice. ([#124])
* The `rrdp` module now provides access to object content via a reader
  rather then decoding it into a vec. In addition, `rrdp::DigestHex` has
  been renamed to the more clear `rrdp::Hash` and turned into a wrapper
  around a fixed-size array. ([#129])
* `SignedObject::process` and `Roa::process` now also return the EE
  certificate on success. ([#131])
* `RoaIpAddress` and `FriendlyRoaIpAddress` are now `Copy`. ([#131])
* Upgrade `bytes` and `tokio` to 1.0. ([#121])
* The minimum required Rust version is now 1.43. ([#121])

New

* New module `rtr`, enabled via the feature `rtr` that contains what was
  previously available via the separated `rpki-rtr` crate. ([#120])
* `ManifestHash` now allows access to its components via the `algorithm`
  and `as_slice` methods. ([#126]) It also implements `Hash`, `PartialEq`,
  and `Eq`. ([#128])
* `DigestAlgorithm` instances can now be created for the SHA-256 algorithm
  and values can be checked whether they in fact represent the SHA-256
  algorithm. Values now also provide the associated digest length via the
  new `digest_len` method. ([#126])
* Certificate and signed object validation (strictly speaking: inspection) now
  follow OpenSSL’s practice of refusing certificates with mismatching encoding
  of the signature algorithm inside and outside the signed portion.
  ([#130])

Bug Fixes

* `Validity::from_duration` now correctly deals with negative durations.
  ([#131])

Other Changes

[#119]: https://github.com/NLnetLabs/rpki-rs/pull/119
[#120]: https://github.com/NLnetLabs/rpki-rs/pull/120
[#121]: https://github.com/NLnetLabs/rpki-rs/pull/121
[#124]: https://github.com/NLnetLabs/rpki-rs/pull/124
[#126]: https://github.com/NLnetLabs/rpki-rs/pull/126
[#128]: https://github.com/NLnetLabs/rpki-rs/pull/128
[#129]: https://github.com/NLnetLabs/rpki-rs/pull/129
[#139]: https://github.com/NLnetLabs/rpki-rs/pull/130
[#131]: https://github.com/NLnetLabs/rpki-rs/pull/131


## 0.10.1

Released 2021-05-10.

New

* `resources::AsBlocks::difference` and `resources::IpBlocks::difference`.
  ([#138])

[#138]: https://github.com/NLnetLabs/rpki-rs/pull/138


## 0.10.0

Released 2020-10-07.

Breaking

* `crypto::key::PublicKeyFormat` has been changed into an enum in order to
  be able to deal with two different possible public key algorithms. It
  and `crypto::key::PublicKey` also received functions to determine
  whether the algorithms and keys are allowed in regular RPKI certificates
  or router certificates. ([#113])
* The type for RRDP serial numbers has been changed to `u64` from `usize`.
  This affects the various traits in the `rrdp` module. ([#111])
* `crl::CrlStore` has been deprecated. The new rules for manifest handling
  have clarified that there must only ever be one CRL for each CA. The
  `CrlStore` was designed to make it easier to deal with cases where there
  are multiple CRLs and is therefore not necessary any more. ([#112])
* The minimum required Rust version is now 1.42. ([#108])

New

* `cert::Cert` can now decode, inspect, and verify BGPSec router
  certificates. ([#113])
* Module `rta` for handling Resource Tagged Assertions. ([#108])
* `crypto::DigestAlgorithm::digest_file` allows calculating the digest
  value of an entire file.  ([#108])
* `IpBlock` can now be displayed via helper types to select IPv4 or IPv6.
  ([#108])
* `SignedObject::process` to validate generic signed objects and return
  their content on success. ([#108])
* The various steps in certificate validation are now available as
  separate methods. ([#108])
* New methods:
  * `resources::AsBlock::is_whole_range` ([#110)]
  * `resources::IpBlock::is_slash_zero` ([#110)]
  * `resources::IpBlocks::contains_block` and `intersects_block` ([#110)]
  * `roa::FriendlyRoaIpAddress::prefix` and `is_v4` ([#110)]

Bug Fixes

* Don’t refuse an rpkiNotify SIA in EE certificates in strict validation mode. 
  The spec is somewhat contradictory on whether they are allowed or now,
  so we should allow them. ([#105])
* Do not include a parameter to the algorithm identifier of the SHA-256
  digest algorithm. ([#109])

[#105]: https://github.com/NLnetLabs/rpki-rs/pull/105
[#108]: https://github.com/NLnetLabs/rpki-rs/pull/108
[#109]: https://github.com/NLnetLabs/rpki-rs/pull/109
[#110]: https://github.com/NLnetLabs/rpki-rs/pull/110
[#111]: https://github.com/NLnetLabs/rpki-rs/pull/111
[#112]: https://github.com/NLnetLabs/rpki-rs/pull/112
[#113]: https://github.com/NLnetLabs/rpki-rs/pull/113


## 0.9.2

New

* The new method `Tal::prefer_https` reorders the URIs of a TAL so that the
  HTTPS URIs appear first. ([#106])

[#106]: https://github.com/NLnetLabs/rpki-rs/pull/106


## 0.9.1

New

* `Tal`s can now be created with an explicit name for their `TalInfo`
  instead of deriving the name from the path. ([#102)]
* All types from the `uri` module now have a `authority` method that provides
  access to the authority portion of the URI (a.k.a., the hostname).
  [(#103)]
* All types from the `uri` module now have a method `unshare` that causes
  to value to use its own memory, possibly freeing up the shared memory
  block they were taken out of earlier and saving memory. [(#103)]

Dependencies

* Update `base64` to 0.12. ([#101])
* Dropped dependency on `unwrap` and `derive_more`. ([#101])

[#101]: https://github.com/NLnetLabs/rpki-rs/pull/101
[#102]: https://github.com/NLnetLabs/rpki-rs/pull/102
[#103]: https://github.com/NLnetLabs/rpki-rs/pull/102


## 0.9.0

Breaking

* The minimum supported Rust version is now 1.40.0. ([#96])
* The crate now requires ring 0.16. ([#96])

Bug Fixes

* Fix `Time::years_from_now` to work on February 29. ([#95], thanks to
  [@dadepo]).

Dependencies

* Upgrade to bytes 0.5 and bcder 0.5. ([#99])

[#95]: https://github.com/NLnetLabs/rpki-rs/pull/95
[#96]: https://github.com/NLnetLabs/rpki-rs/pull/96
[#99]: https://github.com/NLnetLabs/rpki-rs/pull/99
[@dadepo]: https://github.com/dadepo


## 0.8.3

Bug Fixes

* Fix an issue in resource range calculation that could result in a range
  added in parts being encoded in multiple ranges. [(#93)]

[(#93)]: https://github.com/NLnetLabs/rpki-rs/pull/93


## 0.8.2

Bug Fixes

* Fix trimming of large resource sets. [(#91)]
* Fix creation of IPv4 resources from strings. [(#91)]

[(#91)]: https://github.com/NLnetLabs/rpki-rs/pull/91


## 0.8.1

New

* `uri::Https::join` [(#87)]

Bug Fixes

* Fix order of signed attributes in created signed objects. (New versions
  of Bouncy Castle insist on that.) [(#88)]

[(#87)]: https://github.com/NLnetLabs/rpki-rs/pull/87
[(#88)]: https://github.com/NLnetLabs/rpki-rs/pull/88


## 0.8.0

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


## 0.7.0

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


## 0.6.0

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


## 0.5.0

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


## 0.4.0

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

