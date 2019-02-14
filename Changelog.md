# Change Log


## Unrelease next version

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


Bug Fixes


Dependencies

[(#16)]: https://github.com/NLnetLabs/rpki-rs/pull/16
[(#17)]: https://github.com/NLnetLabs/rpki-rs/pull/17
[(#19)]: https://github.com/NLnetLabs/rpki-rs/pull/19
[(#21)]: https://github.com/NLnetLabs/rpki-rs/pull/21


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

