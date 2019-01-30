# Change Log


## Unrelease next version

Breaking Changes

* New module `crypto` includes the now removed module `signer` and all
  crypto-related types. The latter have been re-designed as well.

* `roa::RoaStatus::Valid` now contains the complete resource certificate
  of the ROA. This change is reflected in the methods of
  `roa::RouteOriginAttestation` that deal with the ROA status.


New

* `DigestAlgorithm` allows digesting, `PublicKeyFormat` allows checking
  signatures.

* `cert::CertBuilder` for making certificates. [(#16)]

* `uri::Rsync::relative_to` for finding a relative path.

* Added methods:

  * `cert::ResourceCertificate::into_tal`, `signed_object_uri`,
    `validity`.


Bug Fixes

Dependencies

[(#49)]: https://github.com/NLnetLabs/rpki-rs/pull/16


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

