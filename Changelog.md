# Change Log

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

Bug Fixes

Dependencies


## 0.1.0

Initial public release.

