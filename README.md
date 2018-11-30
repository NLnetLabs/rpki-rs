# rpki – A Library for Validating and Creating RPKI Data

This crate aims to provide the foundation for implementing Resource
Public Key Infrastructure – RPKI –, which is an important building block
in Internet routing security. The crate provides the ability to parse,
validate, and create the the objects published in the RPKI: certificates,
CRLs, manifests, and ROAs. It also provides functionality share between
certification authority and publication software such as the protocol the
two use for communication.

The crate is work in progress and will grow over time to be more and more
complete.


## Usage

Add the following dependency to your `Cargo.toml`:

```
[dependencies]
rpki = "^0.1"
```

Sadly, at this time, we don’t have a usage guide or detailed documentation
for the crate. We are planning to rectify this oversight in the near
future.


## Contributing

If you have comments, proposed changes, or would like to contribute,
please open an issue in the [Github repository]. In particular, if you
would like to use the crate but it is missing functionality for your use
case, we would love to hear from you!

[Github repository]: (https://github.com/NLnetLabs/rpki-rs)

## License

The _rpki_ crate is distributed under the terms of the BSD-3-clause license.
See LICENSE for details.

