# aws-mls &emsp; [![Build Status]][actions] [![Latest Version]][crates.io]

[![API Documentation]][docs.rs]

[build status]: https://img.shields.io/github/workflow/status/WickrInc/mls/CI/master
[actions]: https://github.com/WickrInc/mls/actions?query=branch%3Amaster
[latest version]: https://img.shields.io/crates/v/aws-mls.svg
[crates.io]: https://crates.io/crates/aws-mls
[api documentation]: (https://docs.rs/aws-mls/badge.svg)
[docs.rs]: (https://docs.rs/aws-mls)

<!-- cargo-sync-readme start -->

An implementation of the [Messaging Layer Security](https://messaginglayersecurity.rocks) standard,
based on Draft 12 of the RFC. Cryptographic operations are supported by [Ferriscrypt](https://github.com/WickrInc/ferriscrypt).

## Supported Ciphersuites


* `MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
* `MLS10_128_DHKEMP256_AES128GCM_SHA256_P256`
* `MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
* `MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448`
* `MLS10_256_DHKEMP521_AES256GCM_SHA512_P521`
* `MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448`


## Supported Extensions


* `capabilities`
* `lifetime`
* `external_key_id`
* `parent_hash`
* **TODO**: `ratchet_tree`


## Supported Proposal Types

* `add`
* `update`
* `remove`
* *TODO*: `psk`
* *TODO*: `reinit`
* *TODO*: `external_init`
* *TODO*: `app_ack`
* *TODO*: `group_context_extensions`

## Supported Credential Types

* `basic`
* `x509`

<!-- cargo-sync-readme end -->

## License

This software is distributed under the [Apache License, version 2.0](https://www.apache.org/licenses/LICENSE-2.0.html)

```
   Copyright 2022 Wickr, Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```
