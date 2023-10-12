# aws-mls &emsp; [![Build Status]][actions] [![Latest Version]][crates.io]

[![API Documentation]][docs.rs]

[build status]: https://img.shields.io/github/workflow/status/WickrInc/mls/CI/master
[actions]: https://github.com/WickrInc/mls/actions?query=branch%3Amaster
[latest version]: https://img.shields.io/crates/v/aws-mls.svg
[crates.io]: https://crates.io/crates/aws-mls
[api documentation]: (https://docs.rs/aws-mls/badge.svg)
[docs.rs]: (https://docs.rs/aws-mls)

<!-- cargo-sync-readme start -->

An implementation of the [IETF Messaging Layer Security](https://messaginglayersecurity.rocks)
end-to-end encryption (E2EE) protocol.

## What is MLS?

MLS is a new IETF end-to-end encryption standard that is designed to
provide transport agnostic, asynchronous, and highly performant
communication between a group of clients.

## MLS Protocol Features

* Multi-party E2EE [group evolution](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-cryptographic-state-and-evo)
via a propose-then-commit mechanism.
* Asynchronous by design with pre-computed [key packages](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-key-packages),
allowing members to be added to a group while offline.
* Customizable credential system with built in support for X.509 certificates.
* [Extension system](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-extensions)
allowing for application specific data to be negotiated via the protocol.
* Strong forward secrecy and post compromise security.
* Crypto agility via support for multiple [ciphersuites](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-mls-ciphersuites).
* Pre-shared key support.
* Subgroup branching.
* Group reinitialization (ex: protocol version upgrade).

## Features

* Easy to use client interface that manages multiple MLS identities and groups.
* 100% RFC conformance with support for all default credential, proposal,
  and extension types.
* Async API with async trait based extension points.
* Configurable storage for key packages, secrets and group state
  via provider traits along with default "in memory" implementations.
* Support for custom user created proposal, and extension types.
* Ability to create user defined credentials with custom validation
  routines that can bridge to existing credential schemes.
* OpenSSL and Rust Crypto based ciphersuite implementations.
* Crypto agility with support for user defined ciphersuites.
* High test coverage including security focused tests and
  pre-computed test vectors.
* Fuzz testing suite.
* Benchmarks for core functionality.


<!-- cargo-sync-readme end -->

## License

This library is licensed under the Apache-2.0 or the MIT License.
