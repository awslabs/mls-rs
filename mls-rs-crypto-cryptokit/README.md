CryptoKit Crypto Provider
=========================

This crate implements a crypto provider for `mls-rs` based on Apple's CryptoKit
cryptographic library.  Because CryptoKit only exposes a Swift interface, we
include a Swift package `cryptokit-bridge` that implements a C interface that
can be called from Rust.

```
+-------------------------+
|          mls-rs         |
+------------+------------+
             |
             | Rust
             |
+------------+------------+
| mls-rs-crypto-cryptokit |
+------------+------------+
             |
             | C FFI
             |
+------------+------------+
|    cryptokit-bridge     |
+------------+------------+
             |
             | Swift
             |
+------------+------------+
|        CryptoKit        |
+-------------------------+
```

## Implementation status

The `mls-rs` `CipherSuiteProvider` interface has a number of methods to support
the various cryptographic functions that MLS requires.  The following checklist
indicates whether we have implemented access to the appropriate functionality in
CryptoKit.  Once all of the CryptoKit wiring is in place, implementing
`CipherSuiteProvider` and `CryptoProvider` should be straightforward.

Final packaging:
* [ ] `type Error: IntoAnyError;`
* [ ] `cipher_suite`

Random bytes:
* [X] `random_bytes`

Hashing:
* [X] `hash`

MAC:
* [X] `mac`

KDF:
* [X] `kdf_extract`
* [X] `kdf_expand`
* [X] `kdf_extract_size`

AEAD:
* [X] `aead_seal`
* [X] `aead_open`
* [X] `aead_key_size`
* [X] `aead_nonce_size`

KEM / HPKE:
* [ ] `kem_derive`
* [ ] `kem_generate`
* [ ] `kem_public_key_validate`
* [ ] `type HpkeContextS: HpkeContextS + Send + Sync;`
* [ ] `type HpkeContextR: HpkeContextR + Send + Sync;`
* [ ] `hpke_seal`
* [ ] `hpke_open`
* [ ] `hpke_setup_s`
* [ ] `hpke_setup_r`

Signature:
* [X] `signature_key_generate`
* [X] `signature_key_derive_public`
* [X] `sign`
* [X] `verify`

