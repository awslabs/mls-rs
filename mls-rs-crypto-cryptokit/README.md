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
