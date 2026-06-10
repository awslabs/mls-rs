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

The Rust source files in this crate include only very basic testing, enough to
verify that the plumbing depicted above is working.  We rely on the crypto
provider tests in `mls-rs-core` for more thorough validation.

## Build requirements

The Swift bridge requires a toolchain that can build for macOS 26 / iOS 26 targets,
because `CryptoKit.MLKEM768` (FIPS 203) is only available from those platform
versions.

| Component | Minimum version |
|-----------|----------------|
| Swift toolchain | Swift 6.2 (ships with Xcode 26 beta or later) |
| macOS deployment target | 26.0 |
| iOS deployment target | 26.0 |

The build script (`build.rs`) invokes `swift build` on `cryptokit-bridge/` at
compile time.  If the active Xcode / Swift toolchain does not support the macOS
26 SDK, the build will fail with a deployment-target error.

### Feature flags

| Flag | Meaning |
|------|---------|
| `post-quantum` | Enables the ML-KEM-768 cipher suite backed by CryptoKit. Requires the Swift bridge to build successfully. |
| `awslc-interop` | Enables interoperability tests between this provider and `mls-rs-crypto-awslc`. Not required for production use; keep this gate disabled on CI builders that cannot build AWS-LC or the Swift bridge simultaneously. |
