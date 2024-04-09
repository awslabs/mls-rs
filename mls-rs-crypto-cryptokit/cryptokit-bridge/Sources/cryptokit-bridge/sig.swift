import Foundation
import CryptoKit

// The values in this enum MUST match those of the Curve enum in Rust:
// https://docs.rs/mls-rs-crypto-traits/latest/mls_rs_crypto_traits/enum.Curve.html
enum SignatureId : UInt16 {
    case P256 = 0
    case P384 = 1
    case P521 = 2
    case Ed25519 = 4

    // Unsupported: https://forums.developer.apple.com/forums/thread/715865
    // case Ed448 = 6
}

// fn signature_key_generate(
//     &self
// ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error>;
@_cdecl("signature_key_generate")
public func signature_key_generate(sigID: UInt16, 
    privPtr: UnsafeMutablePointer<UInt8>, privLen: UnsafeMutablePointer<UInt64>, 
    pubPtr: UnsafeMutablePointer<UInt8>, pubLen: UnsafeMutablePointer<UInt64>
) -> UInt64 
{
    var privRaw = Data()
    var pubRaw = Data()
    switch SignatureId(rawValue: sigID)! {
    case .P256:
        let priv = P256.Signing.PrivateKey()
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentation
        pubRaw = pub.rawRepresentation

    case .P384:
        let priv = P384.Signing.PrivateKey()
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentation
        pubRaw = pub.rawRepresentation

    case .P521:
        let priv = P521.Signing.PrivateKey()
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentation
        pubRaw = pub.rawRepresentation

    case .Ed25519:
        let priv = Curve25519.Signing.PrivateKey()
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentation
        pubRaw = pub.rawRepresentation
    }

    guard copyToOutput(from: privRaw, ptr: privPtr, lenPtr: privLen) == 1 else { return 0 }
    guard copyToOutput(from: pubRaw, ptr: pubPtr, lenPtr: pubLen) == 1 else { return 0 }
    return 1
}

// fn signature_key_derive_public(
//     &self,
//     secret_key: &SignatureSecretKey
// ) -> Result<SignaturePublicKey, Self::Error>;
@_cdecl("signature_key_derive_public")
public func signature_key_derive_public(sigID: UInt16, 
    privPtr: UnsafePointer<UInt8>, privLen: UInt64, 
    pubPtr: UnsafeMutablePointer<UInt8>, pubLen: UnsafeMutablePointer<UInt64>
) -> UInt64 
{
    let privRaw = dataFromRawParts(ptr: privPtr, len: privLen)
    var pubRaw = Data()
    switch SignatureId(rawValue: sigID)! {
    case .P256:
        do {
            let priv = try P256.Signing.PrivateKey(rawRepresentation: privRaw)
            let pub = priv.publicKey 
            pubRaw = pub.rawRepresentation
        } catch {
            return 0
        }

    case .P384:
        do {
            let priv = try P384.Signing.PrivateKey(rawRepresentation: privRaw)
            let pub = priv.publicKey 
            pubRaw = pub.rawRepresentation
        } catch {
            return 0
        }

    case .P521:
        do {
            let priv = try P521.Signing.PrivateKey(rawRepresentation: privRaw)
            let pub = priv.publicKey 
            pubRaw = pub.rawRepresentation
        } catch {
            return 0
        }

    case .Ed25519:
        do {
            let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: privRaw)
            let pub = priv.publicKey 
            pubRaw = pub.rawRepresentation
        } catch {
            return 0
        }
    }

    guard copyToOutput(from: pubRaw, ptr: pubPtr, lenPtr: pubLen) == 1 else { return 0 }
    return 1
}

// fn sign(
//     &self,
//     secret_key: &SignatureSecretKey,
//     data: &[u8]
// ) -> Result<Vec<u8>, Self::Error>;
@_cdecl("sign")
public func sign(sigID: UInt16, 
    privPtr: UnsafePointer<UInt8>, privLen: UInt64, 
    dataPtr: UnsafePointer<UInt8>, dataLen: UInt64,
    sigPtr: UnsafeMutablePointer<UInt8>, sigLen: UnsafeMutablePointer<UInt64>
) -> UInt64 
{
    let privRaw = dataFromRawParts(ptr: privPtr, len: privLen)
    let data = dataFromRawParts(ptr: dataPtr, len: dataLen)
    
    var sig = Data()
    switch SignatureId(rawValue: sigID)! {
    case .P256:
        do {
            let priv = try P256.Signing.PrivateKey(rawRepresentation: privRaw)
            sig = try priv.signature(for: data).derRepresentation
        } catch {
            return 0
        }

    case .P384:
        do {
            let priv = try P384.Signing.PrivateKey(rawRepresentation: privRaw)
            sig = try priv.signature(for: data).derRepresentation
        } catch {
            return 0
        }

    case .P521:
        do {
            let priv = try P521.Signing.PrivateKey(rawRepresentation: privRaw)
            sig = try priv.signature(for: data).derRepresentation
        } catch {
            return 0
        }

    case .Ed25519:
        do {
            let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: privRaw)
            sig = try priv.signature(for: data)
        } catch {
            return 0
        }
    }

    guard copyToOutput(from: sig, ptr: sigPtr, lenPtr: sigLen) == 1 else { return 0 }
    return 1
}

// fn verify(
//     &self,
//     public_key: &SignaturePublicKey,
//     signature: &[u8],
//     data: &[u8]
// ) -> Result<(), Self::Error>;
@_cdecl("verify")
public func verify(sigID: UInt16, 
    pubPtr: UnsafePointer<UInt8>, pubLen: UInt64, 
    sigPtr: UnsafePointer<UInt8>, sigLen: UInt64,
    dataPtr: UnsafePointer<UInt8>, dataLen: UInt64
) -> UInt64 
{
    let pubRaw = dataFromRawParts(ptr: pubPtr, len: pubLen)
    let sig = dataFromRawParts(ptr: sigPtr, len: sigLen)
    let data = dataFromRawParts(ptr: dataPtr, len: dataLen)
    
    var valid = false
    switch SignatureId(rawValue: sigID)! {
    case .P256:
        do {
            let sig = try P256.Signing.ECDSASignature(derRepresentation: sig)
            let pub = try P256.Signing.PublicKey(rawRepresentation: pubRaw)
            valid = pub.isValidSignature(sig, for: data)
        } catch {
            return 0
        }

    case .P384:
        do {
            let sig = try P384.Signing.ECDSASignature(derRepresentation: sig)
            let pub = try P384.Signing.PublicKey(rawRepresentation: pubRaw)
            valid = pub.isValidSignature(sig, for: data)
        } catch {
            return 0
        }

    case .P521:
        do {
            let sig = try P521.Signing.ECDSASignature(derRepresentation: sig)
            let pub = try P521.Signing.PublicKey(rawRepresentation: pubRaw)
            valid = pub.isValidSignature(sig, for: data)
        } catch {
            return 0
        }

    case .Ed25519:
        do {
            let pub = try Curve25519.Signing.PublicKey(rawRepresentation: pubRaw)
            valid = pub.isValidSignature(sig, for: data)
        } catch {
            return 0
        }
    }

    if valid {
        return 1
    } else {
        return 0
    }
}
