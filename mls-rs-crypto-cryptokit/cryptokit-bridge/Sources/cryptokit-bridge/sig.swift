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

// Convention in mls-rs is to append the public key to the private key, which
// improves efficiency in some other crypto back-ends.
extension Curve25519.Signing.PrivateKey {
    init(rawRepresentationWithPublicKey: Data) throws {
        let rawRepresentation = rawRepresentationWithPublicKey.prefix(upTo: 32)
        try self.init(rawRepresentation: rawRepresentation)
    }

    var rawRepresentationWithPublicKey: Data {
        self.rawRepresentation + self.publicKey.rawRepresentation
    }
}

// RFC 9420 specifies that signature public keys are in the form prefixed with 0x04.
func unpadNISTPrivateKey(_ data: Data) throws -> Data {
    guard data[0] == 0x04 else {
        throw CryptoKitError.invalidParameter
    }

    return data.suffix(from: 1)
}

func padNISTPrivateKey(_ data: Data) -> Data {
    return [0x04] + data
}

extension P256.Signing.PublicKey {
    init(rawRepresentationWithPrefix: Data) throws {
        try self.init(rawRepresentation: unpadNISTPrivateKey(rawRepresentationWithPrefix))
    }

    var rawRepresentationWithPrefix: Data {
        padNISTPrivateKey(self.rawRepresentation)
    }
}

extension P384.Signing.PublicKey {
    init(rawRepresentationWithPrefix: Data) throws {
        try self.init(rawRepresentation: unpadNISTPrivateKey(rawRepresentationWithPrefix))
    }

    var rawRepresentationWithPrefix: Data {
        padNISTPrivateKey(self.rawRepresentation)
    }
}

extension P521.Signing.PublicKey {
    init(rawRepresentationWithPrefix: Data) throws {
        try self.init(rawRepresentation: unpadNISTPrivateKey(rawRepresentationWithPrefix))
    }

    var rawRepresentationWithPrefix: Data {
        padNISTPrivateKey(self.rawRepresentation)
    }
}

// CryptoKit requires that private keys have exactly the right number of bytes
func leftPad(_ data: Data, count: Int) -> Data {
    let pad = Data(repeating: 0x00, count: count - data.count)
    return pad + data
}

extension P256.Signing.PrivateKey {
    init(unpaddedRawRepresentation: Data) throws {
        try self.init(rawRepresentation: leftPad(unpaddedRawRepresentation, count: 32))
    }

    var paddedRawRepresentation: Data {
        leftPad(self.rawRepresentation, count: 32)
    }
}

extension P384.Signing.PrivateKey {
    init(unpaddedRawRepresentation: Data) throws {
        try self.init(rawRepresentation: leftPad(unpaddedRawRepresentation, count: 48))
    }

    var paddedRawRepresentation: Data {
        leftPad(self.rawRepresentation, count: 48)
    }
}

extension P521.Signing.PrivateKey {
    init(unpaddedRawRepresentation: Data) throws {
        try self.init(rawRepresentation: leftPad(unpaddedRawRepresentation, count: 66))
    }

    var paddedRawRepresentation: Data {
        leftPad(self.rawRepresentation, count: 66)
    }
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

        privRaw = priv.paddedRawRepresentation
        pubRaw = pub.rawRepresentationWithPrefix

    case .P384:
        let priv = P384.Signing.PrivateKey()
        let pub = priv.publicKey 

        privRaw = priv.paddedRawRepresentation
        pubRaw = pub.rawRepresentationWithPrefix

    case .P521:
        let priv = P521.Signing.PrivateKey()
        let pub = priv.publicKey 

        privRaw = priv.paddedRawRepresentation
        pubRaw = pub.rawRepresentationWithPrefix

    case .Ed25519:
        let priv = Curve25519.Signing.PrivateKey()
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentationWithPublicKey
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
            let priv = try P256.Signing.PrivateKey(unpaddedRawRepresentation: privRaw)
            let pub = priv.publicKey 
            pubRaw = pub.rawRepresentationWithPrefix
        } catch {
            return 0
        }

    case .P384:
        do {
            let priv = try P384.Signing.PrivateKey(unpaddedRawRepresentation: privRaw)
            let pub = priv.publicKey 
            pubRaw = pub.rawRepresentationWithPrefix
        } catch {
            return 0
        }

    case .P521:
        do {
            let priv = try P521.Signing.PrivateKey(unpaddedRawRepresentation: privRaw)
            let pub = priv.publicKey 
            pubRaw = pub.rawRepresentationWithPrefix
        } catch {
            return 0
        }

    case .Ed25519:
        do {
            let priv = try Curve25519.Signing.PrivateKey(rawRepresentationWithPublicKey: privRaw)
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
            let priv = try P256.Signing.PrivateKey(unpaddedRawRepresentation: privRaw)
            sig = try priv.signature(for: data).derRepresentation
        } catch {
            return 0
        }

    case .P384:
        do {
            let priv = try P384.Signing.PrivateKey(unpaddedRawRepresentation: privRaw)
            sig = try priv.signature(for: data).derRepresentation
        } catch {
            return 0
        }

    case .P521:
        do {
            let priv = try P521.Signing.PrivateKey(unpaddedRawRepresentation: privRaw)
            sig = try priv.signature(for: data).derRepresentation
        } catch {
            return 0
        }

    case .Ed25519:
        do {
            let priv = try Curve25519.Signing.PrivateKey(rawRepresentationWithPublicKey: privRaw)
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
            let pub = try P256.Signing.PublicKey(rawRepresentationWithPrefix: pubRaw)
            valid = pub.isValidSignature(sig, for: data)
        } catch {
            return 0
        }

    case .P384:
        do {
            let sig = try P384.Signing.ECDSASignature(derRepresentation: sig)
            let pub = try P384.Signing.PublicKey(rawRepresentationWithPrefix: pubRaw)
            valid = pub.isValidSignature(sig, for: data)
        } catch {
            return 0
        }

    case .P521:
        do {
            let sig = try P521.Signing.ECDSASignature(derRepresentation: sig)
            let pub = try P521.Signing.PublicKey(rawRepresentationWithPrefix: pubRaw)
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
