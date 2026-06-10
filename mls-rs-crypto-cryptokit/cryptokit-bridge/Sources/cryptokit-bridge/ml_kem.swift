import Foundation
import CryptoKit

// ML-KEM-768 key and ciphertext sizes (FIPS 203 / CryptoKit representation)
private let ML_KEM_768_ENC_KEY_SIZE: Int = 1184
private let ML_KEM_768_DEC_KEY_SIZE: Int = 96    // integrityCheckedRepresentation
private let ML_KEM_768_CT_SIZE: Int = 1088
private let ML_KEM_768_SS_SIZE: Int = 32

// Generate a fresh ML-KEM-768 key pair.
// privPtr/privLen out: decapsulation key (96 bytes, integrityCheckedRepresentation)
// pubPtr/pubLen out: encapsulation key (1184 bytes, rawRepresentation)
@_cdecl("ml_kem_768_generate")
@available(iOS 26.0, macOS 26.0, *)
public func ml_kem_768_generate(
    privPtr: UnsafeMutablePointer<UInt8>, privLen: UnsafeMutablePointer<UInt64>,
    pubPtr: UnsafeMutablePointer<UInt8>, pubLen: UnsafeMutablePointer<UInt64>
) -> UInt64 {
    guard let key = try? MLKEM768.PrivateKey() else { return 0 }
    guard copyToOutput(from: key.integrityCheckedRepresentation, ptr: privPtr, lenPtr: privLen) == 1 else { return 0 }
    guard copyToOutput(from: key.publicKey.rawRepresentation, ptr: pubPtr, lenPtr: pubLen) == 1 else { return 0 }
    return 1
}

// CryptoKit's MLKEM768 does not expose a seed-based key generation API.
// Returns 0 (failure) unconditionally.
@_cdecl("ml_kem_768_derive")
@available(iOS 26.0, macOS 26.0, *)
public func ml_kem_768_derive(
    seedPtr: UnsafePointer<UInt8>, seedLen: UInt64,
    privPtr: UnsafeMutablePointer<UInt8>, privLen: UnsafeMutablePointer<UInt64>,
    pubPtr: UnsafeMutablePointer<UInt8>, pubLen: UnsafeMutablePointer<UInt64>
) -> UInt64 {
    return 0
}

// Encapsulate to the given encapsulation (public) key.
// pubPtr/pubLen in: encapsulation key (1184 bytes)
// ctPtr/ctLen out: ciphertext (1088 bytes)
// ssPtr/ssLen out: shared secret (32 bytes)
@_cdecl("ml_kem_768_encap")
@available(iOS 26.0, macOS 26.0, *)
public func ml_kem_768_encap(
    pubPtr: UnsafePointer<UInt8>, pubLen: UInt64,
    ctPtr: UnsafeMutablePointer<UInt8>, ctLen: UnsafeMutablePointer<UInt64>,
    ssPtr: UnsafeMutablePointer<UInt8>, ssLen: UnsafeMutablePointer<UInt64>
) -> UInt64 {
    let pubRaw = dataFromRawParts(ptr: pubPtr, len: pubLen)
    guard let encKey = try? MLKEM768.PublicKey(rawRepresentation: pubRaw) else { return 0 }
    guard let result = try? encKey.encapsulate() else { return 0 }
    let ssData = result.sharedSecret.withUnsafeBytes { Data($0) }
    guard copyToOutput(from: result.encapsulated, ptr: ctPtr, lenPtr: ctLen) == 1 else { return 0 }
    guard copyToOutput(from: ssData, ptr: ssPtr, lenPtr: ssLen) == 1 else { return 0 }
    return 1
}

// Decapsulate using the given decapsulation (secret) key.
// ctPtr/ctLen in: ciphertext (1088 bytes)
// privPtr/privLen in: decapsulation key (96 bytes, integrityCheckedRepresentation)
// ssPtr/ssLen out: shared secret (32 bytes)
@_cdecl("ml_kem_768_decap")
@available(iOS 26.0, macOS 26.0, *)
public func ml_kem_768_decap(
    ctPtr: UnsafePointer<UInt8>, ctLen: UInt64,
    privPtr: UnsafePointer<UInt8>, privLen: UInt64,
    ssPtr: UnsafeMutablePointer<UInt8>, ssLen: UnsafeMutablePointer<UInt64>
) -> UInt64 {
    let ctRaw = dataFromRawParts(ptr: ctPtr, len: ctLen)
    let privRaw = dataFromRawParts(ptr: privPtr, len: privLen)
    guard let decKey = try? MLKEM768.PrivateKey(integrityCheckedRepresentation: privRaw) else { return 0 }
    guard let sharedSecret = try? decKey.decapsulate(ctRaw) else { return 0 }
    let ssData = sharedSecret.withUnsafeBytes { Data($0) }
    guard copyToOutput(from: ssData, ptr: ssPtr, lenPtr: ssLen) == 1 else { return 0 }
    return 1
}
