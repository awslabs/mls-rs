import CryptoKit

// The values in this enum MUST match those of the KdfId enum in Rust:
// https://docs.rs/mls-rs-crypto-traits/latest/mls_rs_crypto_traits/enum.KdfId.html
enum KdfId : UInt16 {
    case HkdfSha256 = 1
    case HkdfSha384 = 2
    case HkdfSha512 = 3
}

@_cdecl("hash")
public func hash(kdfID: UInt16, inPtr: UnsafePointer<UInt8>, inLen: UInt64, outPtr: UnsafeMutablePointer<UInt8>, outLen: UInt64) -> UInt64 {
    let input = dataFromRawParts(ptr: inPtr, len: inLen)

    switch KdfId(rawValue: kdfID)! {
    case .HkdfSha256:
        let out = SHA256.hash(data: input)
        guard copyToOutput(from: out, ptr: outPtr, len: outLen) == 1 else { return 0 }

    case .HkdfSha384:
        let out = SHA384.hash(data: input)
        guard copyToOutput(from: out, ptr: outPtr, len: outLen) == 1 else { return 0 }

    case .HkdfSha512:
        let out = SHA512.hash(data: input)
        guard copyToOutput(from: out, ptr: outPtr, len: outLen) == 1 else { return 0 }
    }

    return 1
}

@_cdecl("hmac")
public func hmac(kdfID: UInt16, keyPtr: UnsafePointer<UInt8>, keyLen: UInt64, dataPtr: UnsafePointer<UInt8>, dataLen: UInt64, outPtr: UnsafeMutablePointer<UInt8>, outLen: UInt64) -> UInt64 {
    let key = SymmetricKey(data: dataFromRawParts(ptr: keyPtr, len: keyLen))
    let data = dataFromRawParts(ptr: dataPtr, len: dataLen)

    switch KdfId(rawValue: kdfID)! {
    case .HkdfSha256:
        let out = HMAC<SHA256>.authenticationCode(for: data, using: key)
        guard copyToOutput(from: out, ptr: outPtr, len: outLen) == 1 else { return 0 }

    case .HkdfSha384:
        let out = HMAC<SHA384>.authenticationCode(for: data, using: key)
        guard copyToOutput(from: out, ptr: outPtr, len: outLen) == 1 else { return 0 }

    case .HkdfSha512:
        let out = HMAC<SHA512>.authenticationCode(for: data, using: key)
        guard copyToOutput(from: out, ptr: outPtr, len: outLen) == 1 else { return 0 }
    }

    return 1
}

@_cdecl("hkdf_extract")
public func hkdf_extract(kdfID: UInt16, ikmPtr: UnsafePointer<UInt8>, ikmLen: UInt64, saltPtr: UnsafePointer<UInt8>, saltLen: UInt64, outPtr: UnsafeMutablePointer<UInt8>, outLen: UInt64) -> UInt64 {
    let ikm = SymmetricKey(data: dataFromRawParts(ptr: ikmPtr, len: ikmLen))
    let salt = dataFromRawParts(ptr: saltPtr, len: saltLen)

    let outBuf = UnsafeMutableBufferPointer<UInt8>(start: outPtr, count: Int(outLen))
    switch KdfId(rawValue: kdfID)! {
    case .HkdfSha256:
        let out = HKDF<SHA256>.extract(inputKeyMaterial: ikm, salt: salt)
        guard out.byteCount == outLen else { return 0 }
        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }

    case .HkdfSha384:
        let out = HKDF<SHA384>.extract(inputKeyMaterial: ikm, salt: salt)
        guard out.byteCount == outLen else { return 0 }
        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }

    case .HkdfSha512:
        let out = HKDF<SHA512>.extract(inputKeyMaterial: ikm, salt: salt)
        guard out.byteCount == outLen else { return 0 }
        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }
    }

    return 1
}

@_cdecl("hkdf_expand")
public func hkdf_expand(kdfID: UInt16, prkPtr: UnsafePointer<UInt8>, prkLen: UInt64, infoPtr: UnsafePointer<UInt8>, infoLen: UInt64, outPtr: UnsafeMutablePointer<UInt8>, outLen: UInt64) -> UInt64 {
    let prk = dataFromRawParts(ptr: prkPtr, len: prkLen)
    let info = dataFromRawParts(ptr: infoPtr, len: infoLen)

    let outBuf = UnsafeMutableBufferPointer<UInt8>(start: outPtr, count: Int(outLen))
    switch KdfId(rawValue: kdfID)! {
    case .HkdfSha256:
        let out = HKDF<SHA256>.expand(pseudoRandomKey: prk, info: info, outputByteCount: Int(outLen))
        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }

    case .HkdfSha384:
        let out = HKDF<SHA384>.expand(pseudoRandomKey: prk, info: info, outputByteCount: Int(outLen))
        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }

    case .HkdfSha512:
        let out = HKDF<SHA512>.expand(pseudoRandomKey: prk, info: info, outputByteCount: Int(outLen))
        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }
    }

    return 1
}

