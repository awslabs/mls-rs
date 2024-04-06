import CryptoKit

// The values in this enum MUST match those of the KdfId enum in Rust:
// https://docs.rs/mls-rs-crypto-traits/latest/mls_rs_crypto_traits/enum.KdfId.html
enum KdfId : UInt16 {
    case HkdfSha256 = 1
    case HkdfSha384 = 2
    case HkdfSha512 = 3
}

@_cdecl("hkdf_extract")
public func hkdf_extract(kdfID: UInt16, ikmPtr: UnsafePointer<UInt8>, ikmLen: UInt64, saltPtr: UnsafePointer<UInt8>, saltLen: UInt64, outPtr: UnsafeMutablePointer<UInt8>, outLen: UInt64) {
    let ikm = SymmetricKey.init(data: dataFromRawParts(ptr: ikmPtr, len: ikmLen)!)
    let salt = dataFromRawParts(ptr: saltPtr, len: saltLen)

    let outBuf = UnsafeMutableBufferPointer<UInt8>.init(start: outPtr, count: Int(outLen))
    switch KdfId(rawValue: kdfID)! {
    case .HkdfSha256:
        let out = HKDF<SHA256>.extract(inputKeyMaterial: ikm, salt: salt)
        if out.byteCount != outLen {
            break
        }

        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }

    case .HkdfSha384:
        let out = HKDF<SHA384>.extract(inputKeyMaterial: ikm, salt: salt)
        if out.byteCount != outLen {
            break
        }

        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }

    case .HkdfSha512:
        let out = HKDF<SHA512>.extract(inputKeyMaterial: ikm, salt: salt)
        if out.byteCount != outLen {
            break
        }

        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }
    }
}

@_cdecl("hkdf_expand")
public func hkdf_expand(kdfID: UInt16, prkPtr: UnsafePointer<UInt8>, prkLen: UInt64, infoPtr: UnsafePointer<UInt8>, infoLen: UInt64, outPtr: UnsafeMutablePointer<UInt8>, outLen: UInt64) {
    let prk = dataFromRawParts(ptr: prkPtr, len: prkLen)!
    let info = dataFromRawParts(ptr: infoPtr, len: infoLen)

    let outBuf = UnsafeMutableBufferPointer<UInt8>.init(start: outPtr, count: Int(outLen))
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
}

