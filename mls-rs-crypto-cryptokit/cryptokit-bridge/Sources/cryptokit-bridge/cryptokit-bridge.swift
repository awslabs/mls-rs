import Foundation
import CryptoKit

func dataFromRawParts(ptr: UnsafePointer<UInt8>, len: UInt64) -> Data? {
    if len == 0 {
        return nil
    }

    return Data(buffer: UnsafeBufferPointer(start: ptr, count: Int(len)))
}

@_cdecl("hkdf_extract")
public func hkdf_extract(kdfID: UInt16, ikmPtr: UnsafePointer<UInt8>, ikmLen: UInt64, saltPtr: UnsafePointer<UInt8>, saltLen: UInt64, outPtr: UnsafeMutablePointer<UInt8>, outLen: UInt64) {
    let ikm = SymmetricKey.init(data: dataFromRawParts(ptr: ikmPtr, len: ikmLen)!)
    let salt = dataFromRawParts(ptr: saltPtr, len: saltLen)

    // TODO Use constants / enum
    let outBuf = UnsafeMutableBufferPointer<UInt8>.init(start: outPtr, count: Int(outLen))
    switch kdfID {
    case 1:
        let out = HKDF<SHA256>.extract(inputKeyMaterial: ikm, salt: salt)
        if out.byteCount != outLen {
            break
        }

        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }

    case 2:
        let out = HKDF<SHA384>.extract(inputKeyMaterial: ikm, salt: salt)
        if out.byteCount != outLen {
            break
        }

        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }

    case 3:
        let out = HKDF<SHA512>.extract(inputKeyMaterial: ikm, salt: salt)
        if out.byteCount != outLen {
            break
        }

        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }

    default:
        break
    }
}

@_cdecl("hkdf_expand")
public func hkdf_expand(kdfID: UInt16, prkPtr: UnsafePointer<UInt8>, prkLen: UInt64, infoPtr: UnsafePointer<UInt8>, infoLen: UInt64, outPtr: UnsafeMutablePointer<UInt8>, outLen: UInt64) {
    let prk = dataFromRawParts(ptr: prkPtr, len: prkLen)!
    let info = dataFromRawParts(ptr: infoPtr, len: infoLen)

    // TODO Use constants / enum
    let outBuf = UnsafeMutableBufferPointer<UInt8>.init(start: outPtr, count: Int(outLen))
    switch kdfID {
    case 1:
        let out = HKDF<SHA256>.expand(pseudoRandomKey: prk, info: info, outputByteCount: Int(outLen))
        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }

    case 2:
        let out = HKDF<SHA384>.expand(pseudoRandomKey: prk, info: info, outputByteCount: Int(outLen))
        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }

    case 3:
        let out = HKDF<SHA512>.expand(pseudoRandomKey: prk, info: info, outputByteCount: Int(outLen))
        _ = out.withUnsafeBytes { buf in buf.copyBytes(to: outBuf, count: Int(outLen)) }

    default:
        break
    }
}
