import Foundation
import CryptoKit

@_cdecl("hash_sha256")
public func hash_sha256(codePtr: UnsafePointer<UInt8>, codeLen: UInt64, hashLenPtr: UnsafeMutablePointer<UInt64>) -> UnsafeMutablePointer<UInt8> {
    let buf = UnsafeBufferPointer(start: codePtr, count: Int(codeLen))
    let data = Data(buffer: buf)
    let hashBytes = SHA256.hash(data: data)
    
    let outPtr = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: SHA256Digest.byteCount)
    _ = hashBytes.withUnsafeBytes { buf in
        buf.copyBytes(to: outPtr, count: buf.count)
    }
    hashLenPtr.pointee = UInt64(outPtr.count)
    return outPtr.baseAddress!
}
