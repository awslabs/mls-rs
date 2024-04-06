import Foundation
import CryptoKit

func dataFromRawParts(ptr: UnsafePointer<UInt8>, len: UInt64) -> Data {
    if len == 0 {
        return Data()
    }

    return Data(buffer: UnsafeBufferPointer(start: ptr, count: Int(len)))
}

func copyToOutput<D>(from: D, ptr: UnsafeMutablePointer<UInt8>, len: UInt64) -> UInt64 
where D: ContiguousBytes
{
    let out = UnsafeMutableBufferPointer<UInt8>(start: ptr, count: Int(len))
    return from.withUnsafeBytes{ 
        (buf) -> UInt64 in 
            guard len == buf.count else { return 0 }
            buf.copyBytes(to: out, count: out.count) 
            return 1
    }
}
