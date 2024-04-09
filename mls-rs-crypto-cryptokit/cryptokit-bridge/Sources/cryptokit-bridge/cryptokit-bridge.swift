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
    return from.withUnsafeBytes{ 
        (buf) -> UInt64 in 
            guard len == buf.count else { return 0 }
    
            let out = UnsafeMutableBufferPointer<UInt8>(start: ptr, count: buf.count)
            buf.copyBytes(to: out, count: out.count) 
            return 1
    }
}

func copyToOutput<D>(from: D, ptr: UnsafeMutablePointer<UInt8>, lenPtr: UnsafeMutablePointer<UInt64>) -> UInt64 
where D: ContiguousBytes
{
    return from.withUnsafeBytes{ 
        (buf) -> UInt64 in 
            guard lenPtr.pointee >= buf.count else { return 0 }
            lenPtr.pointee = UInt64(buf.count)
    
            let out = UnsafeMutableBufferPointer<UInt8>(start: ptr, count: buf.count)
            buf.copyBytes(to: out, count: out.count) 
            return 1
    }
}
