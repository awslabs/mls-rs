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

func exportPointer<Instance>(_ obj: Instance) -> UnsafeMutableRawPointer 
where Instance: AnyObject
{
    return Unmanaged.passRetained(obj).toOpaque()
}

func pointerToRef<Instance>(_ ptr: UnsafeMutableRawPointer) -> Instance
where Instance: AnyObject
{
    return Unmanaged<Instance>.fromOpaque(ptr).takeUnretainedValue()
}

// XXX(RLB) The bogus return value is needed to avoid "generic parameter
// 'Instance' is not used in function signature" errors
func importAndDropPointer<Instance>(_ ptr: UnsafeMutableRawPointer) -> Instance?
where Instance: AnyObject
{
    Unmanaged<Instance>.fromOpaque(ptr).release()
    return nil
}
