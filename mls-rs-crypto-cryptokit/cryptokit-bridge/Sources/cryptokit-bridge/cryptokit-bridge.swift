import Foundation
import CryptoKit

// Convenience methods for C FFI
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

// Conversion between managed objects and unmanaged pointers
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

// The bogus return value is needed to avoid "generic parameter 'Instance' is
// not used in function signature" errors.  It can be safely ignored.
func importAndDropPointer<Instance>(_ ptr: UnsafeMutableRawPointer) -> Instance?
where Instance: AnyObject
{
    Unmanaged<Instance>.fromOpaque(ptr).release()
    return nil
}

// Conversion to/from hex strings
extension String {
    var hex : [UInt8] {
        var i = 0
        return self.map({ c -> UInt8 in UInt8(String(c), radix: 16)! })
                .reduce( into: [UInt8](), { (buf, digit) in 
                    if  i % 2 == 0 {
                        buf = buf + [digit << 4]
                    } else {
                        buf[buf.count - 1] += digit
                    }
                    i += 1
                })
    }
    
    var hexData : Data {
        return Data(self.hex)
    }
}

extension Data {
    var hexString : String {
        return self.reduce("") { (a: String, v: UInt8) -> String in
            return a + String(format: "%02x", v)
        }
    }
}


