import Foundation
import CryptoKit

func dataFromRawParts(ptr: UnsafePointer<UInt8>, len: UInt64) -> Data {
    if len == 0 {
        return Data()
    }

    return Data(buffer: UnsafeBufferPointer(start: ptr, count: Int(len)))
}
