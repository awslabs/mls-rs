import Foundation
import CryptoKit

@_cdecl("random_bytes")
public func random_bytes(ptr: UnsafeMutablePointer<UInt8>, len: UInt64) -> UInt64 {
    let rv = SecRandomCopyBytes(kSecRandomDefault, Int(len), ptr)
    guard rv == errSecSuccess else { return 0 }
    return 1
}
