import XCTest
@testable import cryptokit_bridge

func fromHex(_ s: String) -> Data? {
    var data = Data(capacity: s.count / 2)
        

    let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
    regex.enumerateMatches(in: s, range: NSRange(s.startIndex..., in:s)) { match, _, _ in
        let byteString = (s as NSString).substring(with: match!.range)
        let num = UInt8(byteString, radix: 16)!
        data.append(num)
    }

    return data
}

class CryptoKitBridgeTests: XCTestCase {
    static var allTests = [
        ("testSHA256", testSHA256),
    ]
    
    func testSHA256() {
        var code = "this is a string to be hashed with SHA-256"
        var len: UInt64 = 0
        let result = code.withUTF8 { codePtr in
            withUnsafeMutablePointer(to: &len) { lenPtr in
                hash_sha256(codePtr: codePtr.baseAddress!, codeLen: UInt64(codePtr.count), hashLenPtr: lenPtr)
            }
        }
        let ptr = UnsafeBufferPointer(start: result, count: Int(len))
        let actual = Data(buffer: ptr)
        let expected = fromHex("c8236b75cad715d62c0f733d244a44d01e18b8c1797d1b9c55fa64aa7603cc6a")
        XCTAssertEqual(actual, expected)
    }
}
