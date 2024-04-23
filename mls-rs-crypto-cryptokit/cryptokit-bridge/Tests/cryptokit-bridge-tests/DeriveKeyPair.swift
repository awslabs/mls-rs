import XCTest
import Foundation
import CryptoKit
@testable import cryptokit_bridge

class DeriveKeyPairTests: XCTestCase {
    static var allTests = [
        ("testX25519", testX25519),
        ("testNIST", testNIST),
    ]

    struct TestCase {
        var kemID = KemId.DhKemP256Sha256Aes128
        var ikm = String()
        var skm = String()
        var pkm = String()
    }
    
    func testX25519() {
        let testCases = [
            TestCase(
                kemID: .DhKemX25519Sha256Aes128,
                ikm: "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
                skm: "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
                pkm: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
            ),
            TestCase(
                kemID: .DhKemX25519Sha256ChaChaPoly,
                ikm: "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
                skm: "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
                pkm: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
            )
        ]
        
        for tc in testCases {
            let skData = derive_key_pair_x25519(kemID: tc.kemID, ikm: tc.ikm.hexData)      

            let sk = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: skData)
            let skm = sk.rawRepresentation
            verifyPrivateKey(sk: sk, skm: skm, tc: tc)
        }
    }

    func testNIST() {
        let testCases = [
            TestCase(
                kemID: .DhKemP256Sha256Aes128,
                ikm: "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e",
                skm: "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
                pkm: "04" + 
                     "a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac9" +
                     "8536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
            ),
            TestCase(
                kemID: .DhKemP521Sha512Aes256,
                ikm: "7f06ab8215105fc46aceeb2e3dc5028b44364f960426eb0d8e4026c2f8b5d7e7a9" + 
                     "86688f1591abf5ab753c357a5d6f0440414b4ed4ede71317772ac98d9239f70904",
                skm: "014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8" +
                     "569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b",
                pkm: "04" + 
                     "0138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aae" + 
                     "ed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2" +
                     "013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed069" +
                     "2237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0"
            ),
        ]
        
        for tc in testCases {
            let skData = derive_key_pair_nist(kemID: tc.kemID, ikm: tc.ikm.hexData)!   

            switch tc.kemID {
            case .DhKemP256Sha256Aes128:
                let sk = try! P256.KeyAgreement.PrivateKey(rawRepresentation: skData)
                let skm = sk.rawRepresentation
                verifyPrivateKey(sk: sk, skm: skm, tc: tc)
            
            case .DhKemP521Sha512Aes256:
                let sk = try! P521.KeyAgreement.PrivateKey(rawRepresentation: skData)
                let skm = sk.rawRepresentation
                verifyPrivateKey(sk: sk, skm: skm, tc: tc)

            default:
                XCTAssert(false)
            }
        }
    }

    func verifyPrivateKey<PrivateKey>(sk: PrivateKey, skm: Data, tc: TestCase)
    where PrivateKey: HPKEDiffieHellmanPrivateKey
    {
        XCTAssertEqual(skm.hexString, tc.skm)

        let pk = sk.publicKey
        let pkm = try! pk.hpkeRepresentation(kem: tc.kemID.hpkeKem)
        XCTAssertEqual(pkm.hexString, tc.pkm)
    }
}
