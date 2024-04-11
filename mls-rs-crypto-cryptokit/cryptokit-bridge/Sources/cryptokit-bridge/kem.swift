import Foundation
import CryptoKit

// The values in this enum MUST match those of the KemId enum in Rust:
// https://docs.rs/mls-rs-crypto-traits/latest/mls_rs_crypto_traits/enum.KemId.html
enum KemId : UInt16 {
    case DhKemP256Sha256Aes128 = 1
    case DhKemP384Sha384Aes256 = 2
    case DhKemP521Sha512Aes256 = 3
    case DhKemX25519Sha256Aes128 = 4
    case DhKemX25519Sha256ChaChaPoly = 5
    
    // X448 KEMs Unsupported: https://forums.developer.apple.com/forums/thread/715865
    var hpkeKem: HPKE.KEM {
        get {
            switch self {
            case .DhKemP256Sha256Aes128: HPKE.KEM.P256_HKDF_SHA256
            case .DhKemP384Sha384Aes256: HPKE.KEM.P384_HKDF_SHA384
            case .DhKemP521Sha512Aes256: HPKE.KEM.P521_HKDF_SHA512
            case .DhKemX25519Sha256Aes128: HPKE.KEM.Curve25519_HKDF_SHA256
            case .DhKemX25519Sha256ChaChaPoly: HPKE.KEM.Curve25519_HKDF_SHA256
            }
        }
    }

    var hpkeCipherSuite: HPKE.Ciphersuite {
        get {
            switch self {
            case .DhKemP256Sha256Aes128:
                HPKE.Ciphersuite(kem: HPKE.KEM.P256_HKDF_SHA256, kdf: HPKE.KDF.HKDF_SHA256, aead: HPKE.AEAD.AES_GCM_128)
            case .DhKemP384Sha384Aes256:
                HPKE.Ciphersuite.P384_SHA384_AES_GCM_256
            case .DhKemP521Sha512Aes256:
                HPKE.Ciphersuite.P521_SHA512_AES_GCM_256
            case .DhKemX25519Sha256Aes128:
                HPKE.Ciphersuite(kem: HPKE.KEM.Curve25519_HKDF_SHA256, kdf: HPKE.KDF.HKDF_SHA256, aead: HPKE.AEAD.AES_GCM_128)
            case .DhKemX25519Sha256ChaChaPoly:
                HPKE.Ciphersuite.Curve25519_SHA256_ChachaPoly
            }
        }
    }

    var suiteID: Data {
        get {
            var id = "HPKE".data(using: .utf8)!

            switch self {
            case .DhKemP256Sha256Aes128:       id.append(Data([0, 0x10, 0, 1, 0, 1]))
            case .DhKemP384Sha384Aes256:       id.append(Data([0, 0x11, 0, 2, 0, 2]))
            case .DhKemP521Sha512Aes256:       id.append(Data([0, 0x12, 0, 3, 0, 2]))
            case .DhKemX25519Sha256Aes128:     id.append(Data([0, 0x20, 0, 1, 0, 1]))
            case .DhKemX25519Sha256ChaChaPoly: id.append(Data([0, 0x21, 0, 1, 0, 3]))
            }

            return id
        }
    }

    var nsk: Int {
        get {
            switch self {
            case .DhKemP256Sha256Aes128: 32
            case .DhKemP384Sha384Aes256: 48
            case .DhKemP521Sha512Aes256: 66
            case .DhKemX25519Sha256Aes128: 32
            case .DhKemX25519Sha256ChaChaPoly: 56
            }
        }
    }

    var order: Data {
        get {
            switch self {
            case .DhKemP256Sha256Aes128: Data([0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 
                                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                                               0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 
                                               0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,])
            case .DhKemP384Sha384Aes256: Data([0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 
                                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                                               0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 
                                               0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51])
            case .DhKemP521Sha512Aes256: Data([0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                                               0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 
                                               0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09, 
                                               0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 
                                               0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38, 
                                               0x64, 0x09])
            case .DhKemX25519Sha256Aes128: Data() // not used
            case .DhKemX25519Sha256ChaChaPoly: Data() // not used
            }
        }
    }
}

class SenderWrapper {
    var sender: HPKE.Sender? = nil

    init(_ sender_in: HPKE.Sender) {
        sender = sender_in
    }
}

class RecipientWrapper {
    var recipient: HPKE.Recipient? = nil

    init(_ recipient_in: HPKE.Recipient) {
        recipient = recipient_in
    }
}

// fn kem_generate(
//     &self
// ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;
@_cdecl("kem_generate")
public func kem_generate(kemID: UInt16, 
    privPtr: UnsafeMutablePointer<UInt8>, privLen: UnsafeMutablePointer<UInt64>, 
    pubPtr: UnsafeMutablePointer<UInt8>, pubLen: UnsafeMutablePointer<UInt64>
) -> UInt64 
{
    var privRaw = Data()
    var pubRaw = Data()
    let kemID = KemId(rawValue: kemID)!
    switch kemID {
    case .DhKemP256Sha256Aes128:
        let priv = P256.KeyAgreement.PrivateKey()
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentation
        pubRaw = try! pub.hpkeRepresentation(kem: kemID.hpkeKem)

    case .DhKemP384Sha384Aes256:
        let priv = P384.KeyAgreement.PrivateKey()
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentation
        pubRaw = try! pub.hpkeRepresentation(kem: kemID.hpkeKem)

    case .DhKemP521Sha512Aes256:
        let priv = P521.KeyAgreement.PrivateKey()
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentation
        pubRaw = try! pub.hpkeRepresentation(kem: kemID.hpkeKem)

    case .DhKemX25519Sha256Aes128:
        fallthrough
    case .DhKemX25519Sha256ChaChaPoly:
        let priv = Curve25519.KeyAgreement.PrivateKey()
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentation
        pubRaw = try! pub.hpkeRepresentation(kem: kemID.hpkeKem)
    }

    guard copyToOutput(from: privRaw, ptr: privPtr, lenPtr: privLen) == 1 else { return 0 }
    guard copyToOutput(from: pubRaw, ptr: pubPtr, lenPtr: pubLen) == 1 else { return 0 }
    return 1
}

func unwrapBytes<B>(_ data: B) -> Data 
where B: ContiguousBytes
{
    return data.withUnsafeBytes { buffer in Data(buffer) }
}

func LabeledExtract(kemID: KemId, salt: Data, label: Data, ikm: Data) -> Data {
    // labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
    var labeledIKM = "HPKE-v1".data(using: .utf8)!
    labeledIKM.append(kemID.suiteID)
    labeledIKM.append(label)
    labeledIKM.append(ikm)

    // return Extract(salt, labeled_ikm)
    let ikm = SymmetricKey(data: labeledIKM)
    switch kemID {
    case .DhKemP256Sha256Aes128:
        fallthrough
    case .DhKemX25519Sha256Aes128:
        fallthrough
    case .DhKemX25519Sha256ChaChaPoly:
        return unwrapBytes(HKDF<SHA256>.extract(inputKeyMaterial: ikm, salt: salt))

    case .DhKemP384Sha384Aes256:
        return unwrapBytes(HKDF<SHA384>.extract(inputKeyMaterial: ikm, salt: salt))

    case .DhKemP521Sha512Aes256:
        return unwrapBytes(HKDF<SHA512>.extract(inputKeyMaterial: ikm, salt: salt))
    }
}

func LabeledExpand(kemID: KemId, prk: Data, label: Data, info: Data, len: Int) -> Data {
    // labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
    var labeledInfo = Data([UInt8(len >> 8), UInt8(len)])
    labeledInfo.append("HPKE-v1".data(using: .utf8)!)
    labeledInfo.append(kemID.suiteID)
    labeledInfo.append(label)
    labeledInfo.append(info)

    // return Expand(prk, labeled_info, L)
    switch kemID {
    case .DhKemP256Sha256Aes128:
        fallthrough
    case .DhKemX25519Sha256Aes128:
        fallthrough
    case .DhKemX25519Sha256ChaChaPoly:
        return unwrapBytes(HKDF<SHA256>.expand(pseudoRandomKey: prk, info: labeledInfo, outputByteCount: len))

    case .DhKemP384Sha384Aes256:
        return unwrapBytes(HKDF<SHA384>.expand(pseudoRandomKey: prk, info: labeledInfo, outputByteCount: len))

    case .DhKemP521Sha512Aes256:
        return unwrapBytes(HKDF<SHA512>.expand(pseudoRandomKey: prk, info: labeledInfo, outputByteCount: len))
    }
}

func bigintLessThan(_ a: Data, _ b: Data) -> Bool {
    // For big-endian a, b, a < b iff at the first digit at which a and b
    // differ, the a digit is less than the b digit
    let diffs = zip(a, b).filter { (x, y) in x == y }
    if diffs.count == 0 {
        // The two numbers are equal
        return false
    }

    let (da, db) = diffs[0]
    return da < db
}

func derive_key_pair_nist(kemID: KemId, ikm: Data) -> Data? {
    let prkLabel = "dkp_prk".data(using: .utf8)!
    let candidateLabel = "candidate".data(using: .utf8)!
    let dkpPrk = LabeledExtract(kemID: kemID, salt: Data(), label: prkLabel, ikm: ikm)
    let zero = Data([UInt8](repeating: 0, count: kemID.nsk))
    let order = kemID.order

    let bitmask = switch kemID {
    case .DhKemP256Sha256Aes128: UInt8(0xff)
    case .DhKemX25519Sha256Aes128: UInt8(0xff)
    case .DhKemX25519Sha256ChaChaPoly: UInt8(0x01)
    case .DhKemP384Sha384Aes256: UInt8(0x00) // unused
    case .DhKemP521Sha512Aes256: UInt8(0x00) // unused
    }

    var counter = 0
    while counter <= 255 {
        let counterInfo = Data([UInt8(counter)])
        var sk = LabeledExpand(kemID: kemID, prk: dkpPrk, label: candidateLabel, info: counterInfo, len: kemID.nsk)
        sk[0] &= bitmask

        if bigintLessThan(zero, sk) && bigintLessThan(sk, order) {
            return sk
        }

        counter += 1
    }

    return nil
}

func derive_key_pair_x25519(kemID: KemId, ikm: Data) -> Data {
    let Nsk = 32
    let prkLabel = "dkp_prk".data(using: .utf8)!
    let skLabel = "sk".data(using: .utf8)!

    let dkpPrk = LabeledExtract(kemID: kemID, salt: Data(), label: prkLabel, ikm: ikm)
    return LabeledExpand(kemID: kemID, prk: dkpPrk, label: skLabel, info: Data(), len: Nsk)
}

// fn kem_derive(
//     &self,
//     ikm: &[u8]
// ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;
@_cdecl("kem_derive")
public func kem_derive(kemID: UInt16, 
    ikmPtr: UnsafePointer<UInt8>, ikmLen: UInt64,
    privPtr: UnsafeMutablePointer<UInt8>, privLen: UnsafeMutablePointer<UInt64>, 
    pubPtr: UnsafeMutablePointer<UInt8>, pubLen: UnsafeMutablePointer<UInt64>
) -> UInt64 
{
    let ikm = dataFromRawParts(ptr: ikmPtr, len: ikmLen)

    var privRaw = Data()
    var pubRaw = Data()
    let kemID = KemId(rawValue: kemID)!
    switch kemID {
    case .DhKemP256Sha256Aes128:
        guard let skm = derive_key_pair_nist(kemID: kemID, ikm: ikm) else { return 0 }
        let priv = try! P256.KeyAgreement.PrivateKey(rawRepresentation: skm)
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentation
        pubRaw = try! pub.hpkeRepresentation(kem: kemID.hpkeKem)

    case .DhKemP384Sha384Aes256:
        guard let skm = derive_key_pair_nist(kemID: kemID, ikm: ikm) else { return 0 }
        let priv = try! P384.KeyAgreement.PrivateKey(rawRepresentation: skm)
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentation
        pubRaw = try! pub.hpkeRepresentation(kem: kemID.hpkeKem)

    case .DhKemP521Sha512Aes256:
        guard let skm = derive_key_pair_nist(kemID: kemID, ikm: ikm) else { return 0 }
        let priv = try! P521.KeyAgreement.PrivateKey(rawRepresentation: skm)
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentation
        pubRaw = try! pub.hpkeRepresentation(kem: kemID.hpkeKem)

    case .DhKemX25519Sha256Aes128:
        fallthrough
    case .DhKemX25519Sha256ChaChaPoly:
        let skm = derive_key_pair_x25519(kemID: kemID, ikm: ikm)
        let priv = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: skm)
        let pub = priv.publicKey 

        privRaw = priv.rawRepresentation
        pubRaw = try! pub.hpkeRepresentation(kem: kemID.hpkeKem)
    }

    guard copyToOutput(from: privRaw, ptr: privPtr, lenPtr: privLen) == 1 else { return 0 }
    guard copyToOutput(from: pubRaw, ptr: pubPtr, lenPtr: pubLen) == 1 else { return 0 }
    return 1
}

// fn kem_public_key_validate(
//     &self,
//     key: &HpkePublicKey
// ) -> Result<(), Self::Error>;
@_cdecl("kem_public_key_validate")
public func kem_public_key_validate(kemID: UInt16, 
    pubPtr: UnsafePointer<UInt8>, pubLen: UInt64 
) -> UInt64 
{
    let pubRaw = dataFromRawParts(ptr: pubPtr, len: pubLen)
    
    let kemID = KemId(rawValue: kemID)!
    switch kemID {
    case .DhKemP256Sha256Aes128:
        do {
            _ = try P256.KeyAgreement.PublicKey(pubRaw, kem: kemID.hpkeKem)
            return 1
        } catch {
            return 0
        }

    case .DhKemP384Sha384Aes256:
        do {
            _ = try P384.KeyAgreement.PublicKey(pubRaw, kem: kemID.hpkeKem)
            return 1
        } catch {
            return 0
        }

    case .DhKemP521Sha512Aes256:
        do {
            _ = try P521.KeyAgreement.PublicKey(pubRaw, kem: kemID.hpkeKem)
            return 1
        } catch {
            return 0
        }

    case .DhKemX25519Sha256Aes128:
        fallthrough
    case .DhKemX25519Sha256ChaChaPoly:
        do {
            _ = try Curve25519.KeyAgreement.PublicKey(pubRaw, kem: kemID.hpkeKem)
            return 1
        } catch {
            return 0
        }
    }
}

// fn hpke_setup_s(
//     &self,
//     remote_key: &HpkePublicKey,
//     info: &[u8]
// ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error>;
@_cdecl("hpke_setup_s")
public func hpke_setup_s(kemID: UInt16, 
    pubPtr: UnsafePointer<UInt8>, pubLen: UInt64,
    infoPtr: UnsafePointer<UInt8>, infoLen: UInt64,
    encPtr: UnsafeMutablePointer<UInt8>, encLen: UnsafeMutablePointer<UInt64>
) -> UnsafeMutableRawPointer?
{
    let pubRaw = dataFromRawParts(ptr: pubPtr, len: pubLen)
    let info = dataFromRawParts(ptr: infoPtr, len: infoLen)
    
    let kemID = KemId(rawValue: kemID)!
    var maybe_sender: HPKE.Sender? = nil
    switch kemID {
    case .DhKemP256Sha256Aes128:
        do {
            let pub = try P256.KeyAgreement.PublicKey(pubRaw, kem: kemID.hpkeKem)
            maybe_sender = try HPKE.Sender(recipientKey: pub, ciphersuite: kemID.hpkeCipherSuite, info: info)
        } catch {
            return nil
        }

    case .DhKemP384Sha384Aes256:
        do {
            let pub = try P384.KeyAgreement.PublicKey(pubRaw, kem: kemID.hpkeKem)
            maybe_sender = try HPKE.Sender(recipientKey: pub, ciphersuite: kemID.hpkeCipherSuite, info: info)
        } catch {
            return nil
        }

    case .DhKemP521Sha512Aes256:
        do {
            let pub = try P521.KeyAgreement.PublicKey(pubRaw, kem: kemID.hpkeKem)
            maybe_sender = try HPKE.Sender(recipientKey: pub, ciphersuite: kemID.hpkeCipherSuite, info: info)
        } catch {
            return nil
        }

    case .DhKemX25519Sha256Aes128:
        fallthrough
    case .DhKemX25519Sha256ChaChaPoly:
        do {
            let pub = try Curve25519.KeyAgreement.PublicKey(pubRaw, kem: kemID.hpkeKem)
            maybe_sender = try HPKE.Sender(recipientKey: pub, ciphersuite: kemID.hpkeCipherSuite, info: info)
        } catch {
            return nil
        }
    }
    
    let sender = maybe_sender!
    guard copyToOutput(from: sender.encapsulatedKey, ptr: encPtr, lenPtr: encLen) == 1 else { return nil }
    return exportPointer(SenderWrapper(sender))
}

// fn hpke_seal_s(
//     &mut self,
//     aad: Option<&[u8]>,
//     data: &[u8]
// ) -> Result<Vec<u8>, Self::Error>;
@_cdecl("hpke_seal_s")
public func hpke_seal_s(
    senderPtr: UnsafeMutableRawPointer,
    aadPtr: UnsafePointer<UInt8>, aadLen: UInt64,
    dataPtr: UnsafePointer<UInt8>, dataLen: UInt64,
    ctPtr: UnsafeMutablePointer<UInt8>, ctLen: UnsafeMutablePointer<UInt64>
) -> UInt64
{
    let sender: SenderWrapper = pointerToRef(senderPtr)
    
    let aad = dataFromRawParts(ptr: aadPtr, len: aadLen)
    let data = dataFromRawParts(ptr: dataPtr, len: dataLen)
    
    do {
        let ct = try sender.sender!.seal(data, authenticating: aad)
        return copyToOutput(from: ct, ptr: ctPtr, lenPtr: ctLen)
    } catch {
        return 0
    }
}

// fn hpke_export_s(
//     &self,
//     exporter_context: &[u8],
//     len: usize
// ) -> Result<Vec<u8>, Self::Error>;
@_cdecl("hpke_export_s")
public func hpke_export_s(
    senderPtr: UnsafeMutableRawPointer,
    ctxPtr: UnsafePointer<UInt8>, ctxLen: UInt64,
    outPtr: UnsafeMutablePointer<UInt8>, outLen: UInt64
) -> UInt64
{
    let sender: SenderWrapper = pointerToRef(senderPtr)
    
    let ctx = dataFromRawParts(ptr: ctxPtr, len: ctxLen)
    
    do {
        let out = try sender.sender!.exportSecret(context: ctx, outputByteCount: Int(outLen))
        return copyToOutput(from: out, ptr: outPtr, len: outLen)
    } catch {
        return 0
    }
}

// fn hpke_drop_s()
@_cdecl("hpke_drop_s")
public func hpke_drop_s( 
    senderPtr: UnsafeMutableRawPointer
)
{
    let _: SenderWrapper? = importAndDropPointer(senderPtr)
}

// fn hpke_setup_r(
//     &self,
//     kem_output: &[u8],
//     local_secret: &HpkeSecretKey,
//     local_public: &HpkePublicKey,
//     info: &[u8]
// ) -> Result<Self::HpkeContextR, Self::Error>;
@_cdecl("hpke_setup_r")
public func hpke_setup_r(kemID: UInt16, 
    encPtr: UnsafePointer<UInt8>, encLen: UInt64,
    privPtr: UnsafePointer<UInt8>, privLen: UInt64,
    infoPtr: UnsafePointer<UInt8>, infoLen: UInt64
) -> UnsafeMutableRawPointer?
{
    let enc = dataFromRawParts(ptr: encPtr, len: encLen)
    let privRaw = dataFromRawParts(ptr: privPtr, len: privLen)
    let info = dataFromRawParts(ptr: infoPtr, len: infoLen)
    
    let kemID = KemId(rawValue: kemID)!
    var maybe_recipient: HPKE.Recipient? = nil
    switch kemID {
    case .DhKemP256Sha256Aes128:
        do {
            let priv = try P256.KeyAgreement.PrivateKey(rawRepresentation: privRaw)
            maybe_recipient = 
                try HPKE.Recipient(privateKey: priv, ciphersuite: kemID.hpkeCipherSuite, info: info, encapsulatedKey: enc)
        } catch {
            return nil
        }

    case .DhKemP384Sha384Aes256:
        do {
            let priv = try P384.KeyAgreement.PrivateKey(rawRepresentation: privRaw)
            maybe_recipient = 
                try HPKE.Recipient(privateKey: priv, ciphersuite: kemID.hpkeCipherSuite, info: info, encapsulatedKey: enc)
        } catch {
            return nil
        }

    case .DhKemP521Sha512Aes256:
        do {
            let priv = try P521.KeyAgreement.PrivateKey(rawRepresentation: privRaw)
            maybe_recipient = 
                try HPKE.Recipient(privateKey: priv, ciphersuite: kemID.hpkeCipherSuite, info: info, encapsulatedKey: enc)
        } catch {
            return nil
        }

    case .DhKemX25519Sha256Aes128:
        fallthrough
    case .DhKemX25519Sha256ChaChaPoly:
        do {
            let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privRaw)
            maybe_recipient = 
                try HPKE.Recipient(privateKey: priv, ciphersuite: kemID.hpkeCipherSuite, info: info, encapsulatedKey: enc)
        } catch {
            return nil
        }
    }
    
    return exportPointer(RecipientWrapper(maybe_recipient!))
}

// fn hpke_open_r(
//     &mut self,
//     aad: Option<&[u8]>,
//     ciphertext: &[u8]
// ) -> Result<Vec<u8>, Self::Error>;
@_cdecl("hpke_open_r")
public func hpke_open_r(
    recipientPtr: UnsafeMutableRawPointer,
    aadPtr: UnsafePointer<UInt8>, aadLen: UInt64,
    dataPtr: UnsafePointer<UInt8>, dataLen: UInt64,
    ptPtr: UnsafeMutablePointer<UInt8>, ptLen: UnsafeMutablePointer<UInt64>
) -> UInt64
{
    let recipient: RecipientWrapper = pointerToRef(recipientPtr)
    
    let aad = dataFromRawParts(ptr: aadPtr, len: aadLen)
    let data = dataFromRawParts(ptr: dataPtr, len: dataLen)
    
    do {
        let pt = try recipient.recipient!.open(data, authenticating: aad)
        return copyToOutput(from: pt, ptr: ptPtr, lenPtr: ptLen)
    } catch {
        return 0
    }
}

// fn hpke_export_r(
//     &self,
//     exporter_context: &[u8],
//     len: usize
// ) -> Result<Vec<u8>, Self::Error>;
@_cdecl("hpke_export_r")
public func hpke_export_r(
    recipientPtr: UnsafeMutableRawPointer,
    ctxPtr: UnsafePointer<UInt8>, ctxLen: UInt64,
    outPtr: UnsafeMutablePointer<UInt8>, outLen: UInt64
) -> UInt64
{
    let recipient: RecipientWrapper = pointerToRef(recipientPtr)
    
    let ctx = dataFromRawParts(ptr: ctxPtr, len: ctxLen)
    
    do {
        let out = try recipient.recipient!.exportSecret(context: ctx, outputByteCount: Int(outLen))
        return copyToOutput(from: out, ptr: outPtr, len: outLen)
    } catch {
        return 0
    }
}

// fn hpke_drop_r()
@_cdecl("hpke_drop_r")
public func hpke_drop_r( 
    recipientPtr: UnsafeMutableRawPointer
)
{
    let _: RecipientWrapper? = importAndDropPointer(recipientPtr)
}
