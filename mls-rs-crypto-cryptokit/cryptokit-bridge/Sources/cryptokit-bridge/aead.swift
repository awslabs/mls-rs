import CryptoKit

// The values in this enum MUST match those of the KdfId enum in Rust:
// https://docs.rs/mls-rs-crypto-traits/latest/mls_rs_crypto_traits/enum.AeadId.html
enum AeadId : UInt16 {
    case Aes128Gcm = 1
    case Aes256Gcm = 2
    case Chacha20Poly1305 = 3
}

@_cdecl("aead_seal")
public func aead_seal(aeadID: UInt16, 
    keyPtr: UnsafePointer<UInt8>, keyLen: UInt64, 
    ptPtr: UnsafePointer<UInt8>, ptLen: UInt64, 
    aadPtr: UnsafePointer<UInt8>, aadLen: UInt64, 
    noncePtr: UnsafePointer<UInt8>, nonceLen: UInt64,
    ctPtr: UnsafeMutablePointer<UInt8>, ctLen: UInt64,
    tagPtr: UnsafeMutablePointer<UInt8>, tagLen: UInt64
) -> UInt64 
{
    let key = SymmetricKey(data: dataFromRawParts(ptr: keyPtr, len: keyLen))
    let pt = dataFromRawParts(ptr: ptPtr, len: ptLen)
    let aad = dataFromRawParts(ptr: aadPtr, len: aadLen)
    let nonce = dataFromRawParts(ptr: noncePtr, len: nonceLen)

    switch AeadId(rawValue: aeadID)! {
    case .Aes128Gcm:
        fallthrough
    case .Aes256Gcm:
        let nonce = try! AES.GCM.Nonce(data: nonce)
        let box = try! AES.GCM.seal(pt, using: key, nonce: nonce, authenticating: aad)
        
        guard copyToOutput(from: box.ciphertext, ptr: ctPtr, len: ctLen) == 1 else { return 0 }
        guard copyToOutput(from: box.tag, ptr: tagPtr, len: tagLen) == 1 else { return 0 }

    case .Chacha20Poly1305:
        let nonce = try! ChaChaPoly.Nonce(data: nonce)
        let box = try! ChaChaPoly.seal(pt, using: key, nonce: nonce, authenticating: aad)
        
        guard copyToOutput(from: box.ciphertext, ptr: ctPtr, len: ctLen) == 1 else { return 0 }
        guard copyToOutput(from: box.tag, ptr: tagPtr, len: tagLen) == 1 else { return 0 }
    }

    return 1
}

@_cdecl("aead_open")
public func aead_seal(aeadID: UInt16, 
    keyPtr: UnsafePointer<UInt8>, keyLen: UInt64, 
    ctPtr: UnsafePointer<UInt8>, ctLen: UInt64,
    tagPtr: UnsafePointer<UInt8>, tagLen: UInt64,
    aadPtr: UnsafePointer<UInt8>, aadLen: UInt64,
    noncePtr: UnsafePointer<UInt8>, nonceLen: UInt64, 
    ptPtr: UnsafeMutablePointer<UInt8>, ptLen: UInt64
) -> UInt64 
{
    let key = SymmetricKey(data: dataFromRawParts(ptr: keyPtr, len: keyLen))
    let ct = dataFromRawParts(ptr: ctPtr, len: ctLen)
    let tag = dataFromRawParts(ptr: tagPtr, len: tagLen)
    let aad = dataFromRawParts(ptr: aadPtr, len: aadLen)
    let nonce = dataFromRawParts(ptr: noncePtr, len: nonceLen)

    switch AeadId(rawValue: aeadID)! {
    case .Aes128Gcm:
        fallthrough
    case .Aes256Gcm:
        let nonce = try! AES.GCM.Nonce(data: nonce)
        let box = try! AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        
        do {
            let pt = try AES.GCM.open(box, using: key, authenticating: aad)
            guard copyToOutput(from: pt, ptr: ptPtr, len: ptLen) == 1 else { return 0 }
        } catch {
            return 0
        }

    case .Chacha20Poly1305:
        let nonce = try! ChaChaPoly.Nonce(data: nonce)
        let box = try! ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        
        do {
            let pt = try ChaChaPoly.open(box, using: key, authenticating: aad)
            guard copyToOutput(from: pt, ptr: ptPtr, len: ptLen) == 1 else { return 0 }
        } catch {
            return 0
        }
    }

    return 1
}
