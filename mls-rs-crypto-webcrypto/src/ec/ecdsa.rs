use der::{asn1::Uint, Decode, Encode, Sequence};
use js_sys::{Boolean, Uint8Array};
use mls_rs_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};
use wasm_bindgen_futures::JsFuture;
use web_sys::EcdsaParams;

use super::der_private_key::{generate, DerPrivateKey};
use crate::{get_crypto, key_type::KeyType, CryptoError};

#[derive(Sequence)]
struct DerSignature {
    pub r: Uint,
    pub s: Uint,
}

fn wasm_signature_to_der(signature: &[u8]) -> Result<Vec<u8>, der::Error> {
    let (r, s) = signature.split_at(signature.len() / 2);
    let r = Uint::new(r)?;
    let s = Uint::new(s)?;

    DerSignature { r, s }.to_der()
}

#[derive(Debug, Clone)]
pub(crate) struct EcSigner {
    curve: &'static str,
    hash: &'static str,
    curve_bytesize: usize,
}

impl EcSigner {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        match cipher_suite {
            CipherSuite::P256_AES128 => Some(Self {
                curve: "P-256",
                hash: "SHA-256",
                curve_bytesize: 32,
            }),
            CipherSuite::P384_AES256 => Some(Self {
                curve: "P-384",
                hash: "SHA-384",
                curve_bytesize: 48,
            }),
            CipherSuite::P521_AES256 => Some(Self {
                curve: "P-521",
                hash: "SHA-512",
                curve_bytesize: 66,
            }),
            _ => None,
        }
    }

    pub async fn generate(&self) -> Result<(SignatureSecretKey, SignaturePublicKey), CryptoError> {
        // It does not matter whether it's for ECDH or ECDSA
        let (private, public) = generate(self.curve).await?;
        Ok((private.into(), public.into()))
    }

    pub async fn sign(
        &self,
        key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let crypto = get_crypto()?;
        let key_type = KeyType::EcdsaSecret(self.curve);

        let key = key_type.import(&crypto, key).await?;
        let params = EcdsaParams::new(key_type.algorithm(), &self.hash.into());
        let data = Uint8Array::from(data);

        let signature = crypto.sign_with_object_and_buffer_source(&params, &key, &data)?;
        let signature = Uint8Array::new(&JsFuture::from(signature).await?).to_vec();

        wasm_signature_to_der(&signature).map_err(|e| CryptoError::DerError(format!("{:?}", e)))
    }

    pub async fn verify(
        &self,
        key: &SignaturePublicKey,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let crypto = get_crypto()?;
        let key_type = KeyType::EcdsaPublic(self.curve);

        let key = key_type.import(&crypto, key).await?;
        let params = EcdsaParams::new(key_type.algorithm(), &self.hash.into());
        let data = Uint8Array::from(data);

        let signature = self
            .der_to_wasm_signature(signature)
            .map_err(|e| CryptoError::DerError(format!("{:?}", e)))?;

        let signature = Uint8Array::from(signature.as_slice());

        let valid = crypto.verify_with_object_and_buffer_source_and_buffer_source(
            &params, &key, &signature, &data,
        )?;

        let valid: Boolean = JsFuture::from(valid).await?.into();

        (valid == true)
            .then_some(())
            .ok_or(CryptoError::InvalidSignature)
    }

    // From https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign :
    //
    // Signatures are encoded as the s1 and s2 values specified in RFC 6090 (known respectively
    // as r and s in RFC 4754), each in big-endian byte arrays, with their length the bit size
    // of the curve rounded up to a whole number of bytes. These values are concatenated together
    // in this order.
    fn der_to_wasm_signature(&self, signature: &[u8]) -> Result<Vec<u8>, der::Error> {
        let signature = DerSignature::from_der(signature)?;

        let r = signature.r.as_bytes();
        let s = signature.s.as_bytes();

        let padding_r = vec![0u8; self.curve_bytesize - r.len()];
        let padding_s = vec![0u8; self.curve_bytesize - s.len()];

        Ok([&padding_r, r, &padding_s, s].concat())
    }

    // Signatures are stored in the PKCS8 format
    pub fn derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, CryptoError> {
        let private_key = DerPrivateKey::from_bytes(secret_key)
            .map_err(|e| CryptoError::DerError(e.to_string()))?;

        match private_key.public_key {
            Some(public_key) => Ok(public_key.value.raw_bytes().to_vec().into()),
            None => Err(CryptoError::CouldNotComputePublicKey),
        }
    }
}

#[cfg(test)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn test_ecdsa() {
    let signer = EcSigner::new(CipherSuite::P256_AES128).unwrap();
    let (secret, public) = signer.generate().await.unwrap();
    let signature = signer.sign(&secret, b"data").await.unwrap();
    signer.verify(&public, b"data", &signature).await.unwrap();
}

#[cfg(test)]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn s_shorter_than_curve_bitlength() {
    let signer = EcSigner::new(CipherSuite::P521_AES256).unwrap();

    let public = "0401cfb5a169bdf90f20f289abb43e494a2ffa8849241b8b9ce5d18c46f03a7ebeec1d704b7194fff616325c2b5a5f3509e9264bdd42cecf5c521b614bdfd21217305e0156031ad239d288dc63974945a7e734b6990c261eab0316ff031937bb412b30a7ee9438a42a39c8fa73ea4b3b92b87b3ce58fa666fe719650a52801396ece7ce0d1";
    let public = hex::decode(public).unwrap();

    let signature = "308188024201c0a09fd148130072b6cda33ddc76445fe005472a5272686640299a7a2206c4052bfe1c97fe9ea55466dab204789fe8696efc1a4bc1b353784f4d3d883b47fa6618024200ddc0c62b25498d87cbc71564f336cd04e872f5402433c2fb4d5c5f628117eb76398a6f450e32858ad0acb3a7114b83788901e5bd2b29861780937fe0245d355388";
    let signature = hex::decode(signature).unwrap();

    signer
        .verify(&public.into(), &[], &signature)
        .await
        .unwrap();
}
