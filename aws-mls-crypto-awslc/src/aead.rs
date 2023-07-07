use aws_lc_rs::aead;
use aws_mls_crypto_traits::AeadId;

use crate::AwsLcCryptoError;

#[derive(Clone)]
pub struct Aes256Gcm(AeadId);

impl Aes256Gcm {
    pub fn new() -> Self {
        Self(AeadId::Aes256Gcm)
    }
}

impl Default for Aes256Gcm {
    fn default() -> Self {
        Self::new()
    }
}

impl aws_mls_crypto_traits::AeadType for Aes256Gcm {
    type Error = AwsLcCryptoError;

    fn aead_id(&self) -> u16 {
        self.0 as u16
    }

    fn seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let mut in_out_buffer = data.to_vec();

        let key = aead::UnboundKey::new(&aead::AES_256_GCM, key)?;
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)?;

        let sealing_key = aead::LessSafeKey::new(key);

        let aad = aead::Aad::from(aad.unwrap_or_default());

        sealing_key.seal_in_place_append_tag(nonce, aad, &mut in_out_buffer)?;

        Ok(in_out_buffer)
    }

    fn open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let mut in_out_buffer = ciphertext.to_vec();

        let key = aead::UnboundKey::new(&aead::AES_256_GCM, key)?;
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)?;

        let opening_key = aead::LessSafeKey::new(key);

        let aad = aead::Aad::from(aad.unwrap_or_default());

        let len = opening_key
            .open_in_place(nonce, aad, &mut in_out_buffer)?
            .len();

        in_out_buffer.truncate(len);

        Ok(in_out_buffer)
    }

    fn key_size(&self) -> usize {
        self.0.key_size()
    }

    fn nonce_size(&self) -> usize {
        self.0.nonce_size()
    }
}
