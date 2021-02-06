use thiserror::Error;
use openssl::error::ErrorStack;
use openssl::symm::{encrypt_aead, decrypt_aead};

pub struct CipherText {
    pub nonce: Vec<u8>,
    pub data: Vec<u8>,
    pub tag: Vec<u8>
}

pub trait NonceGenerator {
    fn gen(&self) -> Vec<u8>;
}

impl NonceGenerator for Vec<u8> {
    fn gen(&self) -> Vec<u8> {
        return self.to_vec();
    }
}

pub struct CipherInfo {
    pub key_len: u8,
    pub nonce_len: u8,
    pub tag_len: u8,
}

pub trait Key {
    fn get_data(&self) -> &Vec<u8>;
}

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Invalid key size: {0}")]
    InvalidKeySize(usize),
    #[error("Openssl error: {0}")]
    OpenSSLError(#[from] ErrorStack)
}

pub trait Cipher {
    fn info() -> CipherInfo;
    fn encrypt<NG: NonceGenerator>(&self,
                                   key: &Vec<u8>,
                                   data: &Vec<u8>,
                                   aad: Option<&Vec<u8>>,
                                   nonce: &NG) -> Result<CipherText, CipherError>;
    fn decrypt(&self,
               key: &Vec<u8>,
               cipher_text: &CipherText,
               aad: Option<&Vec<u8>>) -> Result<Vec<u8>, CipherError>;
}

struct Aes256Gcm {}

impl Cipher for Aes256Gcm {

    fn info() -> CipherInfo {
        CipherInfo {
            key_len: 32,
            nonce_len: 16,
            tag_len: 12
        }
    }

    fn encrypt<NG: NonceGenerator>(&self,
                                   key: &Vec<u8>,
                                   data: &Vec<u8>,
                                   aad: Option<&Vec<u8>>,
                                   nonce: &NG) -> Result<CipherText, CipherError> {

        if key.len() != Self::info().key_len as usize {
            return Err(CipherError::InvalidKeySize(key.len()));
        }

        let iv = nonce.gen();
        let mut tag_out = vec![0; Self::info().tag_len as usize];
        let encrypted = encrypt_aead(openssl::symm::Cipher::aes_256_gcm(),
                                     &key,
                                     Some(&iv),
                                     &aad.unwrap_or(&Vec::new()),
                                     data,
                                     &mut tag_out)?;

        Ok(CipherText {
            nonce: iv,
            data: encrypted,
            tag: tag_out
        })
    }

    fn decrypt(&self,key: &Vec<u8>, ciphertext: &CipherText, aad: Option<&Vec<u8>>) -> Result<Vec<u8>, CipherError> {

        if key.len() != Self::info().key_len as usize {
            return Err(CipherError::InvalidKeySize(key.len()));
        }

        decrypt_aead(openssl::symm::Cipher::aes_256_gcm(),
                     &key,
                     Some(&ciphertext.data),
                     aad.unwrap_or(&Vec::new()),
                     &ciphertext.data,
                     &ciphertext.tag)
            .map_err(|e| CipherError::OpenSSLError(e))
    }
}