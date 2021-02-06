use crate::digest::MessageDigest;
use openssl::error::ErrorStack;
use thiserror::Error;
use std::iter::repeat;
use std::ptr;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use std::ops::Deref;

pub trait KeyDerivationFunction {
    fn extract(&self, salt: &[u8], key: &Vec<u8>) -> Result<Vec<u8>, KeyDerivationError>;
    fn expand(&self, key: &Vec<u8>, info: &[u8], out_len: u8) -> Result<Vec<u8>, KeyDerivationError>;
}

#[derive(Error, Debug)]
pub enum KeyDerivationError {
    #[error("Openssl error: {0}")]
    OpenSSLError(#[from] ErrorStack),
}

pub struct Hkdf {
    digest: MessageDigest,
}

pub struct HkdfSha256(Hkdf);
pub struct HkdfSha512(Hkdf);

impl Deref for HkdfSha256 {
    type Target = Hkdf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for HkdfSha512 {
    type Target = Hkdf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl HkdfSha256 {
    pub fn new() -> Self {
        Self(Hkdf::new(MessageDigest::Sha256))
    }
}

impl HkdfSha512 {
    pub fn new() -> Self {
        Self(Hkdf::new(MessageDigest::Sha512))
    }
}

impl Hkdf {
    pub fn new(digest: MessageDigest) -> Self {
        Hkdf {
            digest,
        }
    }
}

/* Based on rust-crypto https://github.com/DaGenix/rust-crypto/blob/master/src/hkdf.rs
   The OpenSSL crate does not expose HKDF yet, when it does we can use that
*/

#[inline]
pub fn copy_memory(src: &[u8], dst: &mut [u8]) {
    assert!(dst.len() >= src.len());
    unsafe {
        let srcp = src.as_ptr();
        let dstp = dst.as_mut_ptr();
        ptr::copy_nonoverlapping(srcp, dstp, src.len());
    }
}

fn extract(digest: MessageDigest, salt: &[u8], key: &Vec<u8>) -> Result<Vec<u8>, KeyDerivationError> {
    let key = PKey::hmac(key)?;
    let mut signer = Signer::new(digest.into(), &key)?;
    signer
        .sign_oneshot_to_vec(salt)
        .map_err(|e| e.into())
}

fn expand(digest: MessageDigest, key: &Vec<u8>, info: &[u8], out_len: u8) -> Result<Vec<u8>, KeyDerivationError> {
    let key = PKey::hmac(key)?;
    let ossl_digest = digest.clone().into();
    let mut mac = Signer::new(ossl_digest, &key)?;

    let os = digest.len();
    let mut t: Vec<u8> = repeat(0).take(os as usize).collect();
    let mut n: u8 = 0;

    let mut okm = [out_len; 0];

    for chunk in okm.chunks_mut(os as usize) {
        // The block index starts at 1. So, this is supposed to run on the first execution.
        n = n.checked_add(1).expect("HKDF size limit exceeded.");

        if n != 1 {
            mac.update(&t[..])?;
        }
        let nbuf = [n];
        mac.update(info)?;
        mac.update(&nbuf)?;
        mac.sign(&mut t)?;
        mac = Signer::new(ossl_digest, &key)?;
        let chunk_len = chunk.len();
        copy_memory(&t[..chunk_len], chunk);
    }

    Ok(okm.to_vec())
}

//TODO: Figure out macros so that this isn't duplicated
impl KeyDerivationFunction for HkdfSha256 {
    fn extract(&self, salt: &[u8], key: &Vec<u8>) -> Result<Vec<u8>, KeyDerivationError> {
        extract(self.digest.clone(), salt, key)
    }

    fn expand(&self, key: &Vec<u8>, info: &[u8], out_len: u8) -> Result<Vec<u8>, KeyDerivationError> {
        expand(self.digest.clone(), key, info, out_len)
    }
}

impl KeyDerivationFunction for HkdfSha512 {
    fn extract(&self, salt: &[u8], key: &Vec<u8>) -> Result<Vec<u8>, KeyDerivationError> {
        extract(self.digest.clone(), salt, key)
    }

    fn expand(&self, key: &Vec<u8>, info: &[u8], out_len: u8) -> Result<Vec<u8>, KeyDerivationError> {
        expand(self.digest.clone(), key, info, out_len)
    }
}