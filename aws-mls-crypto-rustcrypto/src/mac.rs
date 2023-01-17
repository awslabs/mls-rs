use aws_mls_core::crypto::CipherSuite;
use hmac::{
    digest::{crypto_common::BlockSizeUser, FixedOutputReset},
    Mac, SimpleHmac,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error(transparent)]
    InvalidHmacLength(#[from] hmac::digest::InvalidLength),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        match cipher_suite {
            CipherSuite::Curve25519Aes128
            | CipherSuite::P256Aes128
            | CipherSuite::Curve25519ChaCha20 => Hash::Sha256,
            CipherSuite::P384Aes256 => Hash::Sha384,
            _ => Hash::Sha512,
        }
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    pub fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, HashError> {
        match self {
            Hash::Sha256 => generic_generate_tag(SimpleHmac::<Sha256>::new_from_slice(key)?, data),
            Hash::Sha384 => generic_generate_tag(SimpleHmac::<Sha384>::new_from_slice(key)?, data),
            Hash::Sha512 => generic_generate_tag(SimpleHmac::<Sha512>::new_from_slice(key)?, data),
        }
    }
}

fn generic_generate_tag<D: Digest + BlockSizeUser + FixedOutputReset>(
    mut hmac: SimpleHmac<D>,
    data: &[u8],
) -> Result<Vec<u8>, HashError> {
    hmac.update(data);
    let res = hmac.finalize().into_bytes().to_vec();
    Ok(res)
}
