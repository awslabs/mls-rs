use thiserror::Error;
use openssl::error::ErrorStack;
use openssl::hash::{Hasher, MessageDigest, hash};

#[derive(Error, Debug)]
pub enum HashError {
    #[error("Openssl error: {0}")]
    OpenSSLError(#[from] ErrorStack),
}

trait HashFunction {
    const OUT_LEN: u16;
    fn update(&mut self, data: &[u8]) -> Result<(), HashError>;
    fn finish(&mut self) -> Result<Vec<u8>, HashError>;
    fn hash(data: &[u8]) -> Result<Vec<u8>, HashError>;
}

#[macro_use]
mod ossl {
    macro_rules! impl_openssl_hash {
        ($name:ident, $digest:expr, $out_size:expr) => {
            pub struct $name {
                hasher: Hasher
            }

            impl $name {
                fn new() -> Result<Self, HashError> {
                    Ok(Self {
                        hasher: Hasher::new($digest)?
                    })
                }
            }

            impl HashFunction for $name {
                const OUT_LEN: u16 = $out_size as u16;

                fn update(&mut self, data: &[u8]) -> Result<(), HashError> {
                    self.hasher.update(data)
                        .map_err(|e| e.into())
                }

                fn finish(&mut self) -> Result<Vec<u8>, HashError> {
                    self.hasher.finish()
                        .map(|d| d.to_vec())
                        .map_err(|e| e.into())
                }

                fn hash(data: &[u8]) -> Result<Vec<u8>, HashError> {
                    hash($digest, data)
                        .map(|d| d.to_vec())
                        .map_err(|e| e.into())
                }
            }
        };
    }
}

impl_openssl_hash!(Sha256, MessageDigest::sha256(), 32);
impl_openssl_hash!(Sha512, MessageDigest::sha512(), 64);

#[cfg(test)]
mod test {
    use crate::hash::{Sha256, HashFunction, Sha512};

    #[test]
    fn test_sha256() {
        let expected = hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace\
                                      2efcde9");

        let mut sha_256 = Sha256::new().expect("failed to create hasher");
        sha_256.update(b"hello").expect("failed to update hasher");
        sha_256.update(b" world").expect("failed to update hasher");

        let output = sha_256.finish().expect("failed to finish hasher");
        assert_eq!(output, expected);
        assert_eq!(Sha256::hash(b"hello world").expect("failed to hash"), expected);
    }

    #[test]
    fn test_sha512() {
        let expected = hex!("309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca\
                                      86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7\
                                      dc5542e93ae9cd76f");

        let mut sha_512 = Sha512::new().expect("failed to create hasher");
        sha_512.update(b"hello").expect("failed to update hasher");
        sha_512.update(b" world").expect("failed to update hasher");

        let output = sha_512.finish().expect("failed to finish hasher");
        assert_eq!(output, expected);
        assert_eq!(Sha512::hash(b"hello world").expect("failed to hash"), expected);
    }
}





