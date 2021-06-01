use openssl::error::ErrorStack;
use openssl::hash::{hash, Hasher, MessageDigest};
use openssl::pkey::PKey;
use openssl::sign::Signer;
use ossl::OpenSslHashFunction;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HashError {
    #[error("Openssl error: {0}")]
    OpenSSLError(#[from] ErrorStack),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Mac {
    pub mac_value: Vec<u8>,
}

impl From<Vec<u8>> for Mac {
    fn from(mac_value: Vec<u8>) -> Self {
        Mac { mac_value }
    }
}

pub trait HashFunction {
    const OUT_LEN: u16;
    fn update(&mut self, data: &[u8]) -> Result<(), HashError>;
    fn finish(&mut self) -> Result<Vec<u8>, HashError>;
    fn hash(data: &[u8]) -> Result<Vec<u8>, HashError>;
    fn hmac(key: &[u8], message: &[u8]) -> Result<Mac, HashError>;
}

#[macro_use]
pub(crate) mod ossl {
    use openssl::hash::MessageDigest;

    pub(crate) trait OpenSslHashFunction {
        fn get_digest() -> MessageDigest;
    }

    macro_rules! impl_openssl_hash {
        ($name:ident, $digest:expr, $out_size:expr) => {
            pub struct $name {
                hasher: Hasher,
            }

            impl $name {
                fn new() -> Result<Self, HashError> {
                    Ok(Self {
                        hasher: Hasher::new($digest)?,
                    })
                }
            }

            impl HashFunction for $name {
                const OUT_LEN: u16 = $out_size as u16;

                fn update(&mut self, data: &[u8]) -> Result<(), HashError> {
                    self.hasher.update(data).map_err(|e| e.into())
                }

                fn finish(&mut self) -> Result<Vec<u8>, HashError> {
                    self.hasher
                        .finish()
                        .map(|d| d.to_vec())
                        .map_err(|e| e.into())
                }

                fn hash(data: &[u8]) -> Result<Vec<u8>, HashError> {
                    hash($digest, data)
                        .map(|d| d.to_vec())
                        .map_err(|e| e.into())
                }

                fn hmac(key: &[u8], message: &[u8]) -> Result<Mac, HashError> {
                    let ossl_key = PKey::hmac(key)?;
                    let mut signer = Signer::new($digest, &ossl_key)?;
                    signer
                        .sign_oneshot_to_vec(message)
                        .map(|o| Mac { mac_value: o })
                        .map_err(|e| e.into())
                }
            }

            impl OpenSslHashFunction for $name {
                fn get_digest() -> MessageDigest {
                    $digest
                }
            }
        };
    }
}

impl_openssl_hash!(Sha256, MessageDigest::sha256(), 32);
impl_openssl_hash!(Sha512, MessageDigest::sha512(), 64);

#[cfg(test)]
pub mod test_util {
    use super::{HashError, HashFunction, Mac};
    use mockall::mock;

    mock! {
        pub TestHashFunction {}
        impl HashFunction for TestHashFunction {
            const OUT_LEN: u16 = 0;
            fn update(&mut self, data: &[u8]) -> Result<(), HashError>;
            fn finish(&mut self) -> Result<Vec<u8>, HashError>;
            fn hash(data: &[u8]) -> Result<Vec<u8>, HashError>;
            fn hmac(key: &[u8], message: &[u8]) -> Result<Mac, HashError>;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::hash::{HashFunction, Sha256, Sha512};

    #[test]
    fn test_sha256() {
        let expected = hex!(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace\
                                      2efcde9"
        );

        let mut sha_256 = Sha256::new().expect("failed to create hasher");
        sha_256.update(b"hello").expect("failed to update hasher");
        sha_256.update(b" world").expect("failed to update hasher");

        let output = sha_256.finish().expect("failed to finish hasher");
        assert_eq!(output, expected);
        assert_eq!(
            Sha256::hash(b"hello world").expect("failed to hash"),
            expected
        );
    }

    #[test]
    fn test_hmac_sha256() {
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let message = hex!("4869205468657265");
        let expected = hex!(
            "b0344c61d8db38535ca8afceaf0bf12b\
                                      881dc200c9833da726e9376c2e32cff7"
        );

        let output = Sha256::hmac(&key, &message).unwrap();
        assert_eq!(output.mac_value, expected);
    }

    #[test]
    fn test_sha512() {
        let expected = hex!(
            "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca\
                                      86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7\
                                      dc5542e93ae9cd76f"
        );

        let mut sha_512 = Sha512::new().expect("failed to create hasher");
        sha_512.update(b"hello").expect("failed to update hasher");
        sha_512.update(b" world").expect("failed to update hasher");

        let output = sha_512.finish().expect("failed to finish hasher");
        assert_eq!(output, expected);
        assert_eq!(
            Sha512::hash(b"hello world").expect("failed to hash"),
            expected
        );
    }

    #[test]
    fn test_hmac_sha512() {
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let message = hex!("4869205468657265");
        let expected = hex!(
            "87aa7cdea5ef619d4ff0b4241a1d6cb0\
                                      2379f4e2ce4ec2787ad0b30545e17cde\
                                      daa833b7d6b8a702038b274eaea3f4e4\
                                      be9d914eeb61f1702e696c203a126854"
        );

        let output = Sha512::hmac(&key, &message).unwrap();
        assert_eq!(output.mac_value, expected);
    }
}
