use num_enum::{IntoPrimitive, TryFromPrimitive};
use openssl::error::ErrorStack;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Openssl error: {0}")]
    OpenSSLError(#[from] ErrorStack),
    #[error("Chacha20 error: {0}")]
    ChaCha20Error(chacha20poly1305::aead::Error),
    #[error("Invalid key: bad length {0}")]
    InvalidKey(usize),
    #[error("Invalid nonce: bad length {0}")]
    InvalidNonce(usize),
    #[error("Invalid ciphertext: bad length {0}")]
    InvalidCiphertext(usize),
}

pub trait Cipher: Sized {
    const CIPHER_ID: AeadId;
    const KEY_LEN: u16;
    const NONCE_LEN: u16;
    const TAG_LEN: u16;

    fn new(key: Vec<u8>) -> Result<Self, CipherError>;

    fn encrypt(&self, data: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CipherError>;

    fn decrypt(&self, nonce: &[u8], cipher_text: &[u8], aad: &[u8])
        -> Result<Vec<u8>, CipherError>;
}

#[macro_use]
mod ossl {
    use openssl::error::ErrorStack;
    use openssl::symm::{decrypt_aead, encrypt_aead};

    pub fn encrypt(
        cipher: openssl::symm::Cipher,
        key: &[u8],
        data: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
        let mut tag_out = vec![0; 16];
        let encrypted = encrypt_aead(cipher, &key, Some(nonce), aad, data, &mut tag_out)?;

        Ok((encrypted, tag_out))
    }

    pub fn decrypt(
        cipher: openssl::symm::Cipher,
        key: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, ErrorStack> {
        decrypt_aead(cipher, key, Some(nonce), aad, ciphertext, tag)
    }

    macro_rules! openssl_aead {
        ($name:ident, $cipher:expr, $cipher_id:expr,
            $key_len:expr, $nonce_len:expr, $tag_len:expr) => {
            #[derive(Debug, PartialEq)]
            pub struct $name {
                pub(crate) key: Vec<u8>,
            }

            impl Cipher for $name {
                const CIPHER_ID: AeadId = $cipher_id;
                const KEY_LEN: u16 = $key_len;
                const NONCE_LEN: u16 = $nonce_len;
                const TAG_LEN: u16 = $tag_len;

                fn new(key: Vec<u8>) -> Result<Self, CipherError> {
                    if key.len() != Self::KEY_LEN as usize {
                        Err(CipherError::InvalidKey(key.len()))
                    } else {
                        Ok(Self { key })
                    }
                }

                fn encrypt(
                    &self,
                    data: &[u8],
                    aad: &[u8],
                    nonce: &[u8],
                ) -> Result<Vec<u8>, CipherError> {
                    let (ciphertext, tag) =
                        super::ossl::encrypt($cipher, &self.key, data, aad, &nonce)?;
                    Ok([ciphertext, tag].concat())
                }

                fn decrypt(
                    &self,
                    nonce: &[u8],
                    ciphertext: &[u8],
                    aad: &[u8],
                ) -> Result<Vec<u8>, CipherError> {
                    let ct = ciphertext.get(0..ciphertext.len() - Self::TAG_LEN as usize);
                    let tag = ciphertext
                        .get(ciphertext.len() - (Self::TAG_LEN as usize)..ciphertext.len());

                    if ct == None || tag == None {
                        return Err(CipherError::InvalidCiphertext(ciphertext.len()));
                    }

                    super::ossl::decrypt($cipher, &self.key, ct.unwrap(), nonce, aad, tag.unwrap())
                        .map_err(CipherError::OpenSSLError)
                }
            }
        };
    }
}

pub mod aes {
    use super::{Cipher, CipherError};
    use crate::aead::AeadId;
    openssl_aead!(
        Gcm128,
        openssl::symm::Cipher::aes_128_gcm(),
        AeadId::Aes128Gcm,
        16,
        12,
        16
    );
    openssl_aead!(
        Gcm256,
        openssl::symm::Cipher::aes_256_gcm(),
        AeadId::Aes256Gcm,
        32,
        12,
        16
    );

    #[cfg(test)]
    mod tests {
        use super::Gcm128;
        use super::Gcm256;
        use crate::aead::test::{run_encrypt_decrypt, TestCase};
        use crate::aead::Cipher;

        // NIST GCM test vectors: http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip

        #[test]
        fn test_aes_128_invalid_key() {
            let too_short: Vec<u8> = vec![0; 10];
            let too_long: Vec<u8> = vec![0; 17];

            assert_eq!(Gcm128::new(too_long).is_err(), true);
            assert_eq!(Gcm128::new(too_short).is_err(), true);
        }

        #[test]
        fn test_aes256_invalid_key() {
            let too_short: Vec<u8> = vec![0; 10];
            let too_long: Vec<u8> = vec![0; 33];

            assert_eq!(Gcm256::new(too_long).is_err(), true);
            assert_eq!(Gcm256::new(too_short).is_err(), true);
        }

        #[test]
        fn test_aes_128_gcm_no_aad() {
            let test_case = TestCase {
                key: hex!("387218b246c1a8257748b56980e50c94"),
                iv: hex!("dd7e014198672be39f95b69d"),
                ct: hex!("cdba9e73eaf3d38eceb2b04a8decf90f4a47c9c626d6fb2c765d201556"),
                aad: Vec::new(),
                pt: hex!("48f5b426baca03064554cc2b30"),
            };

            run_encrypt_decrypt::<super::Gcm128>(&test_case);
        }

        #[test]
        fn test_aes_128_aad() {
            let test_case = TestCase {
                key: hex!("660eb76f3d8b6ec54e01b8a36263124b"),
                iv: hex!("3d8cf16e262880ddfe0c86eb"),
                ct: hex!("b1ee05f1415a61d7637e97c5f3761cb84a963e1db1a4ab2c5f904c09db"),
                aad: hex!("8560b10c011a1d4190eb46a3692daa17"),
                pt: hex!("2efbaedfec3cfe4ac32f201fa5"),
            };

            run_encrypt_decrypt::<super::Gcm128>(&test_case);
        }

        #[test]
        fn test_aes_256_gcm_no_aad() {
            let test_case = TestCase {
                key: hex!("a71dac1377a3bf5d7fb1b5e36bee70d2e01de2a84a1c1009ba7448f7f26131dc"),
                iv: hex!("c5b60dda3f333b1146e9da7c"),
                ct: hex!("43af49ec1ae3738a20755034d66f80b6ef2d8830a55eb63680a8dff9e0"),
                aad: Vec::new(),
                pt: hex!("5b87141335f2becac1a559e05f"),
            };

            run_encrypt_decrypt::<super::Gcm256>(&test_case);
        }

        #[test]
        fn test_aes_256_aad() {
            let test_case = TestCase {
                key: hex!("aef220035cbb9e47ce605698aa28e3b0ba50b4ffcd473bb8da2017889b38055f"),
                iv: hex!("cde7af095360ea827778761d"),
                ct: hex!("bb1cdf25717445e5a77444d488387aeee72340deabc1589125e9e4a2755512c7"),
                aad: hex!("f269837306abbcee2da1722f28be35163e3d8567"),
                pt: hex!("9775db638e5d964fc9c70b5fe456ec14"),
            };

            run_encrypt_decrypt::<super::Gcm256>(&test_case);
        }
    }
}

pub mod chacha20 {
    use crate::aead::{AeadId, Cipher, CipherError};
    use chacha20poly1305::aead::{Aead, NewAead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    #[derive(Debug, PartialEq)]
    pub struct Poly1305 {
        pub(crate) key: Vec<u8>,
    }

    impl Cipher for Poly1305 {
        const CIPHER_ID: AeadId = AeadId::ChaCha20Poly1305;
        const KEY_LEN: u16 = 32;
        const NONCE_LEN: u16 = 12;
        const TAG_LEN: u16 = 16;

        fn new(key: Vec<u8>) -> Result<Self, CipherError> {
            if key.len() != Self::KEY_LEN as usize {
                Err(CipherError::InvalidKey(key.len()))
            } else {
                Ok(Self { key })
            }
        }

        fn encrypt(&self, data: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CipherError> {
            let key = Key::from_slice(&self.key);
            let cipher = ChaCha20Poly1305::new(key);

            if nonce.len() != Self::NONCE_LEN as usize {
                return Err(CipherError::InvalidNonce(nonce.len()));
            }

            let nonce = Nonce::from_slice(nonce);
            let payload = Payload { msg: data, aad };

            cipher
                .encrypt(&nonce, payload)
                .map_err(CipherError::ChaCha20Error)
        }

        fn decrypt(
            &self,
            nonce: &[u8],
            cipher_text: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, CipherError> {
            let key = Key::from_slice(&self.key);
            let cipher = ChaCha20Poly1305::new(key);
            let payload = Payload {
                msg: cipher_text,
                aad,
            };
            let nonce = Nonce::from_slice(nonce);

            cipher
                .decrypt(&nonce, payload)
                .map_err(CipherError::ChaCha20Error)
        }
    }

    #[cfg(test)]
    mod test {
        use super::Poly1305;
        use crate::aead::test::{run_encrypt_decrypt, TestCase};
        use crate::aead::Cipher;

        #[test]
        fn test_invalid_key() {
            let too_short: Vec<u8> = vec![0; 10];
            let too_long: Vec<u8> = vec![0; 17];

            assert_eq!(Poly1305::new(too_long).is_err(), true);
            assert_eq!(Poly1305::new(too_short).is_err(), true);
        }

        #[test]
        fn test_no_aad() {
            let test_case = TestCase {
                key: hex!("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
                iv: hex!("000000000102030405060708"),
                ct: hex!(
                    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24\
                          c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf33\
                          2f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855979\
                          7a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b916\
                          6c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf453\
                          4d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb231\
                          6053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d\
                          91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4\
                          022b02709b6e3570b1acaaf1f24f2a644f01acd12b"
                ),
                aad: Vec::new(),
                pt: hex!(
                    "496e7465726e65742d4472616674732061726520647261667420646f63756d656\
                e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320\
                616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6\
                c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20\
                497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447\
                261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465\
                207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726\
                573732e2fe2809d"
                ),
            };

            run_encrypt_decrypt::<super::Poly1305>(&test_case);
        }

        #[test]
        fn test_aad() {
            let test_case = TestCase {
                key: hex!("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
                iv: hex!("000000000102030405060708"),
                ct: hex!(
                    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24\
                          c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf33\
                          2f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855979\
                          7a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b916\
                          6c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf453\
                          4d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb231\
                          6053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d\
                          91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4\
                          022b02709beead9d67890cbb22392336fea1851f38"
                ),
                aad: hex!("f33388860000000000004e91"),
                pt: hex!(
                    "496e7465726e65742d4472616674732061726520647261667420646f63756d656\
                e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320\
                616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6\
                c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20\
                497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447\
                261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465\
                207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726\
                573732e2fe2809d"
                ),
            };

            run_encrypt_decrypt::<super::Poly1305>(&test_case);
        }
    }
}

#[derive(IntoPrimitive, TryFromPrimitive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum AeadId {
    Aes128Gcm = 0x0001,
    Aes256Gcm = 0x0002,
    ChaCha20Poly1305 = 0x0003,
    Unknown = 0xFFFF,
    #[cfg(test)]
    Test = 0x0000,
}

impl AeadId {
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[cfg(test)]
mod test {
    use crate::aead::Cipher;

    pub struct TestCase {
        pub key: Vec<u8>,
        pub iv: Vec<u8>,
        pub ct: Vec<u8>,
        pub aad: Vec<u8>,
        pub pt: Vec<u8>,
    }

    pub fn run_encrypt_decrypt<CT: Cipher>(case: &TestCase) {
        let cipher = CT::new(case.key.clone()).expect("failed to create cipher");

        let cipher_text = cipher
            .encrypt(&case.pt, &case.aad, &case.iv)
            .expect("failed to cipher");

        assert_eq!(cipher_text, case.ct);

        let plaintext = cipher
            .decrypt(&case.iv, &cipher_text, &case.aad)
            .expect("failed to decrypt");

        assert_eq!(plaintext, case.pt);

        // Test for handling a ciphertext with a bad tag as well as incorrect aad
        assert_eq!(
            cipher
                .decrypt(&case.iv, &vec![0; case.ct.len()], &case.aad)
                .is_err(),
            true
        );

        assert_eq!(
            cipher.decrypt(&case.iv, &case.ct, &vec![0; 10]).is_err(),
            true
        );
    }
}

#[cfg(test)]
pub mod test_util {
    use super::{AeadId, Cipher, CipherError};
    use core::fmt;
    use mockall::mock;
    use std::fmt::{Debug, Formatter};

    mock! {
        pub TestCipher {}

        impl Cipher for TestCipher {
            const CIPHER_ID: AeadId = AeadId::Test;
            const KEY_LEN: u16 = 0;
            const NONCE_LEN: u16 = 0;
            const TAG_LEN: u16 = 0;

            fn new(key: Vec<u8>) -> Result<Self, CipherError>;

            fn encrypt(&self,
                       data: &[u8],
                       aad: &[u8],
                       nonce: &[u8]) -> Result<Vec<u8>, CipherError>;

            fn decrypt(&self,
                       nonce: &[u8],
                       cipher_text: &[u8],
                       aad: &[u8]) -> Result<Vec<u8>, CipherError>;
        }
    }

    impl PartialEq for MockTestCipher {
        fn eq(&self, _other: &Self) -> bool {
            true
        }
    }

    impl Debug for MockTestCipher {
        fn fmt(&self, _f: &mut Formatter<'_>) -> fmt::Result {
            unimplemented!()
        }
    }
}
