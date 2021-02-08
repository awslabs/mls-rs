use openssl::error::ErrorStack;
use thiserror::Error;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

pub trait Kdf {
    const KDF_ID: u16;
    const EXTRACT_SIZE: u16;

    // RFC 5869 Extract-and-Expand HKDF
    fn extract(salt: &[u8], key: &[u8]) -> Result<Vec<u8>, KdfError>;

    // RFC 5869 Extract-and-Expand HKDF
    fn expand(key: &[u8], info: &[u8], out_len: u16) -> Result<Vec<u8>, KdfError>;
}

pub trait LabeledKdf : Kdf {
    /* draft-irtf-cfrg-hpke-07 section 4 Cryptographic Dependencies */
    fn labeled_extract(suite_id: &[u8], salt: &[u8],
                       label: &[u8], ikm: &[u8]) -> Result<Vec<u8>, KdfError> {
        Self::extract(salt, &[b"HPKE-v1", suite_id, label, ikm].concat())
    }

    /* draft-irtf-cfrg-hpke-07 section 4 Cryptographic Dependencies */
    fn labeled_expand(suite_id: &[u8], key: &[u8],
                      label: &[u8], info: &[u8], out_len: u16) -> Result<Vec<u8>, KdfError> {
        let labeled_info = [&out_len.to_be_bytes() as &[u8], b"HPKE-v1", suite_id, label, info]
            .concat();
        Self::expand(key, &labeled_info, out_len)
    }

    /* draft-irtf-cfrg-hpke-07 section 4.1 DH-Based KEM */
    fn labeled_extract_and_expand(suite_id: &[u8], ikm: &[u8],
                                  ctx: &[u8], out_len: u16) -> Result<Vec<u8>, KdfError> {
        let eae_prk = Self::labeled_extract(&suite_id,
                                            &[],
                                            b"eae_prk",
                                            ikm)?;

        Self::labeled_expand(&suite_id,
                             &eae_prk,
                             b"shared_secret",
                             ctx,
                             out_len)
    }
}

#[derive(Error, Debug)]
pub enum KdfError {
    #[error("Openssl error: {0}")]
    OpenSSLError(#[from] ErrorStack),
}

/* Based on rust-crypto https://github.com/DaGenix/rust-crypto/blob/master/src/hkdf.rs
   The OpenSSL crate does not expose HKDF yet, when it does we can use that
*/
#[macro_use]
mod ossl {
    use openssl::hash::MessageDigest;
    use crate::kdf::{KdfError};
    use openssl::sign::Signer;
    use openssl::pkey::PKey;
    use core::ptr;

    /* Taken from rust-crypto
       https://github.com/DaGenix/rust-crypto/blob/cc1a5fde1ce957bd1a8a2e30169443cdb4780111/src/hkdf.rs#L44
     */
    #[inline]
    fn copy_memory(src: &[u8], dst: &mut [u8]) {
        assert!(dst.len() >= src.len());
        unsafe {
            let srcp = src.as_ptr();
            let dstp = dst.as_mut_ptr();
            ptr::copy_nonoverlapping(srcp, dstp, src.len());
        }
    }

    pub fn extract(digest: MessageDigest, salt: &[u8], key: &[u8]) -> Result<Vec<u8>, KdfError> {
        // In RFC 5869 the key and salt values are swapped as they go into HMAC
        let ossl_key = PKey::hmac(salt)?;
        let mut signer = Signer::new(digest, &ossl_key)?;
        signer.sign_oneshot_to_vec(key).map_err(|e| e.into())
    }

    /* Modified version of the HKDF logic from rust-crypto
       https://github.com/DaGenix/rust-crypto/blob/cc1a5fde1ce957bd1a8a2e30169443cdb4780111/src/hkdf.rs#L44
     */
    pub fn expand(digest: MessageDigest, key: &[u8], info: &[u8], out_len: u16) -> Result<Vec<u8>, KdfError> {
        let key = PKey::hmac(key)?;
        let ossl_digest = digest.clone().into();
        let mut mac = Signer::new(ossl_digest, &key)?;

        let os = digest.size();
        let mut t: Vec<u8> = vec![0; digest.size()];
        let mut n: u8 = 0;

        let mut okm: Vec<u8> = vec![0; out_len as usize];

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

    macro_rules! impl_hkdf {
        ($name:ident, $digest:expr, $kdf_id:expr, $extract_size:expr) => {
            pub struct $name;

            impl Kdf for $name {
                const KDF_ID: u16 = $kdf_id;
                const EXTRACT_SIZE: u16 = $extract_size;

                fn extract(salt: &[u8], key: &[u8]) -> Result<Vec<u8>, KdfError> {
                    ossl::extract($digest, salt, key)
                }

                fn expand(key: &[u8],
                          info: &[u8],
                          out_len: u16) -> Result<Vec<u8>, KdfError> {
                    ossl::expand($digest, key, info, out_len)
                }
            }
        };
    }
}

impl_hkdf!(HkdfSha256, openssl::hash::MessageDigest::sha256(),KdfId::HkdfSha256 as u16, 32);
impl_hkdf!(HkdfSha512, openssl::hash::MessageDigest::sha512(),KdfId::HkdfSha512 as u16, 64);

impl LabeledKdf for HkdfSha256 {}
impl LabeledKdf for HkdfSha512 {}

#[derive(FromPrimitive, Debug, PartialEq)]
pub enum KdfId {
    HkdfSha256 = 0x0001,
    HkdfSha384 = 0x0002, // Unsupported
    HkdfSha512 = 0x0003
}

impl KdfId {
    pub fn is_supported(&self) -> bool {
        match self {
            Self::HkdfSha384 => false,
            _ => true
        }
    }

    pub fn from_u16(val: u16) -> Option<KdfId> {
        FromPrimitive::from_u16(val)
    }
}

#[cfg(test)]
mod tests {
    use crate::kdf::{HkdfSha256, Kdf, HkdfSha512};

    struct TestCase {
        ikm: Vec<u8>,
        salt: Vec<u8>,
        info: Vec<u8>,
        len: u16,
        prk: Vec<u8>,
        okm: Vec<u8>
    }

    fn run_test_case<KDF: Kdf>(case: TestCase) {
        // Extract phase
        let extracted = KDF::extract(&case.salt, &case.ikm)
            .expect("HKDF extract failed");

        assert_eq!(extracted, case.prk);

        // Expand phase
        let expanded = KDF::expand(
            &case.prk,
            &case.info,
            case.len
        ).expect("HKDF expand failed");

        assert_eq!(expanded, case.okm);
    }

    #[test]
    fn test_basic_sha256() {
        // RFC 5869 Appendix A. Test Case 1
        let case = TestCase {
            ikm: hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            salt: hex!("000102030405060708090a0b0c"),
            info: hex!("f0f1f2f3f4f5f6f7f8f9"),
            len: 42,
            prk: hex!("077709362c2e32df0ddc3f0dc47bb\
                       a6390b6c73bb50f9c3122ec844ad7c2b3e5"),
            okm: hex!("3cb25f25faacd57a90434f64d0362f\
                       2a2d2d0a90cf1a5a4c5db02d56ecc4c5\
                       bf34007208d5b887185865")
        };

        run_test_case::<HkdfSha256>(case)
    }

    #[test]
    fn test_longer_values_sha256() {
        // RFC 5869 Appendix A. Test Case 2
        let case = TestCase {
            ikm: hex!("000102030405060708090a0b0c0d0e0f\
                       101112131415161718191a1b1c1d1e1f\
                       202122232425262728292a2b2c2d2e2f\
                       303132333435363738393a3b3c3d3e3f\
                       404142434445464748494a4b4c4d4e4f"),
            salt: hex!("606162636465666768696a6b6c6d6e6f\
                        707172737475767778797a7b7c7d7e7f\
                        808182838485868788898a8b8c8d8e8f\
                        909192939495969798999a9b9c9d9e9f\
                        a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
            info: hex!("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
                        c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                        d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
                        e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                        f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            len: 82,
            prk: hex!("06a6b88c5853361a06104c9ceb35b45c\
                       ef760014904671014a193f40c15fc244"),
            okm: hex!("b11e398dc80327a1c8e7f78c596a4934\
                       4f012eda2d4efad8a050cc4c19afa97c\
                       59045a99cac7827271cb41c65e590e09\
                       da3275600c2f09b8367793a9aca3db71\
                       cc30c58179ec3e87c14c01d5c1f3434f\
                       1d87")
        };

        run_test_case::<HkdfSha256>(case)
    }

    #[test]
    fn test_zero_length_salt_info() {
        // RFC 5869 Appendix A. Test Case 3
        let case = TestCase {
            ikm: hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            salt: Vec::new(),
            info: Vec::new(),
            len: 42,
            prk: hex!("19ef24a32c717b167f33a91d6f648bdf\
                       96596776afdb6377ac434c1c293ccb04"),
            okm: hex!("8da4e775a563c18f715f802a063c5a31\
                       b8a11f5c5ee1879ec3454e5f3c738d2d\
                       9d201395faa4b61a96c8")
        };

        run_test_case::<HkdfSha256>(case)
    }

    #[test]
    fn test_basic_sha512() {
        let case = TestCase {
            ikm: hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            salt: Vec::new(),
            info: Vec::new(),
            len: 82,
            prk: hex!("fd200c4987ac491313bd4a2a13287121\
                       247239e11c9ef82802044b66ef357e5b\
                       194498d0682611382348572a7b1611de\
                       54764094286320578a863f36562b0df6"),
            okm: hex!("f5fa02b18298a72a8c23898a8703472c\
                       6eb179dc204c03425c970e3b164bf90f\
                       ff22d04836d0e2343bacc4e7cb6045fa\
                       aa698e0e3b3eb91331306def1db8319e\
                       8a699b5ee45ab993847dc4df75bde023\
                       692c")
        };

        run_test_case::<HkdfSha512>(case)
    }

}