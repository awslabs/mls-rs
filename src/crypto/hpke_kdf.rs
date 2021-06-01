use crate::crypto::kdf::{HkdfSha256, HkdfSha512, Kdf, KdfError};

pub trait HpkeKdf: Kdf {
    /* draft-irtf-cfrg-hpke-07 section 4 Cryptographic Dependencies */
    fn labeled_extract(
        suite_id: &[u8],
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>, KdfError> {
        Self::extract(salt, &[b"HPKE-v1", suite_id, label, ikm].concat())
    }

    /* draft-irtf-cfrg-hpke-07 section 4 Cryptographic Dependencies */
    fn labeled_expand(
        suite_id: &[u8],
        key: &[u8],
        label: &[u8],
        info: &[u8],
        out_len: u16,
    ) -> Result<Vec<u8>, KdfError> {
        let labeled_info = [
            &out_len.to_be_bytes() as &[u8],
            b"HPKE-v1",
            suite_id,
            label,
            info,
        ]
        .concat();
        Self::expand(key, &labeled_info, out_len)
    }

    /* draft-irtf-cfrg-hpke-07 section 4.1 DH-Based KEM */
    fn labeled_extract_and_expand(
        suite_id: &[u8],
        ikm: &[u8],
        ctx: &[u8],
        out_len: u16,
    ) -> Result<Vec<u8>, KdfError> {
        let eae_prk = Self::labeled_extract(&suite_id, &[], b"eae_prk", ikm)?;

        Self::labeled_expand(&suite_id, &eae_prk, b"shared_secret", ctx, out_len)
    }
}

impl HpkeKdf for HkdfSha256 {}
impl HpkeKdf for HkdfSha512 {}

#[cfg(test)]
pub mod test_util {
    use crate::crypto::hpke_kdf::HpkeKdf;
    use crate::crypto::kdf::{Kdf, KdfError, KdfId};
    use mockall::mock;

    mock! {
        pub TestHpkeKdf {}

        impl Kdf for TestHpkeKdf {
            const KDF_ID: KdfId = KdfId::Test;
            const EXTRACT_SIZE: u16 = 0;

            // RFC 5869 Extract-and-Expand HKDF
            fn extract(salt: &[u8], key: &[u8]) -> Result<Vec<u8>, KdfError>;

            // RFC 5869 Extract-and-Expand HKDF
            fn expand(key: &[u8], info: &[u8], out_len: u16) -> Result<Vec<u8>, KdfError>;
        }

        impl HpkeKdf for TestHpkeKdf {}
    }
}
