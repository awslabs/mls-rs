use aws_mls_crypto_traits::KdfType;

use alloc::vec::Vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HpkeKdf<K: KdfType> {
    suite_id: Vec<u8>,
    kdf: K,
}

impl<K: KdfType> HpkeKdf<K> {
    pub fn new(suite_id: Vec<u8>, kdf: K) -> Self {
        Self { suite_id, kdf }
    }

    pub fn extract_size(&self) -> usize {
        self.kdf.extract_size()
    }

    /* draft-irtf-cfrg-hpke-09 section 4 Cryptographic Dependencies */
    pub fn labeled_extract(
        &self,
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>, <K as KdfType>::Error> {
        self.kdf.extract(
            salt,
            &[b"HPKE-v1" as &[u8], &self.suite_id, label, ikm].concat(),
        )
    }

    /* draft-irtf-cfrg-hpke-09 section 4 Cryptographic Dependencies */
    pub fn labeled_expand(
        &self,
        key: &[u8],
        label: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, <K as KdfType>::Error> {
        let labeled_info = [
            &(len as u16).to_be_bytes() as &[u8],
            b"HPKE-v1",
            &self.suite_id,
            label,
            info,
        ]
        .concat();

        self.kdf.expand(key, &labeled_info, len)
    }

    /* draft-irtf-cfrg-hpke-09 section 4.1 DH-Based KEM */
    pub fn labeled_extract_then_expand(
        &self,
        ikm: &[u8],
        ctx: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, <K as KdfType>::Error> {
        let eae_prk = self.labeled_extract(&[], b"eae_prk", ikm)?;
        self.labeled_expand(&eae_prk, b"shared_secret", ctx, len)
    }
}
