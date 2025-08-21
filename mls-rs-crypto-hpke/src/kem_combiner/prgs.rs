use alloc::vec::Vec;

use mls_rs_crypto_traits::KdfType;

use crate::kem_combiner::ghp::Prg;

#[derive(Clone)]
pub struct MlsKdfPrg<KDF> {
    pub mls_kdf: KDF,
}

impl<KDF> MlsKdfPrg<KDF> {
    pub fn new(mls_kdf: KDF) -> Self {
        Self { mls_kdf }
    }
}

impl<KDF: KdfType> Prg for MlsKdfPrg<KDF> {
    type Error = <KDF as KdfType>::Error;

    fn eval(&self, key: &[u8], out_len: usize) -> Result<Vec<u8>, Self::Error> {
        self.mls_kdf.expand(key, &[], out_len)
    }
}
