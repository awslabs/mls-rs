use aws_mls_core::crypto::{HpkeCiphertext, HpkeContext, HpkePublicKey, HpkeSecretKey};
use thiserror::Error;

use crate::OpensslCipherSuite;

#[derive(Debug, Error)]
pub enum HpkeError {
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
}

impl OpensslCipherSuite {
    pub fn hpke_seal(
        &self,
        _remote_key: &HpkePublicKey,
        _info: &[u8],
        _aad: Option<&[u8]>,
        _pt: &[u8],
    ) -> Result<HpkeCiphertext, HpkeError> {
        Ok(HpkeCiphertext {
            kem_output: vec![],
            ciphertext: vec![],
        })
    }

    pub fn hpke_open(
        &self,
        _ciphertext: &HpkeCiphertext,
        _local_secret: &HpkeSecretKey,
        _info: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, HpkeError> {
        Ok(vec![])
    }

    pub fn hpke_setup_r(
        &self,
        _enc: &[u8],
        _local_secret: &HpkeSecretKey,
        _info: &[u8],
    ) -> Result<OpensslHpkeContext, HpkeError> {
        Ok(Default::default())
    }

    pub fn hpke_setup_s(
        &self,
        _remote_key: &HpkePublicKey,
        _info: &[u8],
    ) -> Result<(Vec<u8>, OpensslHpkeContext), HpkeError> {
        Ok(Default::default())
    }
}

#[derive(Clone, Debug, Default)]
pub struct OpensslHpkeContext;

impl HpkeContext for OpensslHpkeContext {
    type Error = HpkeError;

    fn open(&mut self, _aad: Option<&[u8]>, _ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![])
    }

    fn seal(&mut self, _aad: Option<&[u8]>, _data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![])
    }

    fn export(&self, _exporter_context: &[u8], _len: usize) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![])
    }
}
