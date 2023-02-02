use aws_mls_core::crypto::{CipherSuiteProvider, HpkeCiphertext, HpkePublicKey, HpkeSecretKey};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsSerialize, TlsSize};

#[derive(Debug, Clone, TlsSize, TlsSerialize)]
struct EncryptContext<'a> {
    #[tls_codec(with = "crate::tls::ByteVec")]
    label: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    context: &'a [u8],
}

impl<'a> EncryptContext<'a> {
    pub fn new(label: &str, context: &'a [u8]) -> Self {
        Self {
            label: format!("MLS 1.0 {label}").into_bytes(),
            context,
        }
    }
}

#[derive(Debug, Error)]
pub enum HpkeEncryptionError {
    #[error(transparent)]
    TlsSerializationError(#[from] tls_codec::Error),
    #[error("internal hpke error: {0:?}")]
    InternalHpkeError(#[source] Box<dyn std::error::Error + Send + Sync>),
}

pub(crate) trait HpkeEncryptable: Serialize + Deserialize + Sized {
    const ENCRYPT_LABEL: &'static str;

    fn encrypt<P: CipherSuiteProvider>(
        &self,
        cipher_suite_provider: &P,
        public_key: &HpkePublicKey,
        context: &[u8],
    ) -> Result<HpkeCiphertext, HpkeEncryptionError> {
        let context = EncryptContext::new(Self::ENCRYPT_LABEL, context).tls_serialize_detached()?;
        let content = self.tls_serialize_detached()?;

        cipher_suite_provider
            .hpke_seal(public_key, &context, None, &content)
            .map_err(|e| HpkeEncryptionError::InternalHpkeError(e.into()))
    }

    fn decrypt<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
        secret_key: &HpkeSecretKey,
        context: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Self, HpkeEncryptionError> {
        let context = EncryptContext::new(Self::ENCRYPT_LABEL, context).tls_serialize_detached()?;

        let plaintext = cipher_suite_provider
            .hpke_open(ciphertext, secret_key, &context, None)
            .map_err(|e| HpkeEncryptionError::InternalHpkeError(e.into()))?;

        Ok(Self::tls_deserialize(&mut &*plaintext)?)
    }
}
