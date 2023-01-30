use crate::{
    group::state_repo::GroupStateRepositoryError, provider::crypto::CipherSuiteProvider,
    serde_utils::vec_u8_as_base64::VecAsBase64,
};
use async_trait::async_trait;
use serde_with::serde_as;
use std::convert::Infallible;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

pub(crate) mod resolver;
pub(crate) mod secret;

pub use aws_mls_core::psk::{ExternalPskId, Psk};

#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PreSharedKeyID {
    pub key_id: JustPreSharedKeyID,
    pub psk_nonce: PskNonce,
}

#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum JustPreSharedKeyID {
    #[tls_codec(discriminant = 1)]
    External(ExternalPskId),
    Resumption(ResumptionPsk),
}

#[serde_as]
#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PskGroupId(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    pub Vec<u8>,
);

#[serde_as]
#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PskNonce(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    pub Vec<u8>,
);

impl PskNonce {
    pub fn random<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
    ) -> Result<Self, <P as CipherSuiteProvider>::Error> {
        Ok(Self(cipher_suite_provider.random_bytes_vec(
            cipher_suite_provider.kdf_extract_size(),
        )?))
    }
}

#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ResumptionPsk {
    pub usage: ResumptionPSKUsage,
    pub psk_group_id: PskGroupId,
    pub psk_epoch: u64,
}

#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum ResumptionPSKUsage {
    Application = 1,
    Reinit,
    Branch,
}

#[derive(Clone, Debug, PartialEq, TlsSerialize, TlsSize)]
struct PSKLabel<'a> {
    id: &'a PreSharedKeyID,
    index: u16,
    count: u16,
}

#[derive(Debug, Error)]
pub enum PskError {
    #[error("Too many PSK IDs ({0}) to compute PSK secret")]
    TooManyPskIds(usize),
    #[error("No PSK for ID {0:?}")]
    NoPskForId(ExternalPskId),
    #[error(transparent)]
    PskStoreError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    GroupStateRepositoryError(#[from] GroupStateRepositoryError),
    #[error("Epoch {0} not found")]
    EpochNotFound(u64),
    #[error(transparent)]
    CipherSuiteProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    KeyScheduleError(Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[async_trait]
pub(crate) trait ExternalPskIdValidator: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn validate(&self, psk_id: &ExternalPskId) -> Result<(), Self::Error>;
}

#[async_trait]
impl<F> ExternalPskIdValidator for &F
where
    F: ExternalPskIdValidator + ?Sized,
{
    type Error = F::Error;

    async fn validate(&self, psk_id: &ExternalPskId) -> Result<(), Self::Error> {
        (**self).validate(psk_id).await
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PassThroughPskIdValidator;

#[async_trait]
impl ExternalPskIdValidator for PassThroughPskIdValidator {
    type Error = Infallible;

    async fn validate(&self, _: &ExternalPskId) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::provider::crypto::test_utils::test_cipher_suite_provider;

    use super::PskNonce;
    use aws_mls_core::{
        crypto::{CipherSuite, CipherSuiteProvider},
        psk::ExternalPskId,
    };

    pub(crate) fn make_external_psk_id<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
    ) -> ExternalPskId {
        ExternalPskId(
            cipher_suite_provider
                .random_bytes_vec(cipher_suite_provider.kdf_extract_size())
                .unwrap(),
        )
    }

    pub(crate) fn make_nonce(cipher_suite: CipherSuite) -> PskNonce {
        PskNonce::random(&test_cipher_suite_provider(cipher_suite)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::provider::crypto::test_utils::TestCryptoProvider;
    use std::iter;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::test_utils::make_nonce;

    #[test]
    fn random_generation_of_nonces_is_random() {
        let good = TestCryptoProvider::all_supported_cipher_suites()
            .into_iter()
            .all(|cipher_suite| {
                let nonce = make_nonce(cipher_suite);
                iter::repeat_with(|| make_nonce(cipher_suite))
                    .take(1000)
                    .all(|other| other != nonce)
            });

        assert!(good);
    }
}
