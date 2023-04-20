use crate::{client::MlsError, serde_utils::vec_u8_as_base64::VecAsBase64, CipherSuiteProvider};
use alloc::{boxed::Box, vec::Vec};
use async_trait::async_trait;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use core::convert::Infallible;
use serde_with::serde_as;
#[cfg(feature = "std")]
use std::error::Error;

#[cfg(not(feature = "std"))]
use core::error::Error;

pub(crate) mod resolver;
pub(crate) mod secret;

pub use aws_mls_core::psk::{ExternalPskId, PreSharedKey};

#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    PartialOrd,
    Ord,
    MlsSize,
    MlsEncode,
    MlsDecode,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PreSharedKeyID {
    pub key_id: JustPreSharedKeyID,
    pub psk_nonce: PskNonce,
}

impl PreSharedKeyID {
    pub(crate) fn new<P: CipherSuiteProvider>(
        key_id: JustPreSharedKeyID,
        cs: &P,
    ) -> Result<Self, MlsError> {
        Ok(Self {
            key_id,
            psk_nonce: PskNonce::random(cs).map_err(|e| MlsError::CryptoProviderError(e.into()))?,
        })
    }
}

#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    PartialEq,
    MlsSize,
    MlsEncode,
    MlsDecode,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum JustPreSharedKeyID {
    External(ExternalPskId) = 1u8,
    Resumption(ResumptionPsk) = 2u8,
}

#[serde_as]
#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    PartialEq,
    MlsSize,
    MlsEncode,
    MlsDecode,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PskGroupId(
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
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
    PartialOrd,
    Ord,
    MlsSize,
    MlsEncode,
    MlsDecode,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PskNonce(
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
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
    Ord,
    PartialOrd,
    PartialEq,
    MlsSize,
    MlsEncode,
    MlsDecode,
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
    Ord,
    PartialOrd,
    MlsSize,
    MlsEncode,
    MlsDecode,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum ResumptionPSKUsage {
    Application = 1u8,
    Reinit = 2u8,
    Branch = 3u8,
}

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode)]
struct PSKLabel<'a> {
    id: &'a PreSharedKeyID,
    index: u16,
    count: u16,
}

#[async_trait]
pub(crate) trait ExternalPskIdValidator: Send + Sync {
    type Error: Error + Send + Sync + 'static;

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
    use crate::crypto::test_utils::test_cipher_suite_provider;

    use super::PskNonce;
    use aws_mls_core::{
        crypto::{CipherSuite, CipherSuiteProvider},
        psk::ExternalPskId,
    };

    pub(crate) fn make_external_psk_id<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
    ) -> ExternalPskId {
        ExternalPskId::new(
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
    use crate::crypto::test_utils::TestCryptoProvider;
    use core::iter;

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
