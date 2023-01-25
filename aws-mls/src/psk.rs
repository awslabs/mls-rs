use crate::{
    group::{
        epoch::EpochSecrets,
        key_schedule::kdf_expand_with_label,
        state_repo::{GroupStateRepository, GroupStateRepositoryError},
        GroupContext,
    },
    provider::{
        crypto::CipherSuiteProvider, group_state::GroupStateStorage,
        key_package::KeyPackageRepository,
    },
    serde_utils::vec_u8_as_base64::VecAsBase64,
};
use serde_with::serde_as;
use std::convert::Infallible;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::{Zeroize, Zeroizing};

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
pub struct ExternalPskId(
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

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct Psk(#[serde_as(as = "VecAsBase64")] Vec<u8>);

impl From<Vec<u8>> for Psk {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Psk {
    pub(crate) fn new_zero(len: usize) -> Self {
        Self(vec![0u8; len])
    }
}

#[derive(Clone, Debug, PartialEq, TlsSerialize, TlsSize)]
struct PSKLabel<'a> {
    id: &'a PreSharedKeyID,
    index: u16,
    count: u16,
}

pub(crate) struct ResumptionPskSearch<'a, R, K>
where
    R: GroupStateStorage,
    K: KeyPackageRepository,
{
    pub group_context: &'a GroupContext,
    pub current_epoch: &'a EpochSecrets,
    pub prior_epochs: &'a GroupStateRepository<R, K>,
}

impl<R: GroupStateStorage, K: KeyPackageRepository> Clone for ResumptionPskSearch<'_, R, K> {
    fn clone(&self) -> Self {
        Self {
            group_context: self.group_context,
            current_epoch: self.current_epoch,
            prior_epochs: self.prior_epochs,
        }
    }
}

impl<R: GroupStateStorage, K: KeyPackageRepository> Copy for ResumptionPskSearch<'_, R, K> {}

impl<R: GroupStateStorage, K: KeyPackageRepository> ResumptionPskSearch<'_, R, K> {
    pub(crate) fn find(&self, epoch_id: u64) -> Result<Option<Psk>, GroupStateRepositoryError> {
        Ok(if epoch_id == self.group_context.epoch {
            Some(self.current_epoch.resumption_secret.clone())
        } else {
            self.prior_epochs
                .get_epoch_owned(epoch_id)?
                .map(|epoch| epoch.secrets.resumption_secret)
        })
    }
}

pub(crate) fn psk_secret<CP, P, PE, R, RE>(
    cipher_suite_provider: &CP,
    mut external_psk_search: P,
    mut resumption_psk_search: R,
    psk_ids: &[PreSharedKeyID],
) -> Result<Psk, PskSecretError>
where
    CP: CipherSuiteProvider,
    P: FnMut(&ExternalPskId) -> Result<Option<Psk>, PE>,
    PE: Into<Box<dyn std::error::Error + Send + Sync>>,
    R: FnMut(u64) -> Result<Option<Psk>, RE>,
    RE: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let len = psk_ids.len();
    let len = u16::try_from(len).map_err(|_| PskSecretError::TooManyPskIds(len))?;

    psk_ids.iter().enumerate().try_fold(
        Psk::new_zero(cipher_suite_provider.kdf_extract_size()),
        |psk_secret, (index, id)| {
            let index = index as u16;

            let psk = match &id.key_id {
                JustPreSharedKeyID::External(id) => external_psk_search(id)
                    .map_err(|e| PskSecretError::SecretStoreError(e.into()))?
                    .ok_or_else(|| PskSecretError::NoPskForId(id.clone()))?,
                JustPreSharedKeyID::Resumption(ResumptionPsk { psk_epoch, .. }) => {
                    resumption_psk_search(*psk_epoch)
                        .map_err(|e| PskSecretError::EpochRepositoryError(e.into()))?
                        .ok_or(PskSecretError::EpochNotFound(*psk_epoch))?
                }
            };

            let label = PSKLabel {
                id,
                index,
                count: len,
            };

            let psk_extracted = cipher_suite_provider
                .kdf_extract(&vec![0; cipher_suite_provider.kdf_extract_size()], &psk.0)
                .map(Zeroizing::new)
                .map_err(|e| PskSecretError::CipherSuiteProviderError(e.into()))?;

            let psk_input = kdf_expand_with_label(
                cipher_suite_provider,
                &psk_extracted,
                "derived psk",
                &label.tls_serialize_detached()?,
                None,
            )
            .map(Zeroizing::new)
            .map_err(|e| PskSecretError::KeyScheduleError(e.into()))?;

            cipher_suite_provider
                .kdf_extract(&psk_input, &psk_secret.0)
                .map(Psk)
                .map_err(|e| PskSecretError::CipherSuiteProviderError(e.into()))
        },
    )
}

#[derive(Clone, Debug, PartialEq, Zeroize, TlsDeserialize, TlsSerialize, TlsSize)]
#[zeroize(drop)]
pub(crate) struct JoinerSecret(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

impl From<Vec<u8>> for JoinerSecret {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

pub(crate) fn get_pre_epoch_secret<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
    psk_secret: &Psk,
    joiner_secret: &JoinerSecret,
) -> Result<Vec<u8>, PskSecretError> {
    cipher_suite_provider
        .kdf_extract(&joiner_secret.0, &psk_secret.0)
        .map_err(|e| PskSecretError::CipherSuiteProviderError(e.into()))
}

#[derive(Debug, Error)]
pub enum PskSecretError {
    #[error("Too many PSK IDs ({0}) to compute PSK secret")]
    TooManyPskIds(usize),
    #[error("No PSK for ID {0:?}")]
    NoPskForId(ExternalPskId),
    #[error(transparent)]
    SecretStoreError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    EpochRepositoryError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Epoch {0} not found")]
    EpochNotFound(u64),
    #[error(transparent)]
    CipherSuiteProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    KeyScheduleError(Box<dyn std::error::Error + Send + Sync + 'static>),
}

pub(crate) trait ExternalPskIdValidator: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn validate(&self, psk_id: &ExternalPskId) -> Result<(), Self::Error>;
}

impl<F> ExternalPskIdValidator for &F
where
    F: ExternalPskIdValidator + ?Sized,
{
    type Error = F::Error;

    fn validate(&self, psk_id: &ExternalPskId) -> Result<(), Self::Error> {
        (**self).validate(psk_id)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PassThroughPskIdValidator;

impl ExternalPskIdValidator for PassThroughPskIdValidator {
    type Error = Infallible;

    fn validate(&self, _: &ExternalPskId) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod test_utils {
    use super::{JoinerSecret, Psk};

    impl From<JoinerSecret> for Vec<u8> {
        fn from(mut value: JoinerSecret) -> Self {
            std::mem::take(&mut value.0)
        }
    }

    impl From<Psk> for Vec<u8> {
        fn from(mut value: Psk) -> Self {
            std::mem::take(&mut value.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        provider::{
            crypto::{
                test_utils::{
                    test_cipher_suite_provider, try_test_cipher_suite_provider, TestCryptoProvider,
                },
                CipherSuiteProvider,
            },
            psk::{InMemoryPskStore, PskStore},
        },
        psk::{
            psk_secret, ExternalPskId, JustPreSharedKeyID, PreSharedKeyID, PskNonce, PskSecretError,
        },
    };
    use assert_matches::assert_matches;
    use serde::{Deserialize, Serialize};
    use std::{convert::Infallible, iter};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    fn make_external_psk_id<P: CipherSuiteProvider>(cipher_suite_provider: &P) -> ExternalPskId {
        ExternalPskId(
            cipher_suite_provider
                .random_bytes_vec(cipher_suite_provider.kdf_extract_size())
                .unwrap(),
        )
    }

    fn make_nonce(cipher_suite: CipherSuite) -> PskNonce {
        PskNonce::random(&test_cipher_suite_provider(cipher_suite)).unwrap()
    }

    fn wrap_external_psk_id(cipher_suite: CipherSuite, id: ExternalPskId) -> PreSharedKeyID {
        PreSharedKeyID {
            key_id: JustPreSharedKeyID::External(id),
            psk_nonce: make_nonce(cipher_suite),
        }
    }

    #[test]
    fn unknown_id_leads_to_error() {
        let expected_id = make_external_psk_id(&test_cipher_suite_provider(TEST_CIPHER_SUITE));
        let res = psk_secret(
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
            |_| Ok::<_, Infallible>(None),
            |_| Ok::<_, Infallible>(None),
            &[wrap_external_psk_id(TEST_CIPHER_SUITE, expected_id.clone())],
        );
        assert_matches!(res, Err(PskSecretError::NoPskForId(actual_id)) if actual_id == expected_id);
    }

    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    struct PskInfo {
        #[serde(with = "hex::serde")]
        id: Vec<u8>,
        #[serde(with = "hex::serde")]
        psk: Vec<u8>,
        #[serde(with = "hex::serde")]
        nonce: Vec<u8>,
    }

    impl From<PskInfo> for PreSharedKeyID {
        fn from(id: PskInfo) -> Self {
            PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(ExternalPskId(id.id)),
                psk_nonce: PskNonce(id.nonce),
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    struct TestScenario {
        cipher_suite: u16,
        psks: Vec<PskInfo>,
        #[serde(with = "hex::serde")]
        psk_secret: Vec<u8>,
    }

    impl TestScenario {
        fn make_psk_list<CS: CipherSuiteProvider>(cs: &CS, n: usize) -> Vec<PskInfo> {
            iter::repeat_with(|| PskInfo {
                id: make_external_psk_id(cs).0,
                psk: cs.random_bytes_vec(cs.kdf_extract_size()).unwrap(),
                nonce: make_nonce(cs.cipher_suite()).0,
            })
            .take(n)
            .collect::<Vec<_>>()
        }

        fn generate() -> Vec<TestScenario> {
            CipherSuite::all()
                .flat_map(|cs| (1..=10).map(move |n| (cs, n)))
                .map(|(cs, n)| {
                    let provider = test_cipher_suite_provider(cs);
                    let psks = Self::make_psk_list(&provider, n);
                    let psk_secret = Self::compute_psk_secret(&provider, &psks);
                    TestScenario {
                        cipher_suite: cs as u16,
                        psks: psks.to_vec(),
                        psk_secret,
                    }
                })
                .collect()
        }

        fn load() -> Vec<TestScenario> {
            load_test_cases!(psk_secret, TestScenario::generate())
        }

        fn compute_psk_secret<P: CipherSuiteProvider>(provider: &P, psks: &[PskInfo]) -> Vec<u8> {
            let secret_store = psks
                .iter()
                .fold(InMemoryPskStore::default(), |mut store, psk| {
                    store.insert(ExternalPskId(psk.id.clone()), psk.psk.clone().into());
                    store
                });

            let ids = psks
                .iter()
                .cloned()
                .map(PreSharedKeyID::from)
                .collect::<Vec<_>>();

            psk_secret(
                provider,
                |id| PskStore::get(&secret_store, id),
                |_| Ok::<_, Infallible>(None),
                &ids,
            )
            .unwrap()
            .0
            .clone()
        }
    }

    #[test]
    fn expected_psk_secret_is_produced() {
        assert_eq!(
            TestScenario::load()
                .into_iter()
                .enumerate()
                .map(|(i, scenario)| (format!("Scenario #{i}"), scenario))
                .find(|(_, scenario)| {
                    if let Some(provider) = try_test_cipher_suite_provider(scenario.cipher_suite) {
                        scenario.psk_secret
                            != TestScenario::compute_psk_secret(&provider, &scenario.psks)
                    } else {
                        false
                    }
                }),
            None
        );
    }

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
