use crate::{
    cipher_suite::CipherSuite,
    client_config::PskStore,
    group::key_schedule::{KeyScheduleKdf, KeyScheduleKdfError},
    EpochRepository,
};
use ferriscrypt::{
    kdf::KdfError,
    rand::{SecureRng, SecureRngError},
};
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
pub struct ExternalPskId(#[tls_codec(with = "crate::tls::ByteVec")] pub Vec<u8>);

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
pub struct PskGroupId(#[tls_codec(with = "crate::tls::ByteVec")] pub Vec<u8>);

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
pub struct PskNonce(#[tls_codec(with = "crate::tls::ByteVec")] pub Vec<u8>);

impl PskNonce {
    pub fn random(cipher_suite: CipherSuite) -> Result<Self, SecureRngError> {
        Ok(Self(SecureRng::gen(
            KeyScheduleKdf::new(cipher_suite.kdf_type()).extract_size(),
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

#[derive(
    Clone,
    Debug,
    PartialEq,
    Zeroize,
    serde::Serialize,
    serde::Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
)]
#[zeroize(drop)]
pub struct Psk(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

impl From<Vec<u8>> for Psk {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Psk {
    pub(crate) fn new_zero(cipher_suite: CipherSuite) -> Self {
        Self(vec![
            0u8;
            KeyScheduleKdf::new(cipher_suite.kdf_type())
                .extract_size()
        ])
    }
}

#[derive(Clone, Debug, PartialEq, TlsSerialize, TlsSize)]
struct PSKLabel<'a> {
    id: &'a PreSharedKeyID,
    index: u16,
    count: u16,
}

pub(crate) fn psk_secret<P, R>(
    cipher_suite: CipherSuite,
    external_psk_search: Option<&P>,
    epoch_search: Option<(&[u8], &R)>,
    psk_ids: &[PreSharedKeyID],
) -> Result<Psk, PskSecretError>
where
    P: PskStore,
    R: EpochRepository,
{
    let len = psk_ids.len();
    let len = u16::try_from(len).map_err(|_| PskSecretError::TooManyPskIds(len))?;
    let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());

    psk_ids
        .iter()
        .enumerate()
        .try_fold(Psk::new_zero(cipher_suite), |psk_secret, (index, id)| {
            let index = index as u16;

            let psk = match &id.key_id {
                JustPreSharedKeyID::External(id) => external_psk_search
                    .ok_or_else(|| PskSecretError::NoPskForId(id.clone()))?
                    .psk(id)
                    .map_err(|e| PskSecretError::SecretStoreError(Box::new(e)))?
                    .ok_or_else(|| PskSecretError::NoPskForId(id.clone()))?,
                JustPreSharedKeyID::Resumption(ResumptionPsk { psk_epoch, .. }) => {
                    let (group_id, epoch_repository) =
                        epoch_search.ok_or(PskSecretError::EpochNotFound(*psk_epoch))?;

                    epoch_repository
                        .get(group_id, *psk_epoch)
                        .map_err(|e| PskSecretError::EpochRepositoryError(e.into()))?
                        .ok_or(PskSecretError::EpochNotFound(*psk_epoch))?
                        .into_inner()
                        .secrets
                        .resumption_secret
                }
            };

            let label = PSKLabel {
                id,
                index,
                count: len,
            };

            let label_bytes = label.tls_serialize_detached()?;
            let psk_extracted = Zeroizing::new(kdf.extract(&vec![0; kdf.extract_size()], &psk.0)?);

            let psk_input = Zeroizing::new(kdf.expand_with_label(
                &psk_extracted,
                "derived psk",
                &label_bytes,
                kdf.extract_size(),
            )?);

            let psk_secret = Psk(kdf.extract(&psk_input, &psk_secret.0)?);

            Ok(psk_secret)
        })
}

#[derive(Clone, Debug, PartialEq, Zeroize, TlsDeserialize, TlsSerialize, TlsSize)]
#[zeroize(drop)]
pub(crate) struct JoinerSecret(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

impl From<Vec<u8>> for JoinerSecret {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

pub(crate) fn get_epoch_secret(
    cipher_suite: CipherSuite,
    psk_secret: &Psk,
    joiner_secret: &JoinerSecret,
) -> Result<Vec<u8>, PskSecretError> {
    let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());
    Ok(kdf.extract(&psk_secret.0, &joiner_secret.0)?)
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
    KdfError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    EpochRepositoryError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Epoch {0} not found")]
    EpochNotFound(u64),
}

impl From<KdfError> for PskSecretError {
    fn from(e: KdfError) -> Self {
        PskSecretError::KdfError(e.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        client_config::InMemoryPskStore,
        psk::{
            psk_secret, ExternalPskId, JustPreSharedKeyID, PreSharedKeyID, PskNonce, PskSecretError,
        },
        InMemoryEpochRepository,
    };
    use assert_matches::assert_matches;
    use ferriscrypt::{kdf::hkdf::Hkdf, rand::SecureRng};
    use serde::{Deserialize, Serialize};
    use std::iter;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    fn digest_size(cipher_suite: CipherSuite) -> usize {
        Hkdf::from(cipher_suite.kdf_type()).extract_size()
    }

    fn make_external_psk_id(cipher_suite: CipherSuite) -> ExternalPskId {
        ExternalPskId(SecureRng::gen(digest_size(cipher_suite)).unwrap())
    }

    fn make_nonce(cipher_suite: CipherSuite) -> PskNonce {
        PskNonce::random(cipher_suite).unwrap()
    }

    fn wrap_external_psk_id(cipher_suite: CipherSuite, id: ExternalPskId) -> PreSharedKeyID {
        PreSharedKeyID {
            key_id: JustPreSharedKeyID::External(id),
            psk_nonce: make_nonce(cipher_suite),
        }
    }

    #[test]
    fn unknown_id_leads_to_error() {
        let expected_id = make_external_psk_id(TEST_CIPHER_SUITE);
        let res = psk_secret(
            TEST_CIPHER_SUITE,
            Some(&InMemoryPskStore::default()),
            None::<(_, &InMemoryEpochRepository)>,
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
        fn generate() -> Vec<TestScenario> {
            let make_psk_list = |cs, n| {
                iter::repeat_with(|| PskInfo {
                    id: make_external_psk_id(cs).0,
                    psk: SecureRng::gen(digest_size(cs)).unwrap(),
                    nonce: make_nonce(cs).0,
                })
                .take(n)
                .collect::<Vec<_>>()
            };

            CipherSuite::all()
                .flat_map(|cs| (1..=10).map(move |n| (cs, n)))
                .map(|(cs, n)| {
                    let psks = make_psk_list(cs, n);
                    let psk_secret = Self::compute_psk_secret(cs, &psks);
                    TestScenario {
                        cipher_suite: cs as u16,
                        psks,
                        psk_secret,
                    }
                })
                .collect()
        }

        fn load() -> Vec<TestScenario> {
            load_test_cases!(psk_secret, TestScenario::generate)
        }

        fn compute_psk_secret(cipher_suite: CipherSuite, psks: &[PskInfo]) -> Vec<u8> {
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
                cipher_suite,
                Some(&secret_store),
                Some((&[], &InMemoryEpochRepository::default())),
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
                    if let Some(cipher_suite) = CipherSuite::from_raw(scenario.cipher_suite) {
                        scenario.psk_secret
                            != TestScenario::compute_psk_secret(cipher_suite, &scenario.psks)
                    } else {
                        false
                    }
                }),
            None
        );
    }

    #[test]
    fn random_generation_of_nonces_is_random() {
        let good = CipherSuite::all().all(|cipher_suite| {
            let nonce = make_nonce(cipher_suite);
            iter::repeat_with(|| make_nonce(cipher_suite))
                .take(1000)
                .all(|other| other != nonce)
        });
        assert!(good);
    }
}
