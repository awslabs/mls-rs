use std::ops::Deref;

use aws_mls_core::{crypto::CipherSuiteProvider, psk::Psk};
use tls_codec::Serialize;
use zeroize::Zeroize;

use crate::group::key_schedule::kdf_expand_with_label;

use super::{PSKLabel, PreSharedKeyID, PskError};

pub struct PskSecretInput {
    pub id: PreSharedKeyID,
    pub psk: Psk,
}

#[derive(Debug, PartialEq, Eq, Clone, Zeroize)]
pub(crate) struct PskSecret(Vec<u8>);

impl From<Vec<u8>> for PskSecret {
    fn from(value: Vec<u8>) -> Self {
        PskSecret(value)
    }
}

impl Deref for PskSecret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PskSecret {
    pub(crate) fn new<P: CipherSuiteProvider>(provider: &P) -> PskSecret {
        PskSecret(vec![0u8; provider.kdf_extract_size()])
    }

    pub(crate) fn calculate<P: CipherSuiteProvider>(
        input: &[PskSecretInput],
        cipher_suite_provider: &P,
    ) -> Result<PskSecret, PskError> {
        let len = u16::try_from(input.len()).map_err(|_| PskError::TooManyPskIds(input.len()))?;

        input.iter().enumerate().try_fold(
            PskSecret::new(cipher_suite_provider),
            |psk_secret, (index, psk_secret_input)| {
                let index = index as u16;

                let label = PSKLabel {
                    id: &psk_secret_input.id,
                    index,
                    count: len,
                };

                let psk_extracted = cipher_suite_provider
                    .kdf_extract(
                        &vec![0; cipher_suite_provider.kdf_extract_size()],
                        &psk_secret_input.psk,
                    )
                    .map(PskSecret)
                    .map_err(|e| PskError::CipherSuiteProviderError(e.into()))?;

                let psk_input = kdf_expand_with_label(
                    cipher_suite_provider,
                    &psk_extracted,
                    "derived psk",
                    &label.tls_serialize_detached()?,
                    None,
                )
                .map(PskSecret)
                .map_err(|e| PskError::KeyScheduleError(e.into()))?;

                cipher_suite_provider
                    .kdf_extract(&psk_input, &psk_secret)
                    .map(PskSecret)
                    .map_err(|e| PskError::CipherSuiteProviderError(e.into()))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use aws_mls_core::{
        crypto::{CipherSuite, CipherSuiteProvider},
        psk::ExternalPskId,
    };
    use serde::{Deserialize, Serialize};

    use crate::{
        provider::crypto::test_utils::{
            test_cipher_suite_provider, try_test_cipher_suite_provider,
        },
        psk::{
            test_utils::{make_external_psk_id, make_nonce},
            JustPreSharedKeyID, PreSharedKeyID, PskNonce,
        },
    };

    use super::{PskSecret, PskSecretInput};

    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    struct PskInfo {
        #[serde(with = "hex::serde")]
        id: Vec<u8>,
        #[serde(with = "hex::serde")]
        psk: Vec<u8>,
        #[serde(with = "hex::serde")]
        nonce: Vec<u8>,
    }

    impl From<PskInfo> for PskSecretInput {
        fn from(info: PskInfo) -> Self {
            let id = PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(ExternalPskId(info.id)),
                psk_nonce: PskNonce(info.nonce),
            };

            PskSecretInput {
                id,
                psk: info.psk.into(),
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
                    let psk_secret = Self::compute_psk_secret(&provider, psks.clone());
                    TestScenario {
                        cipher_suite: cs as u16,
                        psks: psks.to_vec(),
                        psk_secret: psk_secret.to_vec(),
                    }
                })
                .collect()
        }

        fn load() -> Vec<TestScenario> {
            load_test_cases!(psk_secret, TestScenario::generate())
        }

        fn compute_psk_secret<P: CipherSuiteProvider>(
            provider: &P,
            psks: Vec<PskInfo>,
        ) -> PskSecret {
            let input = psks
                .into_iter()
                .map(PskSecretInput::from)
                .collect::<Vec<_>>();

            PskSecret::calculate(&input, provider).unwrap()
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
                            != TestScenario::compute_psk_secret(&provider, scenario.psks.clone())
                                .to_vec()
                    } else {
                        false
                    }
                }),
            None
        );
    }
}
