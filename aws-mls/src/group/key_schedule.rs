use crate::group::secret_tree::SecretTreeError;
use crate::group::{GroupContext, MembershipTag, MembershipTagError, SecretTree};
use crate::psk::{get_pre_epoch_secret, JoinerSecret, Psk, PskSecretError};
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::tree_kem::path_secret::{PathSecret, PathSecretError, PathSecretGenerator};
use serde_with::serde_as;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsSerialize, TlsSize};
use zeroize::{Zeroize, Zeroizing};

use crate::provider::crypto::{
    CipherSuiteProvider, HpkeContextR, HpkeContextS, HpkePublicKey, HpkeSecretKey,
};

use super::epoch::{EpochSecrets, SenderDataSecret};
use super::message_signature::MLSAuthenticatedContent;

#[derive(Error, Debug)]
pub enum KeyScheduleError {
    #[error(transparent)]
    SecretTreeError(#[from] SecretTreeError),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    PskSecretError(#[from] PskSecretError),
    #[error("key derivation failure")]
    KeyDerivationFailure,
    #[error(transparent)]
    CipherSuiteProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct KeySchedule {
    exporter_secret: Vec<u8>,
    pub authentication_secret: Vec<u8>,
    external_secret: Vec<u8>,
    membership_key: Vec<u8>,
    init_secret: InitSecret,
}

pub(crate) struct KeyScheduleDerivationResult {
    pub(crate) key_schedule: KeySchedule,
    pub(crate) confirmation_key: Vec<u8>,
    pub(crate) joiner_secret: JoinerSecret,
    pub(crate) epoch_secrets: EpochSecrets,
}

impl KeySchedule {
    pub fn new(init_secret: InitSecret) -> Self {
        Self {
            exporter_secret: vec![],
            authentication_secret: vec![],
            external_secret: vec![],
            membership_key: vec![],
            init_secret,
        }
    }

    pub fn derive_for_external<P: CipherSuiteProvider>(
        &self,
        kem_output: &[u8],
        cipher_suite: &P,
    ) -> Result<KeySchedule, KeyScheduleError> {
        let (secret, _public) = self.get_external_key_pair(cipher_suite)?;
        let init_secret = InitSecret::decode_for_external(cipher_suite, kem_output, &secret)?;
        Ok(KeySchedule::new(init_secret))
    }

    /// Returns the derived epoch as well as the joiner secret required for building welcome
    /// messages
    pub(crate) fn from_key_schedule<P: CipherSuiteProvider>(
        last_key_schedule: &KeySchedule,
        commit_secret: &CommitSecret,
        context: &GroupContext,
        secret_tree_size: u32,
        psk_secret: &Psk,
        cipher_suite_provider: &P,
    ) -> Result<KeyScheduleDerivationResult, KeyScheduleError> {
        let joiner_seed = cipher_suite_provider
            .kdf_extract(&last_key_schedule.init_secret.0, &commit_secret.0)
            .map(Zeroizing::new)
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))?;

        let joiner_secret = kdf_expand_with_label(
            cipher_suite_provider,
            &joiner_seed,
            "joiner",
            &context.tls_serialize_detached()?,
            None,
        )
        .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))?
        .into();

        let key_schedule_result = Self::from_joiner(
            cipher_suite_provider,
            &joiner_secret,
            context,
            secret_tree_size,
            psk_secret,
        )?;

        Ok(KeyScheduleDerivationResult {
            key_schedule: key_schedule_result.key_schedule,
            confirmation_key: key_schedule_result.confirmation_key,
            joiner_secret,
            epoch_secrets: key_schedule_result.epoch_secrets,
        })
    }

    pub(crate) fn from_joiner<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
        joiner_secret: &JoinerSecret,
        context: &GroupContext,
        secret_tree_size: u32,
        psk_secret: &Psk,
    ) -> Result<KeyScheduleDerivationResult, KeyScheduleError> {
        let epoch_seed = get_pre_epoch_secret(cipher_suite_provider, psk_secret, joiner_secret)?;
        let context = context.tls_serialize_detached()?;

        let epoch_secret =
            kdf_expand_with_label(cipher_suite_provider, &epoch_seed, "epoch", &context, None)
                .map(Zeroizing::new)
                .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))?;

        Self::from_epoch_secret(cipher_suite_provider, &epoch_secret, secret_tree_size)
    }

    pub(crate) fn from_random_epoch_secret<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
        secret_tree_size: u32,
    ) -> Result<KeyScheduleDerivationResult, KeyScheduleError> {
        let epoch_secret = cipher_suite_provider
            .random_bytes_vec(cipher_suite_provider.kdf_extract_size())
            .map(Zeroizing::new)
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))?;

        Self::from_epoch_secret(cipher_suite_provider, &epoch_secret, secret_tree_size)
    }

    fn from_epoch_secret<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
        epoch_secret: &[u8],
        secret_tree_size: u32,
    ) -> Result<KeyScheduleDerivationResult, KeyScheduleError> {
        let secrets_producer = SecretsProducer::new(cipher_suite_provider, epoch_secret);

        let epoch_secrets = EpochSecrets {
            resumption_secret: Psk::from(secrets_producer.derive("resumption")?),
            sender_data_secret: SenderDataSecret::from(secrets_producer.derive("sender data")?),
            secret_tree: SecretTree::new(secret_tree_size, secrets_producer.derive("encryption")?),
        };

        let key_schedule = Self {
            exporter_secret: secrets_producer.derive("exporter")?,
            authentication_secret: secrets_producer.derive("authentication")?,
            external_secret: secrets_producer.derive("external")?,
            membership_key: secrets_producer.derive("membership")?,
            init_secret: InitSecret(secrets_producer.derive("init")?),
        };

        Ok(KeyScheduleDerivationResult {
            key_schedule,
            // TODO investigate if it's zeroized
            confirmation_key: secrets_producer.derive("confirm")?,
            joiner_secret: vec![].into(),
            epoch_secrets,
        })
    }

    pub fn export_secret<P: CipherSuiteProvider>(
        &self,
        label: &str,
        context: &[u8],
        len: usize,
        cipher_suite: &P,
    ) -> Result<Vec<u8>, KeyScheduleError> {
        let secret = Zeroizing::new(kdf_derive_secret(
            cipher_suite,
            &self.exporter_secret,
            label,
        )?);

        let context_hash = cipher_suite
            .hash(context)
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))?;

        kdf_expand_with_label(cipher_suite, &secret, "exporter", &context_hash, Some(len))
    }

    pub fn get_membership_tag<P: CipherSuiteProvider>(
        &self,
        content: &MLSAuthenticatedContent,
        context: &GroupContext,
        cipher_suite_provider: &P,
    ) -> Result<MembershipTag, MembershipTagError> {
        MembershipTag::create(
            content,
            context,
            &self.membership_key,
            cipher_suite_provider,
        )
    }

    pub fn get_external_key_pair<P: CipherSuiteProvider>(
        &self,
        cipher_suite: &P,
    ) -> Result<(HpkeSecretKey, HpkePublicKey), KeyScheduleError> {
        cipher_suite
            .kem_derive(&self.external_secret)
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))
    }
}

#[derive(TlsSerialize, TlsSize)]
struct Label<'a> {
    length: u16,
    #[tls_codec(with = "crate::tls::ByteVec")]
    label: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    context: &'a [u8],
}

impl<'a> Label<'a> {
    fn new(length: u16, label: &'a str, context: &'a [u8]) -> Self {
        Self {
            length,
            label: [b"MLS 1.0 ", label.as_bytes()].concat(),
            context,
        }
    }
}

pub(crate) fn kdf_expand_with_label<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
    secret: &[u8],
    label: &str,
    context: &[u8],
    len: Option<usize>,
) -> Result<Vec<u8>, KeyScheduleError> {
    let extract_size = cipher_suite_provider.kdf_extract_size();
    let len = len.unwrap_or(extract_size);
    let label = Label::new(extract_size as u16, label, context);

    cipher_suite_provider
        .kdf_expand(secret, &label.tls_serialize_detached()?, len)
        .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))
}

pub(crate) fn kdf_derive_secret<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
    secret: &[u8],
    label: &str,
) -> Result<Vec<u8>, KeyScheduleError> {
    kdf_expand_with_label(cipher_suite_provider, secret, label, &[], None)
}

struct SecretsProducer<'a, P: CipherSuiteProvider> {
    cipher_suite_provider: &'a P,
    epoch_secret: &'a [u8],
}

impl<'a, P: CipherSuiteProvider> SecretsProducer<'a, P> {
    fn new(cipher_suite_provider: &'a P, epoch_secret: &'a [u8]) -> Self {
        Self {
            cipher_suite_provider,
            epoch_secret,
        }
    }

    // TODO document somewhere in the crypto provider that the RFC defines the length of all secrets as
    // KDF extract size but then inputs secrets as MAC keys etc, therefore, we require that these
    // lengths match in the crypto provider
    fn derive(&self, label: &str) -> Result<Vec<u8>, KeyScheduleError> {
        kdf_derive_secret(self.cipher_suite_provider, self.epoch_secret, label)
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))
    }
}

const EXPORTER_CONTEXT: &[u8] = b"MLS 1.0 external init secret";

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize, Zeroize)]
#[zeroize(drop)]
pub struct InitSecret(#[serde_as(as = "VecAsBase64")] Vec<u8>);

impl InitSecret {
    pub fn random<P: CipherSuiteProvider>(cipher_suite: &P) -> Result<Self, KeyScheduleError> {
        cipher_suite
            .random_bytes_vec(cipher_suite.kdf_extract_size())
            .map(InitSecret)
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))
    }

    /// Returns init secret and KEM output to be used when creating an external commit.
    pub fn encode_for_external<P: CipherSuiteProvider>(
        cipher_suite: &P,
        external_pub: &HpkePublicKey,
    ) -> Result<(Self, Vec<u8>), KeyScheduleError> {
        let (kem_output, context) = cipher_suite
            .hpke_setup_s(external_pub, &[])
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))?;

        let init_secret = context
            .export(EXPORTER_CONTEXT, cipher_suite.kdf_extract_size())
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))?;

        Ok((InitSecret(init_secret), kem_output))
    }

    pub fn decode_for_external<P: CipherSuiteProvider>(
        cipher_suite: &P,
        kem_output: &[u8],
        external_secret: &HpkeSecretKey,
    ) -> Result<Self, KeyScheduleError> {
        let context = cipher_suite
            .hpke_setup_r(kem_output, external_secret, &[])
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))?;

        context
            .export(EXPORTER_CONTEXT, cipher_suite.kdf_extract_size())
            .map(InitSecret)
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct CommitSecret(PathSecret);

impl CommitSecret {
    pub fn from_root_secret<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
        root_secret: Option<&PathSecret>,
    ) -> Result<Self, PathSecretError> {
        match root_secret {
            Some(root_secret) => {
                let mut generator =
                    PathSecretGenerator::starting_from(cipher_suite_provider, root_secret.clone());

                Ok(CommitSecret(generator.next_secret()?.path_secret))
            }
            None => Ok(Self::empty(cipher_suite_provider)),
        }
    }

    pub fn empty<P: CipherSuiteProvider>(cipher_suite_provider: &P) -> CommitSecret {
        CommitSecret(PathSecret::empty(cipher_suite_provider))
    }
}

pub(crate) struct WelcomeSecret<'a, P: CipherSuiteProvider> {
    cipher_suite: &'a P,
    key: Zeroizing<Vec<u8>>,
    nonce: Zeroizing<Vec<u8>>,
}

impl<'a, P: CipherSuiteProvider> WelcomeSecret<'a, P> {
    pub(crate) fn from_joiner_secret(
        cipher_suite: &'a P,
        joiner_secret: &JoinerSecret,
        psk_secret: &Psk,
    ) -> Result<Self, KeyScheduleError> {
        let epoch_seed = Zeroizing::new(get_pre_epoch_secret(
            cipher_suite,
            psk_secret,
            joiner_secret,
        )?);

        let welcome_secret =
            Zeroizing::new(kdf_derive_secret(cipher_suite, &epoch_seed, "welcome")?);

        let key = cipher_suite
            .kdf_expand(&welcome_secret, b"key", cipher_suite.aead_key_size())
            .map(Zeroizing::new)
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))?;

        let nonce = cipher_suite
            .kdf_expand(&welcome_secret, b"nonce", cipher_suite.aead_nonce_size())
            .map(Zeroizing::new)
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))?;

        Ok(Self {
            cipher_suite,
            key,
            nonce,
        })
    }

    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, KeyScheduleError> {
        self.cipher_suite
            .aead_seal(&self.key, plaintext, None, &self.nonce)
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))
    }

    pub(crate) fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, KeyScheduleError> {
        self.cipher_suite
            .aead_open(&self.key, ciphertext, None, &self.nonce)
            .map_err(|e| KeyScheduleError::CipherSuiteProviderError(e.into()))
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use aws_mls_core::crypto::CipherSuiteProvider;

    use crate::{
        cipher_suite::CipherSuite, provider::crypto::test_utils::test_cipher_suite_provider,
    };

    use super::{InitSecret, KeySchedule};

    pub(crate) fn get_test_key_schedule(cipher_suite: CipherSuite) -> KeySchedule {
        let key_size = test_cipher_suite_provider(cipher_suite).kdf_extract_size();

        KeySchedule {
            exporter_secret: vec![0u8; key_size],
            authentication_secret: vec![0u8; key_size],
            external_secret: vec![0u8; key_size],
            membership_key: vec![0u8; key_size],
            init_secret: InitSecret::new(vec![0u8; key_size]),
        }
    }

    impl InitSecret {
        pub fn new(init_secret: Vec<u8>) -> Self {
            InitSecret(init_secret)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::group::test_utils::get_test_group_context;
    use crate::group::InitSecret;
    use crate::provider::crypto::test_utils::{
        test_cipher_suite_provider, try_test_cipher_suite_provider, TestCryptoProvider,
    };
    use aws_mls_core::crypto::CipherSuiteProvider;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::test_utils::get_test_key_schedule;
    use super::{CommitSecret, KeySchedule};

    #[derive(serde::Deserialize, serde::Serialize)]
    struct ExporterTestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        input: Vec<u8>,
        #[serde(with = "hex::serde")]
        output: Vec<u8>,
    }

    fn generate_epoch_secret_exporter_test_vector() -> Vec<ExporterTestCase> {
        let mut test_cases = Vec::new();

        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let cs_provider = test_cipher_suite_provider(cipher_suite);
            let key_size = cs_provider.kdf_extract_size();

            let mut key_schedule = get_test_key_schedule(cipher_suite);

            cs_provider
                .random_bytes(&mut key_schedule.exporter_secret)
                .unwrap();

            let mut context = vec![0u8; key_size];
            cs_provider.random_bytes(&mut context).unwrap();

            let mut test_case_input = vec![];
            test_case_input.extend(&key_schedule.exporter_secret);
            test_case_input.extend(&context);

            let exported_secret = key_schedule
                .export_secret(
                    "test",
                    &context,
                    key_size,
                    &test_cipher_suite_provider(cipher_suite),
                )
                .unwrap();

            test_cases.push(ExporterTestCase {
                cipher_suite: cipher_suite as u16,
                input: test_case_input,
                output: exported_secret,
            });
        }

        test_cases
    }

    fn load_exporter_test_cases() -> Vec<ExporterTestCase> {
        load_test_cases!(
            epoch_secret_exporter_test_vector,
            generate_epoch_secret_exporter_test_vector()
        )
    }

    #[test]
    fn test_export_secret() {
        let test_cases = load_exporter_test_cases();

        for test_case in test_cases {
            let Some(cipher_suite_provider) = try_test_cipher_suite_provider(test_case.cipher_suite) else {
                continue;
            };

            let key_size = cipher_suite_provider.kdf_extract_size();

            let key_schedule = KeySchedule {
                exporter_secret: test_case.input[0..key_size].to_vec(),
                authentication_secret: vec![0u8; key_size],
                external_secret: vec![0u8; key_size],
                membership_key: vec![0u8; key_size],
                init_secret: InitSecret::new(vec![0u8; key_size]),
            };

            let context = &test_case.input[key_size..];

            let exported_secret = key_schedule
                .export_secret("test", context, key_size, &cipher_suite_provider)
                .unwrap();

            assert_eq!(exported_secret, test_case.output);
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct KeyScheduleTestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        joiner: Vec<u8>,
        #[serde(with = "hex::serde")]
        sender_data: Vec<u8>,
        #[serde(with = "hex::serde")]
        encryption: Vec<u8>,
        #[serde(with = "hex::serde")]
        exporter: Vec<u8>,
        #[serde(with = "hex::serde")]
        confirm: Vec<u8>,
        #[serde(with = "hex::serde")]
        membership: Vec<u8>,
        #[serde(with = "hex::serde")]
        resumption: Vec<u8>,
        #[serde(with = "hex::serde")]
        authentication: Vec<u8>,
    }

    fn generate_key_schedule_test_vector() -> Vec<KeyScheduleTestCase> {
        let mut test_cases = Vec::new();

        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let cs_provider = test_cipher_suite_provider(cipher_suite);
            let key_size = cs_provider.kdf_extract_size();

            let key_schedule = get_test_key_schedule(cipher_suite);
            let context = get_test_group_context(42, cipher_suite);
            let psk = vec![0u8; key_size].into();
            let commit = CommitSecret(vec![0u8; key_size].into());

            let key_schedule = KeySchedule::from_key_schedule(
                &key_schedule,
                &commit,
                &context,
                32,
                &psk,
                &cs_provider,
            )
            .unwrap();

            test_cases.push(KeyScheduleTestCase {
                cipher_suite: cipher_suite as u16,
                joiner: key_schedule.joiner_secret.into(),
                exporter: key_schedule.key_schedule.exporter_secret.clone(),
                confirm: key_schedule.confirmation_key,
                membership: key_schedule.key_schedule.membership_key.clone(),
                resumption: key_schedule.epoch_secrets.resumption_secret.into(),
                authentication: key_schedule.key_schedule.authentication_secret.clone(),
                sender_data: (*key_schedule.epoch_secrets.sender_data_secret).to_vec(),
                encryption: key_schedule.epoch_secrets.secret_tree.get_root_secret(),
            });
        }

        test_cases
    }

    fn load_key_schedue_test_cases() -> Vec<KeyScheduleTestCase> {
        load_test_cases!(
            key_schedule_test_vector,
            generate_key_schedule_test_vector()
        )
    }

    #[test]
    fn test_key_schedule() {
        let test_cases = load_key_schedue_test_cases();

        for test_case in test_cases {
            let Some(cs_provider) = try_test_cipher_suite_provider(test_case.cipher_suite) else {
                continue;
            };

            let key_size = cs_provider.kdf_extract_size();

            let key_schedule = get_test_key_schedule(cs_provider.cipher_suite());
            let context = get_test_group_context(42, cs_provider.cipher_suite());

            let psk = vec![0u8; key_size].into();
            let commit = CommitSecret(vec![0u8; key_size].into());

            let key_schedule = KeySchedule::from_key_schedule(
                &key_schedule,
                &commit,
                &context,
                32,
                &psk,
                &cs_provider,
            )
            .unwrap();

            let expected: Vec<u8> = key_schedule.joiner_secret.into();
            assert_eq!(test_case.joiner, expected);

            assert_eq!(
                test_case.sender_data,
                *key_schedule.epoch_secrets.sender_data_secret.to_vec()
            );

            assert_eq!(
                test_case.encryption,
                *key_schedule.epoch_secrets.secret_tree.get_root_secret()
            );

            assert_eq!(
                test_case.exporter,
                key_schedule.key_schedule.exporter_secret
            );

            assert_eq!(test_case.confirm, key_schedule.confirmation_key);

            assert_eq!(
                test_case.membership,
                key_schedule.key_schedule.membership_key
            );

            let expected: Vec<u8> = key_schedule.epoch_secrets.resumption_secret.into();
            assert_eq!(test_case.resumption, expected);

            assert_eq!(
                test_case.authentication,
                key_schedule.key_schedule.authentication_secret
            );
        }
    }
}
