use ferriscrypt::digest::HashFunction;
use ferriscrypt::hpke::KdfId;
use ferriscrypt::kdf::hkdf::Hkdf;
use ferriscrypt::kdf::KdfError;
use std::ops::Deref;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsSerialize, TlsSize};
use zeroize::{Zeroize, Zeroizing};

use crate::cipher_suite::CipherSuite;
use crate::group::secret_tree::SecretTreeError;
use crate::group::{CommitSecret, GroupContext, InitSecret, LeafIndex, SecretTree};
use crate::tree_kem::TreeKemPublic;
use ferriscrypt::cipher::aead::AeadError;
use ferriscrypt::cipher::NonceError;

use super::epoch::Epoch;

#[derive(Debug, Error)]
pub enum KeyScheduleKdfError {
    #[error(transparent)]
    HkdfError(#[from] KdfError),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
}

#[derive(Error, Debug)]
pub enum KeyScheduleError {
    #[error(transparent)]
    KeyScheduleKdfError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    KdfError(#[from] KdfError),
    #[error(transparent)]
    SecretTreeError(#[from] SecretTreeError),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    AeadError(#[from] AeadError),
    #[error(transparent)]
    NonceError(#[from] NonceError),
    #[error("key derivation failure")]
    KeyDerivationFailure,
}

#[derive(TlsSerialize, TlsSize)]
pub(crate) struct Label<'a> {
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

#[derive(TlsSerialize, TlsSize)]
struct TreeContext {
    node: u32,
    generation: u32,
}

#[derive(Clone, Debug)]
pub struct KeyScheduleKdf(Hkdf);

impl Deref for KeyScheduleKdf {
    type Target = Hkdf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl KeyScheduleKdf {
    pub fn new(kdf_id: KdfId) -> KeyScheduleKdf {
        let hkdf = match kdf_id {
            KdfId::HkdfSha256 => Hkdf::new(HashFunction::Sha256),
            KdfId::HkdfSha384 => Hkdf::new(HashFunction::Sha384),
            KdfId::HkdfSha512 => Hkdf::new(HashFunction::Sha512),
        };

        KeyScheduleKdf(hkdf)
    }

    pub fn expand_with_label(
        &self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, KeyScheduleKdfError> {
        let label = Label::new(self.extract_size() as u16, label, context);
        let mut buf = vec![0u8; len];
        self.expand(secret, &label.tls_serialize_detached()?, &mut buf)?;
        Ok(buf)
    }

    pub fn derive_secret(
        &self,
        secret: &[u8],
        label: &str,
    ) -> Result<Vec<u8>, KeyScheduleKdfError> {
        self.expand_with_label(secret, label, &[], self.extract_size())
    }

    pub fn derive_tree_secret(
        &self,
        secret: &[u8],
        label: &str,
        node: u32,
        generation: u32,
        len: usize,
    ) -> Result<Vec<u8>, KeyScheduleKdfError> {
        let tree_context = TreeContext { node, generation };
        let tree_context_bytes = tree_context.tls_serialize_detached()?;
        self.expand_with_label(secret, label, &tree_context_bytes, len)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize, Zeroize)]
#[zeroize(drop)]
pub struct KeySchedule {
    pub exporter_secret: Vec<u8>,
    pub authentication_secret: Vec<u8>,
    pub external_secret: Vec<u8>,
    pub membership_key: Vec<u8>,
    pub init_secret: InitSecret,
}

pub struct KeyScheduleDerivationResult {
    pub key_schedule: KeySchedule,
    pub confirmation_key: Vec<u8>,
    pub joiner_secret: Vec<u8>,
    pub epoch: Epoch,
}

impl KeySchedule {
    /// Returns the derived epoch as well as the joiner secret required for building welcome
    /// messages
    pub fn derive(
        cipher_suite: CipherSuite,
        last_init_secret: &InitSecret,
        commit_secret: &CommitSecret,
        context: &GroupContext,
        self_index: LeafIndex,
        public_tree: TreeKemPublic,
        psk_secret: &[u8],
    ) -> Result<KeyScheduleDerivationResult, KeyScheduleError> {
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());

        let joiner_seed = Zeroizing::new(kdf.extract(commit_secret, last_init_secret.as_ref())?);

        let joiner_secret = kdf.expand_with_label(
            &joiner_seed,
            "joiner",
            &context.tls_serialize_detached()?,
            kdf.extract_size(),
        )?;

        let key_schedule_result = Self::new_joiner(
            cipher_suite,
            &joiner_secret,
            context,
            self_index,
            public_tree,
            psk_secret,
        )?;

        Ok(KeyScheduleDerivationResult {
            key_schedule: key_schedule_result.key_schedule,
            confirmation_key: key_schedule_result.confirmation_key,
            joiner_secret,
            epoch: key_schedule_result.epoch,
        })
    }

    pub fn new_joiner(
        cipher_suite: CipherSuite,
        joiner_secret: &[u8],
        context: &GroupContext,
        self_index: LeafIndex,
        public_tree: TreeKemPublic,
        psk_secret: &[u8],
    ) -> Result<KeyScheduleDerivationResult, KeyScheduleError> {
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());

        let epoch_seed = Zeroizing::new(kdf.extract(psk_secret, joiner_secret)?);

        let epoch_secret = Zeroizing::new(kdf.expand_with_label(
            &epoch_seed,
            "epoch",
            &context.tls_serialize_detached()?,
            kdf.extract_size(),
        )?);

        // Derive secrets from epoch secret
        let sender_data_secret = kdf.derive_secret(&epoch_secret, "sender data")?;
        let encryption_secret = kdf.derive_secret(&epoch_secret, "encryption")?;
        let exporter_secret = kdf.derive_secret(&epoch_secret, "exporter")?;
        let authentication_secret = kdf.derive_secret(&epoch_secret, "authentication")?;
        let external_secret = kdf.derive_secret(&epoch_secret, "external")?;
        let confirmation_key = kdf.derive_secret(&epoch_secret, "confirm")?;
        let membership_key = kdf.derive_secret(&epoch_secret, "membership")?;
        let resumption_secret = kdf.derive_secret(&epoch_secret, "resumption")?;
        let init_secret = InitSecret::from_epoch_secret(&kdf, &epoch_secret)?;

        let secret_tree = SecretTree::new(
            cipher_suite,
            public_tree.total_leaf_count(),
            encryption_secret,
        );

        let epoch = Epoch {
            context: context.clone(),
            self_index,
            sender_data_secret,
            resumption_secret,
            secret_tree,
            application_ratchets: Default::default(),
            handshake_ratchets: Default::default(),
            cipher_suite,
            public_tree,
        };

        let key_schedule = Self {
            exporter_secret,
            authentication_secret,
            external_secret,
            membership_key,
            init_secret,
        };

        Ok(KeyScheduleDerivationResult {
            key_schedule,
            confirmation_key,
            joiner_secret: vec![],
            epoch,
        })
    }

    pub fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        len: usize,
        cipher_suite: CipherSuite,
    ) -> Result<Vec<u8>, KeyScheduleKdfError> {
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());
        let derived_secret = Zeroizing::new(kdf.derive_secret(&self.exporter_secret, label)?);
        let context_hash = cipher_suite.hash_function().digest(context);

        kdf.expand_with_label(&derived_secret, "exporter", &context_hash, len)
    }
}

#[cfg(test)]
mod tests {
    use ferriscrypt::{kdf::hkdf::Hkdf, rand::SecureRng};

    use crate::{cipher_suite::CipherSuite, group::init_secret::InitSecret};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::KeySchedule;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        input: Vec<u8>,
        #[serde(with = "hex::serde")]
        output: Vec<u8>,
    }

    fn generate_epoch_secret_exporter_test_vector() -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for cipher_suite in CipherSuite::all() {
            let kdf = Hkdf::from(cipher_suite.kdf_type());
            let key_size = kdf.extract_size();

            let mut key_schedule = KeySchedule {
                exporter_secret: vec![0u8; key_size],
                authentication_secret: vec![0u8; key_size],
                external_secret: vec![0u8; key_size],
                membership_key: vec![0u8; key_size],
                init_secret: InitSecret(vec![0u8; key_size]),
            };

            SecureRng::fill(&mut key_schedule.exporter_secret).unwrap();

            let mut context = vec![0u8; key_size];
            SecureRng::fill(&mut context).unwrap();

            let mut test_case_input = vec![];
            test_case_input.extend(&key_schedule.exporter_secret);
            test_case_input.extend(&context);

            let exported_secret = key_schedule
                .export_secret("test", &context, key_size, cipher_suite)
                .unwrap();

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                input: test_case_input,
                output: exported_secret,
            });
        }

        test_cases
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(
            epoch_secret_exporter_test_vector,
            generate_epoch_secret_exporter_test_vector
        )
    }

    #[test]
    fn test_export_secret() {
        let test_cases = load_test_cases();

        for test_case in test_cases {
            let cipher_suite = match CipherSuite::from_raw(test_case.cipher_suite) {
                Some(cs) => cs,
                None => continue,
            };

            let kdf = Hkdf::from(cipher_suite.kdf_type());
            let key_size = kdf.extract_size();

            let key_schedule = KeySchedule {
                exporter_secret: test_case.input[0..key_size].to_vec(),
                authentication_secret: vec![0u8; key_size],
                external_secret: vec![0u8; key_size],
                membership_key: vec![0u8; key_size],
                init_secret: InitSecret(vec![0u8; key_size]),
            };

            let context = &test_case.input[key_size..];

            let exported_secret = key_schedule
                .export_secret("test", context, key_size, cipher_suite)
                .unwrap();

            assert_eq!(exported_secret, test_case.output);
        }
    }
}
