use ferriscrypt::cipher::aead::{AeadNonce, Key};
use ferriscrypt::digest::HashFunction;
use ferriscrypt::hpke::kem::{HpkePublicKey, KemType};
use ferriscrypt::hpke::{HpkeError, KdfId};
use ferriscrypt::kdf::hkdf::Hkdf;
use ferriscrypt::kdf::KdfError;
use ferriscrypt::rand::{SecureRng, SecureRngError};
use std::collections::HashMap;
use std::ops::Deref;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::{Zeroize, Zeroizing};

use crate::cipher_suite::CipherSuite;
use crate::group::secret_tree::SecretTreeError;
use crate::group::{GroupContext, LeafIndex, MembershipTag, MembershipTagError, SecretTree};
use crate::psk::{get_epoch_secret, JoinerSecret, Psk, PskSecretError};
use crate::signing_identity::SigningIdentityError;
use crate::tree_kem::TreeKemPublic;
use crate::tree_kem::{
    path_secret::{PathSecret, PathSecretError, PathSecretGenerator},
    TreeSecrets, UpdatePathGeneration,
};
use ferriscrypt::cipher::aead::AeadError;
use ferriscrypt::cipher::NonceError;

use super::epoch::Epoch;
use super::framing::MLSPlaintext;

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
    #[error(transparent)]
    SecureRngError(#[from] SecureRngError),
    #[error(transparent)]
    PskSecretError(#[from] PskSecretError),
    #[error(transparent)]
    SigningIdentityError(#[from] SigningIdentityError),
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Zeroize)]
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
    pub(crate) epoch: Epoch,
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

    pub fn derive_for_external(
        &self,
        kem_output: &[u8],
        cipher_suite: CipherSuite,
    ) -> Result<KeySchedule, HpkeError> {
        let init_secret =
            InitSecret::decode_for_external(cipher_suite, kem_output, &self.external_secret)?;
        Ok(KeySchedule::new(init_secret))
    }

    /// Returns the derived epoch as well as the joiner secret required for building welcome
    /// messages
    pub(crate) fn derive(
        last_key_schedule: &KeySchedule,
        commit_secret: &CommitSecret,
        context: &GroupContext,
        self_index: LeafIndex,
        public_tree: &TreeKemPublic,
        psk_secret: &Psk,
    ) -> Result<KeyScheduleDerivationResult, KeyScheduleError> {
        let cipher_suite = context.cipher_suite;

        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());

        let joiner_seed =
            Zeroizing::new(kdf.extract(&commit_secret.0, &last_key_schedule.init_secret.0)?);

        let joiner_secret: JoinerSecret = kdf
            .expand_with_label(
                &joiner_seed,
                "joiner",
                &context.tls_serialize_detached()?,
                kdf.extract_size(),
            )?
            .into();

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

    pub(crate) fn new_joiner(
        cipher_suite: CipherSuite,
        joiner_secret: &JoinerSecret,
        context: &GroupContext,
        self_index: LeafIndex,
        public_tree: &TreeKemPublic,
        psk_secret: &Psk,
    ) -> Result<KeyScheduleDerivationResult, KeyScheduleError> {
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());

        let epoch_seed = Zeroizing::new(get_epoch_secret(cipher_suite, psk_secret, joiner_secret)?);

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

        let signature_public_keys = public_tree
            .non_empty_leaves()
            .map(|(index, leaf)| {
                leaf.signing_identity
                    .public_key(cipher_suite)
                    .map(|pk| (index, pk))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        let epoch = Epoch::new(
            context.clone(),
            self_index,
            resumption_secret,
            sender_data_secret,
            secret_tree,
            cipher_suite,
            signature_public_keys,
        );

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
            joiner_secret: vec![].into(),
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

    pub fn get_membership_tag(
        &self,
        plaintext: &MLSPlaintext,
        context: &GroupContext,
    ) -> Result<MembershipTag, MembershipTagError> {
        MembershipTag::create(plaintext, context, &self.membership_key)
    }

    pub fn get_external_public_key(
        &self,
        cipher_suite: CipherSuite,
    ) -> Result<HpkePublicKey, HpkeError> {
        Ok(cipher_suite.kem().derive(&self.external_secret)?.1)
    }
}

const EXPORTER_CONTEXT: &[u8] = b"MLS 1.0 external init secret";

#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
    Zeroize,
)]
#[zeroize(drop)]
pub struct InitSecret(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

impl InitSecret {
    pub fn new(init_secret: Vec<u8>) -> Self {
        InitSecret(init_secret)
    }

    pub fn random(kdf: &Hkdf) -> Result<Self, SecureRngError> {
        SecureRng::gen(kdf.extract_size()).map(InitSecret)
    }

    pub fn from_epoch_secret(
        kdf: &KeyScheduleKdf,
        epoch_secret: &[u8],
    ) -> Result<Self, KeyScheduleKdfError> {
        kdf.derive_secret(epoch_secret, "init").map(InitSecret)
    }

    /// Returns init secret and KEM output to be used when creating an external commit.
    pub fn encode_for_external(
        cipher_suite: CipherSuite,
        external_pub: &HpkePublicKey,
    ) -> Result<(Self, Vec<u8>), HpkeError> {
        let (kem_output, context) = cipher_suite.hpke().setup_sender(external_pub, &[], None)?;

        let kdf_extract_size = Hkdf::from(cipher_suite.kdf_type()).extract_size();
        let mut init_secret = vec![0; kdf_extract_size];
        context.export(EXPORTER_CONTEXT, &mut init_secret)?;

        Ok((InitSecret(init_secret), kem_output))
    }

    pub fn decode_for_external(
        cipher_suite: CipherSuite,
        kem_output: &[u8],
        external_secret: &[u8],
    ) -> Result<Self, HpkeError> {
        let context = cipher_suite.hpke().setup_receiver(
            kem_output,
            &cipher_suite.kem().derive(external_secret)?.0,
            &[],
            None,
        )?;

        let kdf_extract_size = Hkdf::from(cipher_suite.kdf_type()).extract_size();

        let mut init_secret = vec![0; kdf_extract_size];
        context.export(EXPORTER_CONTEXT, &mut init_secret)?;
        Ok(InitSecret(init_secret))
    }
}

#[derive(Debug, Clone, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct CommitSecret(PathSecret);

impl CommitSecret {
    // Define commit_secret as the value path_secret[n+1] derived from the path_secret[n] value
    // assigned to the root node.
    pub fn from_update_path(
        cipher_suite: CipherSuite,
        update_path: Option<&UpdatePathGeneration>,
    ) -> Result<Self, PathSecretError> {
        Self::from_tree_secrets(cipher_suite, update_path.map(|up| &up.secrets))
    }

    pub fn from_tree_secrets(
        cipher_suite: CipherSuite,
        secrets: Option<&TreeSecrets>,
    ) -> Result<Self, PathSecretError> {
        match secrets {
            Some(secrets) => {
                let mut generator = PathSecretGenerator::starting_from(
                    cipher_suite,
                    secrets.secret_path.root_secret.clone(),
                );

                let secret = generator.next_secret()?;
                Ok(CommitSecret(secret.path_secret))
            }
            None => Ok(Self::empty(cipher_suite)),
        }
    }

    pub fn empty(cipher_suite: CipherSuite) -> CommitSecret {
        CommitSecret(PathSecret::empty(cipher_suite))
    }
}

pub(crate) struct WelcomeSecret {
    key: Key,
    nonce: AeadNonce,
}

impl WelcomeSecret {
    pub(crate) fn from_joiner_secret(
        cipher_suite: CipherSuite,
        joiner_secret: &JoinerSecret,
        psk_secret: &Psk,
    ) -> Result<WelcomeSecret, KeyScheduleError> {
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());
        let epoch_seed = Zeroizing::new(get_epoch_secret(cipher_suite, psk_secret, joiner_secret)?);
        let welcome_secret = Zeroizing::new(kdf.derive_secret(&epoch_seed, "welcome")?);

        let aead = cipher_suite.aead_type();

        let mut key_buf = vec![0u8; aead.key_size()];
        kdf.expand(&welcome_secret, b"key", &mut key_buf)?;
        let key = Key::new(aead, key_buf)?;

        let mut nonce_buf = vec![0u8; aead.nonce_size()];
        kdf.expand(&welcome_secret, b"nonce", &mut nonce_buf)?;
        let nonce = AeadNonce::new(&nonce_buf)?;

        Ok(WelcomeSecret { key, nonce })
    }

    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, KeyScheduleError> {
        self.key
            .encrypt_to_vec(plaintext, None, self.nonce.clone())
            .map_err(Into::into)
    }

    pub(crate) fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, KeyScheduleError> {
        self.key
            .decrypt_from_vec(ciphertext, None, self.nonce.clone())
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use ferriscrypt::{kdf::hkdf::Hkdf, rand::SecureRng};

    use crate::cipher_suite::CipherSuite;
    use crate::group::InitSecret;

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
                init_secret: InitSecret::new(vec![0u8; key_size]),
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
                init_secret: InitSecret::new(vec![0u8; key_size]),
            };

            let context = &test_case.input[key_size..];

            let exported_secret = key_schedule
                .export_secret("test", context, key_size, cipher_suite)
                .unwrap();

            assert_eq!(exported_secret, test_case.output);
        }
    }
}
