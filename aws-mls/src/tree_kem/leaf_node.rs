use super::{parent_hash::ParentHash, Capabilities, Lifetime};
use crate::crypto::{CipherSuiteProvider, HpkePublicKey, HpkeSecretKey, SignatureSecretKey};
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::time::MlsTime;
use crate::{
    identity::SigningIdentity,
    signer::{Signable, SignatureError},
    ExtensionList,
};
use aws_mls_core::identity::IdentityProvider;
use aws_mls_core::tls::ByteVec;
use serde_with::serde_as;
use thiserror::Error;
use tls_codec::{Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Debug, Error)]
pub enum LeafNodeError {
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error("parent hash error: {0}")]
    ParentHashError(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("internal signer error: {0}")]
    SignerError(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("signing identity public key does not match the signer (secret key)")]
    InvalidSignerPublicKey,
    #[error("credential rejected by custom credential validator {0:?}")]
    IdentityProviderError(#[source] Box<dyn std::error::Error + Sync + Send>),
    #[error(transparent)]
    CipherSuiteProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[derive(
    Debug,
    Clone,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    PartialEq,
    Eq,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum LeafNodeSource {
    #[tls_codec(discriminant = 1)]
    KeyPackage(Lifetime),
    Update,
    Commit(ParentHash),
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
pub struct LeafNode {
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    pub public_key: HpkePublicKey,
    pub signing_identity: SigningIdentity,
    pub capabilities: Capabilities,
    pub leaf_node_source: LeafNodeSource,
    pub extensions: ExtensionList,
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ConfigProperties {
    pub capabilities: Capabilities,
    pub extensions: ExtensionList,
}

impl LeafNode {
    async fn check_signing_identity<I, CSP>(
        signing_identity: &SigningIdentity,
        signer: &SignatureSecretKey,
        identity_provider: &I,
        cipher_suite_provider: &CSP,
    ) -> Result<(), LeafNodeError>
    where
        I: IdentityProvider,
        CSP: CipherSuiteProvider,
    {
        let public_key = cipher_suite_provider
            .signature_key_derive_public(signer)
            .map_err(|e| LeafNodeError::CipherSuiteProviderError(e.into()))?;

        if public_key != signing_identity.signature_key {
            return Err(LeafNodeError::InvalidSignerPublicKey);
        }

        identity_provider
            .validate(signing_identity, Some(MlsTime::now()))
            .await
            .map_err(|e| LeafNodeError::IdentityProviderError(e.into()))
    }

    pub async fn generate<IP, CSP>(
        cipher_suite_provider: &CSP,
        properties: ConfigProperties,
        signing_identity: SigningIdentity,
        signer: &SignatureSecretKey,
        lifetime: Lifetime,
        identity_provider: &IP,
    ) -> Result<(Self, HpkeSecretKey), LeafNodeError>
    where
        IP: IdentityProvider,
        CSP: CipherSuiteProvider,
    {
        LeafNode::check_signing_identity(
            &signing_identity,
            signer,
            identity_provider,
            cipher_suite_provider,
        )
        .await?;

        let (secret_key, public_key) = cipher_suite_provider
            .kem_generate()
            .map_err(|e| LeafNodeError::CipherSuiteProviderError(e.into()))?;

        let mut leaf_node = LeafNode {
            public_key,
            signing_identity,
            capabilities: properties.capabilities,
            leaf_node_source: LeafNodeSource::KeyPackage(lifetime),
            extensions: properties.extensions,
            signature: Default::default(),
        };

        leaf_node.sign(
            cipher_suite_provider,
            signer,
            &LeafNodeSigningContext::default(),
        )?;

        Ok((leaf_node, secret_key))
    }

    pub fn update<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        group_id: &[u8],
        leaf_index: u32,
        new_properties: ConfigProperties,
        signing_identity: Option<SigningIdentity>,
        signer: &SignatureSecretKey,
    ) -> Result<HpkeSecretKey, LeafNodeError> {
        let (secret, public) = cipher_suite_provider
            .kem_generate()
            .map_err(|e| LeafNodeError::CipherSuiteProviderError(e.into()))?;

        self.public_key = public;
        self.capabilities = new_properties.capabilities;
        self.extensions = new_properties.extensions;
        self.leaf_node_source = LeafNodeSource::Update;

        if let Some(signing_identity) = signing_identity {
            self.signing_identity = signing_identity;
        }

        self.sign(
            cipher_suite_provider,
            signer,
            &(group_id, leaf_index).into(),
        )?;

        Ok(secret)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        group_id: &[u8],
        leaf_index: u32,
        new_properties: ConfigProperties,
        new_signing_identity: Option<SigningIdentity>,
        signer: &SignatureSecretKey,
        parent_hash: ParentHash,
    ) -> Result<HpkeSecretKey, LeafNodeError> {
        let (secret, public) = cipher_suite_provider
            .kem_generate()
            .map_err(|e| LeafNodeError::CipherSuiteProviderError(e.into()))?;

        self.public_key = public;
        self.capabilities = new_properties.capabilities;
        self.extensions = new_properties.extensions;
        self.leaf_node_source = LeafNodeSource::Commit(parent_hash);

        if let Some(new_signing_identity) = new_signing_identity {
            self.signing_identity = new_signing_identity;
        }

        self.sign(
            cipher_suite_provider,
            signer,
            &(group_id, leaf_index).into(),
        )?;

        Ok(secret)
    }
}

#[derive(Debug)]
struct LeafNodeTBS<'a> {
    public_key: &'a HpkePublicKey,
    signing_identity: &'a SigningIdentity,
    capabilities: &'a Capabilities,
    leaf_node_source: &'a LeafNodeSource,
    extensions: &'a ExtensionList,
    group_id: Option<&'a [u8]>,
    leaf_index: Option<u32>,
}

impl<'a> Size for LeafNodeTBS<'a> {
    fn tls_serialized_len(&self) -> usize {
        self.public_key.tls_serialized_len()
            + self.signing_identity.tls_serialized_len()
            + self.capabilities.tls_serialized_len()
            + self.leaf_node_source.tls_serialized_len()
            + self.extensions.tls_serialized_len()
            + self.group_id.map_or(0, ByteVec::tls_serialized_len)
            + self.leaf_index.map_or(0, |i| i.tls_serialized_len())
    }
}

impl<'a> Serialize for LeafNodeTBS<'a> {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let res = self.public_key.tls_serialize(writer)?
            + self.signing_identity.tls_serialize(writer)?
            + self.capabilities.tls_serialize(writer)?
            + self.leaf_node_source.tls_serialize(writer)?
            + self.extensions.tls_serialize(writer)?
            + self
                .group_id
                .map_or(Ok(0), |group_id| ByteVec::tls_serialize(group_id, writer))?
            + self.leaf_index.map_or(Ok(0), |i| i.tls_serialize(writer))?;

        Ok(res)
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct LeafNodeSigningContext<'a> {
    pub group_id: Option<&'a [u8]>,
    pub leaf_index: Option<u32>,
}

impl<'a> From<(&'a [u8], u32)> for LeafNodeSigningContext<'a> {
    fn from((group_id, leaf_index): (&'a [u8], u32)) -> Self {
        Self {
            group_id: Some(group_id),
            leaf_index: Some(leaf_index),
        }
    }
}

impl<'a> Signable<'a> for LeafNode {
    const SIGN_LABEL: &'static str = "LeafNodeTBS";

    type SigningContext = LeafNodeSigningContext<'a>;

    fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn signable_content(
        &self,
        context: &Self::SigningContext,
    ) -> Result<Vec<u8>, tls_codec::Error> {
        LeafNodeTBS {
            public_key: &self.public_key,
            signing_identity: &self.signing_identity,
            capabilities: &self.capabilities,
            leaf_node_source: &self.leaf_node_source,
            extensions: &self.extensions,
            group_id: context.group_id,
            leaf_index: context.leaf_index,
        }
        .tls_serialize_detached()
    }

    fn write_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature
    }
}

#[cfg(any(test, feature = "benchmark"))]
pub(crate) mod test_utils {
    use aws_mls_core::identity::{BasicCredential, CredentialType};

    use crate::{
        cipher_suite::CipherSuite,
        crypto::test_utils::{test_cipher_suite_provider, TestCryptoProvider},
        extension::ApplicationIdExt,
        identity::basic::BasicIdentityProvider,
        identity::test_utils::{get_test_signing_identity, BasicWithCustomProvider},
    };

    use super::*;

    #[allow(unused)]
    pub async fn get_test_node(
        cipher_suite: CipherSuite,
        signing_identity: SigningIdentity,
        secret: &SignatureSecretKey,
        capabilities: Option<Capabilities>,
        extensions: Option<ExtensionList>,
    ) -> (LeafNode, HpkeSecretKey) {
        get_test_node_with_lifetime(
            cipher_suite,
            signing_identity,
            secret,
            capabilities.unwrap_or_else(get_test_capabilities),
            extensions.unwrap_or_default(),
            Lifetime::years(1).unwrap(),
        )
        .await
    }

    pub async fn get_test_node_with_lifetime(
        cipher_suite: CipherSuite,
        signing_identity: SigningIdentity,
        secret: &SignatureSecretKey,
        capabilities: Capabilities,
        extensions: ExtensionList,
        lifetime: Lifetime,
    ) -> (LeafNode, HpkeSecretKey) {
        let properties = ConfigProperties {
            capabilities,
            extensions,
        };

        LeafNode::generate(
            &test_cipher_suite_provider(cipher_suite),
            properties,
            signing_identity,
            secret,
            lifetime,
            &BasicIdentityProvider::new(),
        )
        .await
        .unwrap()
    }

    #[allow(unused)]
    pub async fn get_basic_test_node(cipher_suite: CipherSuite, id: &str) -> LeafNode {
        get_basic_test_node_sig_key(cipher_suite, id).await.0
    }

    pub fn default_properties() -> ConfigProperties {
        ConfigProperties {
            capabilities: get_test_capabilities(),
            extensions: Default::default(),
        }
    }

    pub async fn get_basic_test_node_sig_key(
        cipher_suite: CipherSuite,
        id: &str,
    ) -> (LeafNode, HpkeSecretKey, SignatureSecretKey) {
        let (signing_identity, signature_key) =
            get_test_signing_identity(cipher_suite, id.as_bytes().to_vec());

        LeafNode::generate(
            &test_cipher_suite_provider(cipher_suite),
            default_properties(),
            signing_identity,
            &signature_key,
            Lifetime::years(1).unwrap(),
            &BasicIdentityProvider::new(),
        )
        .await
        .map(|(leaf, hpke_secret_key)| (leaf, hpke_secret_key, signature_key))
        .unwrap()
    }

    #[allow(unused)]
    pub fn get_test_extensions() -> ExtensionList {
        let mut extension_list = ExtensionList::new();

        extension_list
            .set_from(ApplicationIdExt {
                identifier: b"identifier".to_vec(),
            })
            .unwrap();

        extension_list
    }

    pub fn get_test_capabilities() -> Capabilities {
        Capabilities {
            credentials: vec![
                BasicCredential::credential_type(),
                CredentialType::from(BasicWithCustomProvider::CUSTOM_CREDENTIAL_TYPE),
            ],
            cipher_suites: TestCryptoProvider::all_supported_cipher_suites(),
            ..Default::default()
        }
    }

    #[allow(unused)]
    pub fn get_test_client_identity(leaf: &LeafNode) -> Vec<u8> {
        leaf.signing_identity
            .credential
            .tls_serialize_detached()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::*;
    use super::*;

    use crate::client::test_utils::TEST_CIPHER_SUITE;
    use crate::crypto::test_utils::test_cipher_suite_provider;
    use crate::crypto::test_utils::TestCryptoProvider;
    use crate::group::test_utils::random_bytes;
    use crate::identity::basic::BasicIdentityProvider;
    use crate::identity::test_utils::get_test_signing_identity;
    use crate::tree_kem::leaf_node_validator::test_utils::FailureIdentityProvider;
    use assert_matches::assert_matches;

    use aws_mls_core::crypto::CipherSuite;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[futures_test::test]
    async fn test_node_generation() {
        let capabilities = get_test_capabilities();
        let extensions = get_test_extensions();
        let lifetime = Lifetime::years(1).unwrap();

        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let (signing_identity, secret) =
                get_test_signing_identity(cipher_suite, b"foo".to_vec());

            let (leaf_node, secret_key) = get_test_node_with_lifetime(
                cipher_suite,
                signing_identity.clone(),
                &secret,
                capabilities.clone(),
                extensions.clone(),
                lifetime.clone(),
            )
            .await;

            assert_eq!(leaf_node.capabilities, capabilities);
            assert_eq!(leaf_node.extensions, extensions);
            assert_eq!(leaf_node.signing_identity, signing_identity);

            assert_matches!(
                &leaf_node.leaf_node_source,
                LeafNodeSource::KeyPackage(lt) if lt == &lifetime,
                "Expected {:?}, got {:?}", LeafNodeSource::KeyPackage(lifetime),
                leaf_node.leaf_node_source
            );

            let provider = test_cipher_suite_provider(cipher_suite);

            // Verify that the hpke key pair generated will work
            let test_data = random_bytes(32);

            let sealed = provider
                .hpke_seal(&leaf_node.public_key, &[], None, &test_data)
                .unwrap();

            let opened = provider.hpke_open(&sealed, &secret_key, &[], None).unwrap();

            assert_eq!(opened, test_data);

            leaf_node
                .verify(
                    &test_cipher_suite_provider(cipher_suite),
                    &signing_identity.signature_key,
                    &LeafNodeSigningContext::default(),
                )
                .unwrap();
        }
    }

    #[futures_test::test]
    async fn test_credential_signature_mismatch() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (test_signing_identity, _) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"foo".to_vec());

        let (incorrect_secret, _) = cipher_suite_provider.signature_key_generate().unwrap();

        let res = LeafNode::generate(
            &cipher_suite_provider,
            default_properties(),
            test_signing_identity,
            &incorrect_secret,
            Lifetime::years(1).unwrap(),
            &BasicIdentityProvider::new(),
        )
        .await;

        assert_matches!(res, Err(LeafNodeError::InvalidSignerPublicKey));
    }

    #[futures_test::test]
    async fn test_identity_invalid_for_ciphersuite() {
        let cipher_suite = TEST_CIPHER_SUITE;

        let (test_signing_identity, signer) =
            get_test_signing_identity(CipherSuite::P256_AES128, b"foo".to_vec());

        let res = LeafNode::generate(
            &test_cipher_suite_provider(cipher_suite),
            default_properties(),
            test_signing_identity,
            &signer,
            Lifetime::years(1).unwrap(),
            &BasicIdentityProvider::new(),
        )
        .await;

        assert_matches!(res, Err(LeafNodeError::InvalidSignerPublicKey));
    }

    #[futures_test::test]
    async fn invalid_credential_for_application() {
        let cipher_suite = TEST_CIPHER_SUITE;

        let (test_signing_identity, signer) =
            get_test_signing_identity(cipher_suite, b"foo".to_vec());

        let res = LeafNode::generate(
            &test_cipher_suite_provider(cipher_suite),
            default_properties(),
            test_signing_identity,
            &signer,
            Lifetime::years(1).unwrap(),
            &FailureIdentityProvider,
        )
        .await;

        assert_matches!(res, Err(LeafNodeError::IdentityProviderError(_)));
    }

    #[futures_test::test]
    async fn test_node_generation_randomness() {
        let cipher_suite = TEST_CIPHER_SUITE;

        let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo".to_vec());

        let (first_leaf, first_secret) =
            get_test_node(cipher_suite, signing_identity.clone(), &secret, None, None).await;

        for _ in 0..100 {
            let (next_leaf, next_secret) =
                get_test_node(cipher_suite, signing_identity.clone(), &secret, None, None).await;

            assert_ne!(first_secret, next_secret);
            assert_ne!(first_leaf.public_key, next_leaf.public_key);
        }
    }

    #[futures_test::test]
    async fn test_node_update_no_meta_changes() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let (signing_identity, secret) =
                get_test_signing_identity(cipher_suite, b"foo".to_vec());

            let (mut leaf, leaf_secret) =
                get_test_node(cipher_suite, signing_identity.clone(), &secret, None, None).await;

            let original_leaf = leaf.clone();

            let new_secret = leaf
                .update(
                    &cipher_suite_provider,
                    b"group",
                    0,
                    default_properties(),
                    None,
                    &secret,
                )
                .unwrap();

            assert_ne!(new_secret, leaf_secret);
            assert_ne!(original_leaf.public_key, leaf.public_key);

            assert_eq!(leaf.capabilities, original_leaf.capabilities);
            assert_eq!(leaf.extensions, original_leaf.extensions);
            assert_eq!(leaf.signing_identity, original_leaf.signing_identity);
            assert_matches!(&leaf.leaf_node_source, LeafNodeSource::Update);

            leaf.verify(
                &cipher_suite_provider,
                &signing_identity.signature_key,
                &(b"group".as_slice(), 0).into(),
            )
            .unwrap();
        }
    }

    #[futures_test::test]
    async fn test_node_update_meta_changes() {
        let cipher_suite = TEST_CIPHER_SUITE;

        let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo".to_vec());

        let new_properties = ConfigProperties {
            capabilities: get_test_capabilities(),
            extensions: get_test_extensions(),
        };

        let (mut leaf, _) =
            get_test_node(cipher_suite, signing_identity, &secret, None, None).await;

        leaf.update(
            &test_cipher_suite_provider(cipher_suite),
            b"group",
            0,
            new_properties.clone(),
            None,
            &secret,
        )
        .unwrap();

        assert_eq!(leaf.capabilities, new_properties.capabilities);
        assert_eq!(leaf.extensions, new_properties.extensions);
    }

    #[futures_test::test]
    async fn test_node_commit_no_meta_changes() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let (signing_identity, secret) =
                get_test_signing_identity(cipher_suite, b"foo".to_vec());

            let (mut leaf, leaf_secret) =
                get_test_node(cipher_suite, signing_identity.clone(), &secret, None, None).await;

            let original_leaf = leaf.clone();

            let test_parent_hash = ParentHash::from(vec![42u8; 32]);

            let new_secret = leaf
                .commit(
                    &cipher_suite_provider,
                    b"group",
                    0,
                    default_properties(),
                    None,
                    &secret,
                    test_parent_hash.clone(),
                )
                .unwrap();

            assert_ne!(new_secret, leaf_secret);
            assert_ne!(original_leaf.public_key, leaf.public_key);

            assert_eq!(leaf.capabilities, original_leaf.capabilities);
            assert_eq!(leaf.extensions, original_leaf.extensions);
            assert_eq!(leaf.signing_identity, original_leaf.signing_identity);
            assert_matches!(&leaf.leaf_node_source, LeafNodeSource::Commit(parent_hash) if parent_hash == &test_parent_hash);

            leaf.verify(
                &cipher_suite_provider,
                &signing_identity.signature_key,
                &(b"group".as_slice(), 0).into(),
            )
            .unwrap();
        }
    }

    #[futures_test::test]
    async fn test_node_commit_meta_changes() {
        let cipher_suite = TEST_CIPHER_SUITE;

        let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo".to_vec());
        let (mut leaf, _) =
            get_test_node(cipher_suite, signing_identity, &secret, None, None).await;

        let new_properties = ConfigProperties {
            capabilities: get_test_capabilities(),
            extensions: get_test_extensions(),
        };

        // The new identity has a fresh public key
        let new_signing_identity = get_test_signing_identity(cipher_suite, b"foo".to_vec()).0;

        let test_parent_hash = ParentHash::from(vec![42u8; 32]);

        leaf.commit(
            &test_cipher_suite_provider(cipher_suite),
            b"group",
            0,
            new_properties.clone(),
            Some(new_signing_identity.clone()),
            &secret,
            test_parent_hash,
        )
        .unwrap();

        assert_eq!(leaf.capabilities, new_properties.capabilities);
        assert_eq!(leaf.extensions, new_properties.extensions);
        assert_eq!(leaf.signing_identity, new_signing_identity);
    }

    #[futures_test::test]
    async fn context_is_signed() {
        let provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (signing_identity, secret) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"foo".to_vec());

        let (mut leaf, _) = get_test_node(
            TEST_CIPHER_SUITE,
            signing_identity.clone(),
            &secret,
            None,
            None,
        )
        .await;

        leaf.sign(&provider, &secret, &(b"foo".as_slice(), 0).into())
            .unwrap();

        let res = leaf.verify(
            &provider,
            &signing_identity.signature_key,
            &(b"foo".as_slice(), 1).into(),
        );
        assert_matches!(res, Err(SignatureError::SignatureValidationFailed(_)));

        let res = leaf.verify(
            &provider,
            &signing_identity.signature_key,
            &(b"bar".as_slice(), 0).into(),
        );
        assert_matches!(res, Err(SignatureError::SignatureValidationFailed(_)));
    }
}
