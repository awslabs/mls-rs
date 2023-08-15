use super::{parent_hash::ParentHash, Capabilities, Lifetime};
use crate::client::MlsError;
use crate::crypto::{CipherSuiteProvider, HpkePublicKey, HpkeSecretKey, SignatureSecretKey};
use crate::{identity::SigningIdentity, signer::Signable, ExtensionList};
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use aws_mls_core::error::IntoAnyError;

#[derive(Debug, Clone, MlsSize, MlsEncode, MlsDecode, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum LeafNodeSource {
    KeyPackage(Lifetime) = 1u8,
    Update = 2u8,
    Commit(ParentHash) = 3u8,
}

#[derive(Debug, Clone, MlsSize, MlsEncode, MlsDecode, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
pub struct LeafNode {
    pub public_key: HpkePublicKey,
    pub signing_identity: SigningIdentity,
    pub capabilities: Capabilities,
    pub leaf_node_source: LeafNodeSource,
    pub extensions: ExtensionList,
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ConfigProperties {
    pub capabilities: Capabilities,
    pub extensions: ExtensionList,
}

impl LeafNode {
    #[maybe_async::maybe_async]
    pub async fn generate<CSP>(
        cipher_suite_provider: &CSP,
        properties: ConfigProperties,
        signing_identity: SigningIdentity,
        signer: &SignatureSecretKey,
        lifetime: Lifetime,
    ) -> Result<(Self, HpkeSecretKey), MlsError>
    where
        CSP: CipherSuiteProvider,
    {
        let (secret_key, public_key) = cipher_suite_provider
            .kem_generate()
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;

        let mut leaf_node = LeafNode {
            public_key,
            signing_identity,
            capabilities: properties.capabilities,
            leaf_node_source: LeafNodeSource::KeyPackage(lifetime),
            extensions: properties.extensions,
            signature: Default::default(),
        };

        leaf_node.grease(cipher_suite_provider)?;

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
    ) -> Result<HpkeSecretKey, MlsError> {
        let (secret, public) = cipher_suite_provider
            .kem_generate()
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;

        self.public_key = public;
        self.capabilities = new_properties.capabilities;
        self.extensions = new_properties.extensions;
        self.leaf_node_source = LeafNodeSource::Update;

        self.grease(cipher_suite_provider)?;

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
    ) -> Result<HpkeSecretKey, MlsError> {
        let (secret, public) = cipher_suite_provider
            .kem_generate()
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;

        self.public_key = public;
        self.capabilities = new_properties.capabilities;
        self.extensions = new_properties.extensions;

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

impl<'a> MlsSize for LeafNodeTBS<'a> {
    fn mls_encoded_len(&self) -> usize {
        self.public_key.mls_encoded_len()
            + self.signing_identity.mls_encoded_len()
            + self.capabilities.mls_encoded_len()
            + self.leaf_node_source.mls_encoded_len()
            + self.extensions.mls_encoded_len()
            + self
                .group_id
                .as_ref()
                .map_or(0, aws_mls_codec::byte_vec::mls_encoded_len)
            + self.leaf_index.map_or(0, |i| i.mls_encoded_len())
    }
}

impl<'a> MlsEncode for LeafNodeTBS<'a> {
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), aws_mls_codec::Error> {
        self.public_key.mls_encode(writer)?;
        self.signing_identity.mls_encode(writer)?;
        self.capabilities.mls_encode(writer)?;
        self.leaf_node_source.mls_encode(writer)?;
        self.extensions.mls_encode(writer)?;

        if let Some(ref group_id) = self.group_id {
            aws_mls_codec::byte_vec::mls_encode(group_id, writer)?;
        }

        if let Some(leaf_index) = self.leaf_index {
            leaf_index.mls_encode(writer)?;
        }

        Ok(())
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
    ) -> Result<Vec<u8>, aws_mls_codec::Error> {
        LeafNodeTBS {
            public_key: &self.public_key,
            signing_identity: &self.signing_identity,
            capabilities: &self.capabilities,
            leaf_node_source: &self.leaf_node_source,
            extensions: &self.extensions,
            group_id: context.group_id,
            leaf_index: context.leaf_index,
        }
        .mls_encode_to_vec()
    }

    fn write_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use alloc::vec;
    use aws_mls_core::identity::{BasicCredential, CredentialType};

    use crate::{
        cipher_suite::CipherSuite,
        crypto::test_utils::{test_cipher_suite_provider, TestCryptoProvider},
        identity::test_utils::{get_test_signing_identity, BasicWithCustomProvider},
    };

    #[cfg(feature = "all_extensions")]
    use crate::extension::ApplicationIdExt;

    use super::*;

    #[allow(unused)]
    #[maybe_async::maybe_async]
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

    #[maybe_async::maybe_async]
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
        )
        .await
        .unwrap()
    }

    #[allow(unused)]
    #[maybe_async::maybe_async]
    pub async fn get_basic_test_node(cipher_suite: CipherSuite, id: &str) -> LeafNode {
        get_basic_test_node_sig_key(cipher_suite, id).await.0
    }

    #[allow(unused)]
    pub fn default_properties() -> ConfigProperties {
        ConfigProperties {
            capabilities: get_test_capabilities(),
            extensions: Default::default(),
        }
    }

    #[maybe_async::maybe_async]
    pub async fn get_basic_test_node_capabilities(
        cipher_suite: CipherSuite,
        id: &str,
        capabilities: Capabilities,
    ) -> (LeafNode, HpkeSecretKey, SignatureSecretKey) {
        let (signing_identity, signature_key) =
            get_test_signing_identity(cipher_suite, id.as_bytes());

        LeafNode::generate(
            &test_cipher_suite_provider(cipher_suite),
            ConfigProperties {
                capabilities,
                extensions: Default::default(),
            },
            signing_identity,
            &signature_key,
            Lifetime::years(1).unwrap(),
        )
        .await
        .map(|(leaf, hpke_secret_key)| (leaf, hpke_secret_key, signature_key))
        .unwrap()
    }

    #[maybe_async::maybe_async]
    pub async fn get_basic_test_node_sig_key(
        cipher_suite: CipherSuite,
        id: &str,
    ) -> (LeafNode, HpkeSecretKey, SignatureSecretKey) {
        get_basic_test_node_capabilities(cipher_suite, id, get_test_capabilities()).await
    }

    #[cfg(feature = "all_extensions")]
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

    #[cfg(not(feature = "all_extensions"))]
    #[allow(unused)]
    pub fn get_test_extensions() -> ExtensionList {
        ExtensionList::new()
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
            .mls_encode_to_vec()
            .unwrap()
    }
}

#[cfg(feature = "benchmark")]
impl LeafNode {
    #[maybe_async::maybe_async]
    pub async fn generate_default<CS: CipherSuiteProvider>(
        cs: &CS,
        name: &str,
    ) -> (LeafNode, HpkeSecretKey, SignatureSecretKey) {
        let (signer, public) = cs.signature_key_generate().unwrap();
        let basic_identity = crate::identity::basic::BasicCredential::new(name.as_bytes().to_vec());
        let signing_identity = SigningIdentity::new(basic_identity.into_credential(), public);

        let properties = ConfigProperties {
            capabilities: Default::default(),
            extensions: Default::default(),
        };

        let lifetime = Default::default();

        let (leaf, secret) =
            LeafNode::generate(cs, properties, signing_identity, &signer, lifetime)
                .await
                .unwrap();

        (leaf, secret, signer)
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
    use crate::identity::test_utils::get_test_signing_identity;
    use assert_matches::assert_matches;

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_node_generation() {
        let capabilities = get_test_capabilities();
        let extensions = get_test_extensions();
        let lifetime = Lifetime::years(1).unwrap();

        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo");

            let (leaf_node, secret_key) = get_test_node_with_lifetime(
                cipher_suite,
                signing_identity.clone(),
                &secret,
                capabilities.clone(),
                extensions.clone(),
                lifetime.clone(),
            )
            .await;

            assert_eq!(leaf_node.ungreased_capabilities(), capabilities);
            assert_eq!(leaf_node.ungreased_extensions(), extensions);
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

            let opened = provider
                .hpke_open(&sealed, &secret_key, &leaf_node.public_key, &[], None)
                .unwrap();

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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_node_generation_randomness() {
        let cipher_suite = TEST_CIPHER_SUITE;

        let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo");

        let (first_leaf, first_secret) =
            get_test_node(cipher_suite, signing_identity.clone(), &secret, None, None).await;

        for _ in 0..100 {
            let (next_leaf, next_secret) =
                get_test_node(cipher_suite, signing_identity.clone(), &secret, None, None).await;

            assert_ne!(first_secret, next_secret);
            assert_ne!(first_leaf.public_key, next_leaf.public_key);
        }
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_node_update_no_meta_changes() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo");

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

            assert_eq!(
                leaf.ungreased_capabilities(),
                original_leaf.ungreased_capabilities()
            );

            assert_eq!(
                leaf.ungreased_extensions(),
                original_leaf.ungreased_extensions()
            );

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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_node_update_meta_changes() {
        let cipher_suite = TEST_CIPHER_SUITE;

        let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo");

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

        assert_eq!(leaf.ungreased_capabilities(), new_properties.capabilities);
        assert_eq!(leaf.ungreased_extensions(), new_properties.extensions);
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_node_commit_no_meta_changes() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo");

            let (mut leaf, leaf_secret) =
                get_test_node(cipher_suite, signing_identity.clone(), &secret, None, None).await;

            let original_leaf = leaf.clone();

            let new_secret = leaf
                .commit(
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

            assert_eq!(
                leaf.ungreased_capabilities(),
                original_leaf.ungreased_capabilities()
            );

            assert_eq!(
                leaf.ungreased_extensions(),
                original_leaf.ungreased_extensions()
            );

            assert_eq!(leaf.signing_identity, original_leaf.signing_identity);

            leaf.verify(
                &cipher_suite_provider,
                &signing_identity.signature_key,
                &(b"group".as_slice(), 0).into(),
            )
            .unwrap();
        }
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_node_commit_meta_changes() {
        let cipher_suite = TEST_CIPHER_SUITE;

        let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo");
        let (mut leaf, _) =
            get_test_node(cipher_suite, signing_identity, &secret, None, None).await;

        let new_properties = ConfigProperties {
            capabilities: get_test_capabilities(),
            extensions: get_test_extensions(),
        };

        // The new identity has a fresh public key
        let new_signing_identity = get_test_signing_identity(cipher_suite, b"foo").0;

        leaf.commit(
            &test_cipher_suite_provider(cipher_suite),
            b"group",
            0,
            new_properties.clone(),
            Some(new_signing_identity.clone()),
            &secret,
        )
        .unwrap();

        assert_eq!(leaf.capabilities, new_properties.capabilities);
        assert_eq!(leaf.extensions, new_properties.extensions);
        assert_eq!(leaf.signing_identity, new_signing_identity);
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn context_is_signed() {
        let provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (signing_identity, secret) = get_test_signing_identity(TEST_CIPHER_SUITE, b"foo");

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

        assert_matches!(res, Err(MlsError::InvalidSignature));

        let res = leaf.verify(
            &provider,
            &signing_identity.signature_key,
            &(b"bar".as_slice(), 0).into(),
        );

        assert_matches!(res, Err(MlsError::InvalidSignature));
    }
}
