use super::{parent_hash::ParentHash, Capabilities, Lifetime};
use crate::extension::LeafNodeExtension;
use crate::provider::crypto::{CipherSuiteProvider, HpkePublicKey, HpkeSecretKey};
use crate::provider::identity::IdentityProvider;
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::time::MlsTime;
use crate::{
    cipher_suite::CipherSuite,
    extension::ExtensionList,
    identity::CredentialError,
    identity::{SigningIdentity, SigningIdentityError},
    signer::{Signable, SignatureError, Signer},
};
use ferriscrypt::{asym::ec_key::EcKeyError, kdf::KdfError};
use serde_with::serde_as;
use thiserror::Error;
use tls_codec::{Serialize, Size, TlsByteSliceU32};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Debug, Error)]
pub enum LeafNodeError {
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    KdfError(#[from] KdfError),
    #[error(transparent)]
    SigningIdentityError(#[from] SigningIdentityError),
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
    pub extensions: ExtensionList<LeafNodeExtension>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ConfigProperties {
    pub capabilities: Capabilities,
    pub extensions: ExtensionList<LeafNodeExtension>,
}

impl LeafNode {
    fn check_signing_identity<S, C>(
        signing_identity: &SigningIdentity,
        signer: &S,
        identity_provider: &C,
        cipher_suite: CipherSuite,
    ) -> Result<(), LeafNodeError>
    where
        S: Signer,
        C: IdentityProvider,
    {
        let signer_public = signer
            .public_key()
            .map_err(|e| LeafNodeError::SignerError(e.into()))?;

        if signer_public.to_uncompressed_bytes()? != *signing_identity.signature_key {
            return Err(LeafNodeError::InvalidSignerPublicKey);
        }

        identity_provider
            .validate(signing_identity, cipher_suite, Some(MlsTime::now()))
            .map_err(|e| LeafNodeError::IdentityProviderError(e.into()))
    }

    pub fn generate<S, IP, CP>(
        cipher_suite_provider: &CP,
        properties: ConfigProperties,
        signing_identity: SigningIdentity,
        signer: &S,
        lifetime: Lifetime,
        identity_provider: &IP,
    ) -> Result<(Self, HpkeSecretKey), LeafNodeError>
    where
        S: Signer,
        IP: IdentityProvider,
        CP: CipherSuiteProvider,
    {
        LeafNode::check_signing_identity(
            &signing_identity,
            signer,
            identity_provider,
            cipher_suite_provider.cipher_suite(),
        )?;

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

        leaf_node.sign(signer, &LeafNodeSigningContext::default())?;

        Ok((leaf_node, secret_key))
    }

    pub fn update<S: Signer, P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        group_id: &[u8],
        leaf_index: u32,
        new_properties: ConfigProperties,
        signing_identity: Option<SigningIdentity>,
        signer: &S,
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

        self.sign(signer, &(group_id, leaf_index).into())?;

        Ok(secret)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit<S: Signer, P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        group_id: &[u8],
        leaf_index: u32,
        new_properties: ConfigProperties,
        signing_identity: Option<SigningIdentity>,
        signer: &S,
        parent_hash: ParentHash,
    ) -> Result<HpkeSecretKey, LeafNodeError> {
        let (secret, public) = cipher_suite_provider
            .kem_generate()
            .map_err(|e| LeafNodeError::CipherSuiteProviderError(e.into()))?;

        self.public_key = public;
        self.capabilities = new_properties.capabilities;
        self.extensions = new_properties.extensions;
        self.leaf_node_source = LeafNodeSource::Commit(parent_hash);

        if let Some(signing_identity) = signing_identity {
            self.signing_identity = signing_identity;
        }

        self.sign(signer, &(group_id, leaf_index).into())?;

        Ok(secret)
    }
}

#[derive(Debug)]
struct LeafNodeTBS<'a> {
    public_key: &'a HpkePublicKey,
    signing_identity: &'a SigningIdentity,
    capabilities: &'a Capabilities,
    leaf_node_source: &'a LeafNodeSource,
    extensions: &'a ExtensionList<LeafNodeExtension>,
    group_id: Option<&'a [u8]>,
    leaf_index: Option<u32>,
}

impl<'a> Size for LeafNodeTBS<'a> {
    fn tls_serialized_len(&self) -> usize {
        TlsByteSliceU32(self.public_key.as_ref()).tls_serialized_len()
            + self.signing_identity.tls_serialized_len()
            + self.capabilities.tls_serialized_len()
            + self.leaf_node_source.tls_serialized_len()
            + self.extensions.tls_serialized_len()
            + self
                .group_id
                .map_or(0, |group_id| TlsByteSliceU32(group_id).tls_serialized_len())
            + self.leaf_index.map_or(0, |i| i.tls_serialized_len())
    }
}

impl<'a> Serialize for LeafNodeTBS<'a> {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let res = TlsByteSliceU32(self.public_key.as_ref()).tls_serialize(writer)?
            + self.signing_identity.tls_serialize(writer)?
            + self.capabilities.tls_serialize(writer)?
            + self.leaf_node_source.tls_serialize(writer)?
            + self.extensions.tls_serialize(writer)?
            + self.group_id.map_or(Ok(0), |group_id| {
                TlsByteSliceU32(group_id).tls_serialize(writer)
            })?
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
pub mod test_utils {
    use ferriscrypt::asym::ec_key::SecretKey;

    use crate::{
        cipher_suite::CipherSuite,
        extension::{ApplicationIdExt, MlsExtension},
        identity::test_utils::get_test_signing_identity,
        identity::CREDENTIAL_TYPE_BASIC,
        provider::{
            crypto::test_utils::test_cipher_suite_provider, identity::BasicIdentityProvider,
        },
    };

    use super::*;

    pub fn get_test_node(
        cipher_suite: CipherSuite,
        signing_identity: SigningIdentity,
        secret: &SecretKey,
        capabilities: Option<Capabilities>,
        extensions: Option<ExtensionList<LeafNodeExtension>>,
    ) -> (LeafNode, HpkeSecretKey) {
        get_test_node_with_lifetime(
            cipher_suite,
            signing_identity,
            secret,
            capabilities.unwrap_or_else(get_test_capabilities),
            extensions.unwrap_or_default(),
            Lifetime::years(1).unwrap(),
        )
    }

    pub fn get_test_node_with_lifetime(
        cipher_suite: CipherSuite,
        signing_identity: SigningIdentity,
        secret: &SecretKey,
        capabilities: Capabilities,
        extensions: ExtensionList<LeafNodeExtension>,
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
        .unwrap()
    }

    pub fn get_basic_test_node(cipher_suite: CipherSuite, id: &str) -> LeafNode {
        get_basic_test_node_sig_key(cipher_suite, id).0
    }

    pub fn default_properties() -> ConfigProperties {
        ConfigProperties {
            capabilities: get_test_capabilities(),
            extensions: Default::default(),
        }
    }

    pub fn get_basic_test_node_sig_key(
        cipher_suite: CipherSuite,
        id: &str,
    ) -> (LeafNode, HpkeSecretKey, SecretKey) {
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
        .map(|(leaf, hpke_secret_key)| (leaf, hpke_secret_key, signature_key))
        .unwrap()
    }

    pub fn get_test_extensions() -> ExtensionList<LeafNodeExtension> {
        let mut extension_list = ExtensionList::new();

        extension_list
            .set_extension(ApplicationIdExt {
                identifier: b"identifier".to_vec(),
            })
            .unwrap();

        extension_list
    }

    pub fn get_test_capabilities() -> Capabilities {
        let mut capabilities = Capabilities {
            credentials: vec![CREDENTIAL_TYPE_BASIC],
            ..Default::default()
        };
        capabilities.extensions.push(ApplicationIdExt::IDENTIFIER);
        capabilities
    }

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

    use crate::cipher_suite::CipherSuite;
    use crate::identity::test_utils::get_test_signing_identity;
    use crate::provider::crypto::test_utils::test_cipher_suite_provider;
    use crate::provider::identity::BasicIdentityProvider;
    use crate::tree_kem::leaf_node_validator::test_utils::FailureIdentityProvider;
    use assert_matches::assert_matches;

    use ferriscrypt::asym::ec_key::SecretKey;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_node_generation() {
        let capabilities = get_test_capabilities();
        let extensions = get_test_extensions();
        let lifetime = Lifetime::years(1).unwrap();

        for cipher_suite in CipherSuite::all() {
            let (signing_identity, secret) =
                get_test_signing_identity(cipher_suite, b"foo".to_vec());

            let (leaf_node, secret_key) = get_test_node_with_lifetime(
                cipher_suite,
                signing_identity.clone(),
                &secret,
                capabilities.clone(),
                extensions.clone(),
                lifetime.clone(),
            );

            assert_eq!(leaf_node.capabilities, capabilities);
            assert_eq!(leaf_node.extensions, extensions);
            assert_eq!(leaf_node.signing_identity, signing_identity);

            assert_matches!(
                &leaf_node.leaf_node_source,
                LeafNodeSource::KeyPackage(lt) if lt == &lifetime,
                "Expected {:?}, got {:?}", LeafNodeSource::KeyPackage(lifetime),
                leaf_node.leaf_node_source
            );

            let curve = cipher_suite.kem_type().curve();

            leaf_node
                .verify(
                    &signing_identity.public_key(cipher_suite).unwrap(),
                    &LeafNodeSigningContext::default(),
                )
                .unwrap();

            let expected_public = SecretKey::from_bytes(secret_key.as_ref(), curve)
                .unwrap()
                .to_public()
                .unwrap();

            assert_eq!(
                leaf_node.public_key,
                expected_public.to_uncompressed_bytes().unwrap().into()
            );
        }
    }

    #[test]
    fn test_credential_signature_mismatch() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (test_signing_identity, _) = get_test_signing_identity(cipher_suite, b"foo".to_vec());

        let incorrect_secret = SecretKey::generate(
            test_signing_identity
                .public_key(cipher_suite)
                .unwrap()
                .curve(),
        )
        .unwrap();

        let res = LeafNode::generate(
            &test_cipher_suite_provider(cipher_suite),
            default_properties(),
            test_signing_identity,
            &incorrect_secret,
            Lifetime::years(1).unwrap(),
            &BasicIdentityProvider::new(),
        );

        assert_matches!(res, Err(LeafNodeError::InvalidSignerPublicKey));
    }

    #[test]
    fn test_credential_invalid_for_ciphersuite() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (test_signing_identity, signer) =
            get_test_signing_identity(CipherSuite::P256Aes128, b"foo".to_vec());

        let res = LeafNode::generate(
            &test_cipher_suite_provider(cipher_suite),
            default_properties(),
            test_signing_identity,
            &signer,
            Lifetime::years(1).unwrap(),
            &BasicIdentityProvider::new(),
        );

        assert_matches!(res, Err(LeafNodeError::IdentityProviderError(_)));
    }

    #[test]
    fn invalid_credential_for_application() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (test_signing_identity, signer) =
            get_test_signing_identity(cipher_suite, b"foo".to_vec());

        let res = LeafNode::generate(
            &test_cipher_suite_provider(cipher_suite),
            default_properties(),
            test_signing_identity,
            &signer,
            Lifetime::years(1).unwrap(),
            &FailureIdentityProvider,
        );

        assert_matches!(res, Err(LeafNodeError::IdentityProviderError(_)));
    }

    #[test]
    fn test_node_generation_randomness() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo".to_vec());

        let (first_leaf, first_secret) =
            get_test_node(cipher_suite, signing_identity.clone(), &secret, None, None);

        for _ in 0..100 {
            let (next_leaf, next_secret) =
                get_test_node(cipher_suite, signing_identity.clone(), &secret, None, None);

            assert_ne!(first_secret, next_secret);
            assert_ne!(first_leaf.public_key, next_leaf.public_key);
        }
    }

    #[test]
    fn test_node_update_no_meta_changes() {
        for cipher_suite in CipherSuite::all() {
            let (signing_identity, secret) =
                get_test_signing_identity(cipher_suite, b"foo".to_vec());

            let (mut leaf, leaf_secret) =
                get_test_node(cipher_suite, signing_identity.clone(), &secret, None, None);

            let original_leaf = leaf.clone();

            let new_secret = leaf
                .update(
                    &test_cipher_suite_provider(cipher_suite),
                    b"group",
                    0,
                    default_properties(),
                    None,
                    &secret,
                )
                .unwrap();

            assert_ne!(new_secret, leaf_secret);
            assert_ne!(original_leaf.public_key, leaf.public_key);

            let curve = cipher_suite.kem_type().curve();

            let expected_public = SecretKey::from_bytes(new_secret.as_ref(), curve)
                .unwrap()
                .to_public()
                .unwrap();

            assert_eq!(
                leaf.public_key,
                expected_public.to_uncompressed_bytes().unwrap().into()
            );

            assert_eq!(leaf.capabilities, original_leaf.capabilities);
            assert_eq!(leaf.extensions, original_leaf.extensions);
            assert_eq!(leaf.signing_identity, original_leaf.signing_identity);
            assert_matches!(&leaf.leaf_node_source, LeafNodeSource::Update);

            leaf.verify(
                &signing_identity.public_key(cipher_suite).unwrap(),
                &(b"group".as_slice(), 0).into(),
            )
            .unwrap();
        }
    }

    #[test]
    fn test_node_update_meta_changes() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo".to_vec());

        let new_properties = ConfigProperties {
            capabilities: get_test_capabilities(),
            extensions: get_test_extensions(),
        };

        let (mut leaf, _) = get_test_node(cipher_suite, signing_identity, &secret, None, None);

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

    #[test]
    fn test_node_commit_no_meta_changes() {
        for cipher_suite in CipherSuite::all() {
            let (signing_identity, secret) =
                get_test_signing_identity(cipher_suite, b"foo".to_vec());

            let (mut leaf, leaf_secret) =
                get_test_node(cipher_suite, signing_identity.clone(), &secret, None, None);

            let original_leaf = leaf.clone();

            let test_parent_hash = ParentHash::from(vec![42u8; 32]);

            let new_secret = leaf
                .commit(
                    &test_cipher_suite_provider(cipher_suite),
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

            let curve = cipher_suite.kem_type().curve();

            let expected_public = SecretKey::from_bytes(new_secret.as_ref(), curve)
                .unwrap()
                .to_public()
                .unwrap();

            assert_eq!(
                leaf.public_key,
                expected_public.to_uncompressed_bytes().unwrap().into()
            );

            assert_eq!(leaf.capabilities, original_leaf.capabilities);
            assert_eq!(leaf.extensions, original_leaf.extensions);
            assert_eq!(leaf.signing_identity, original_leaf.signing_identity);
            assert_matches!(&leaf.leaf_node_source, LeafNodeSource::Commit(parent_hash) if parent_hash == &test_parent_hash);

            leaf.verify(
                &signing_identity.public_key(cipher_suite).unwrap(),
                &(b"group".as_slice(), 0).into(),
            )
            .unwrap();
        }
    }

    #[test]
    fn test_node_commit_meta_changes() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo".to_vec());
        let (mut leaf, _) = get_test_node(cipher_suite, signing_identity, &secret, None, None);

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

    #[test]
    fn context_is_signed() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (signing_identity, secret) = get_test_signing_identity(cipher_suite, b"foo".to_vec());
        let public = signing_identity.public_key(cipher_suite).unwrap();
        let (mut leaf, _) = get_test_node(cipher_suite, signing_identity, &secret, None, None);

        leaf.sign(&secret, &(b"foo".as_slice(), 0).into()).unwrap();

        let res = leaf.verify(&public, &(b"foo".as_slice(), 1).into());
        assert_matches!(res, Err(SignatureError::SignatureValidationFailed(_)));

        let res = leaf.verify(&public, &(b"bar".as_slice(), 0).into());
        assert_matches!(res, Err(SignatureError::SignatureValidationFailed(_)));
    }
}
