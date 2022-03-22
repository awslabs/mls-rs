use super::parent_hash::ParentHash;
use crate::{
    credential::{Credential, CredentialError},
    extension::{CapabilitiesExt, ExtensionList, LifetimeExt},
    signer::{Signable, SignatureError, Signer},
};
use ferriscrypt::{
    asym::ec_key::{generate_keypair, EcKeyError, PublicKey, SecretKey},
    hpke::kem::{HpkePublicKey, HpkeSecretKey},
    kdf::KdfError,
};
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
    #[error("parent hash error: {0}")]
    ParentHashError(#[source] Box<dyn std::error::Error>),
}

#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize, PartialEq)]
#[repr(u8)]
pub enum LeafNodeSource {
    #[tls_codec(discriminant = 1)]
    Add(LifetimeExt),
    Update,
    Commit(ParentHash),
}

#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize, PartialEq)]
#[non_exhaustive]
pub struct LeafNode {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub public_key: HpkePublicKey,
    pub credential: Credential,
    pub capabilities: CapabilitiesExt,
    pub leaf_node_source: LeafNodeSource,
    pub extensions: ExtensionList,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub signature: Vec<u8>,
}

impl LeafNode {
    pub fn generate<S: Signer>(
        credential: Credential,
        capabilities: CapabilitiesExt,
        extensions: ExtensionList,
        signer: &S,
        lifetime: LifetimeExt,
    ) -> Result<(Self, HpkeSecretKey), LeafNodeError> {
        let (public, secret) = generate_keypair(credential.public_key()?.curve())?;

        let mut leaf_node = LeafNode {
            public_key: public.try_into()?,
            credential,
            capabilities,
            leaf_node_source: LeafNodeSource::Add(lifetime),
            extensions,
            signature: Default::default(),
        };

        leaf_node.sign(signer, &None)?;

        Ok((leaf_node, secret.try_into()?))
    }

    fn update_keypair<S: Signer>(
        &mut self,
        key_pair: (PublicKey, SecretKey),
        group_id: &[u8],
        capabilities: Option<CapabilitiesExt>,
        extensions: Option<ExtensionList>,
        leaf_node_source: LeafNodeSource,
        signer: &S,
    ) -> Result<HpkeSecretKey, LeafNodeError> {
        let (public, secret) = key_pair;

        self.public_key = public.try_into()?;

        if let Some(capabilities) = capabilities {
            self.capabilities = capabilities;
        }

        if let Some(extensions) = extensions {
            self.extensions = extensions;
        }

        self.leaf_node_source = leaf_node_source;
        self.sign(signer, &Some(group_id))?;

        Ok(secret.try_into()?)
    }

    pub fn update<S: Signer>(
        &mut self,
        group_id: &[u8],
        capabilities: Option<CapabilitiesExt>,
        extensions: Option<ExtensionList>,
        signer: &S,
    ) -> Result<HpkeSecretKey, LeafNodeError> {
        let keypair = generate_keypair(self.credential.public_key()?.curve())?;

        self.update_keypair(
            keypair,
            group_id,
            capabilities,
            extensions,
            LeafNodeSource::Update,
            signer,
        )
    }

    pub fn commit<S: Signer>(
        &mut self,
        group_id: &[u8],
        capabilities: Option<CapabilitiesExt>,
        extensions: Option<ExtensionList>,
        signer: &S,
        parent_hash: impl Fn(HpkePublicKey) -> Result<ParentHash, Box<dyn std::error::Error>>,
    ) -> Result<HpkeSecretKey, LeafNodeError> {
        let key_pair = generate_keypair(self.credential.public_key()?.curve())?;
        let hpke_public = key_pair.0.clone().try_into()?;

        let parent_hash = parent_hash(hpke_public).map_err(LeafNodeError::ParentHashError)?;

        self.update_keypair(
            key_pair,
            group_id,
            capabilities,
            extensions,
            LeafNodeSource::Commit(parent_hash),
            signer,
        )
    }
}

#[derive(Debug)]
struct LeafNodeTBS<'a> {
    public_key: &'a HpkePublicKey,
    credential: &'a Credential,
    capabilities: &'a CapabilitiesExt,
    leaf_node_source: &'a LeafNodeSource,
    extensions: &'a ExtensionList,
    group_id: Option<&'a [u8]>,
}

impl<'a> Size for LeafNodeTBS<'a> {
    fn tls_serialized_len(&self) -> usize {
        TlsByteSliceU32(self.public_key.as_ref()).tls_serialized_len()
            + self.credential.tls_serialized_len()
            + self.capabilities.tls_serialized_len()
            + self.leaf_node_source.tls_serialized_len()
            + self.extensions.tls_serialized_len()
            + self
                .group_id
                .map_or(0, |group_id| TlsByteSliceU32(group_id).tls_serialized_len())
    }
}

impl<'a> Serialize for LeafNodeTBS<'a> {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let res = TlsByteSliceU32(self.public_key.as_ref()).tls_serialize(writer)?
            + self.credential.tls_serialize(writer)?
            + self.capabilities.tls_serialize(writer)?
            + self.leaf_node_source.tls_serialize(writer)?
            + self.extensions.tls_serialize(writer)?
            + self.group_id.map_or(Ok(0), |group_id| {
                TlsByteSliceU32(group_id).tls_serialize(writer)
            })?;

        Ok(res)
    }
}

impl<'a> Signable<'a> for LeafNode {
    const SIGN_LABEL: &'static str = "LeafNodeTBS";

    type SigningContext = Option<&'a [u8]>;

    fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn signable_content(
        &self,
        context: &Self::SigningContext,
    ) -> Result<Vec<u8>, tls_codec::Error> {
        LeafNodeTBS {
            public_key: &self.public_key,
            credential: &self.credential,
            capabilities: &self.capabilities,
            leaf_node_source: &self.leaf_node_source,
            extensions: &self.extensions,
            group_id: *context,
        }
        .tls_serialize_detached()
    }

    fn write_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature
    }
}

#[cfg(test)]
pub mod test_util {
    use crate::extension::{ExternalKeyIdExt, MlsExtension};

    use super::*;

    pub fn get_test_node(
        credential: Credential,
        secret: &SecretKey,
        capabilities: Option<CapabilitiesExt>,
        extensions: Option<ExtensionList>,
    ) -> (LeafNode, HpkeSecretKey) {
        LeafNode::generate(
            credential,
            capabilities.unwrap_or_default(),
            extensions.unwrap_or_default(),
            secret,
            LifetimeExt::years(1).unwrap(),
        )
        .unwrap()
    }

    pub fn get_test_extensions() -> ExtensionList {
        let mut extension_list = ExtensionList::new();

        extension_list
            .set_extension(ExternalKeyIdExt {
                identifier: b"identifier".to_vec(),
            })
            .unwrap();

        extension_list
    }

    pub fn get_test_capabilities() -> CapabilitiesExt {
        let mut capabilities = CapabilitiesExt::default();
        capabilities.extensions.push(ExternalKeyIdExt::IDENTIFIER);
        capabilities
    }
}

#[cfg(test)]
mod test {
    use super::test_util::*;
    use super::*;

    use crate::{cipher_suite::CipherSuite, client::test_util::get_test_credential};
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::Curve;

    #[test]
    fn test_node_generation() {
        let capabilities = get_test_capabilities();
        let extensions = get_test_extensions();
        let lifetime = LifetimeExt::years(1).unwrap();

        for cipher_suite in CipherSuite::all() {
            let (credential, secret) = get_test_credential(cipher_suite, b"foo".to_vec());

            let (leaf_node, secret_key) = get_test_node(
                credential.clone(),
                &secret,
                Some(capabilities.clone()),
                Some(extensions.clone()),
            );

            assert_eq!(leaf_node.capabilities, capabilities);
            assert_eq!(leaf_node.extensions, extensions);
            assert_eq!(leaf_node.credential, credential);
            assert_matches!(&leaf_node.leaf_node_source, LeafNodeSource::Add(lt) if lt == &lifetime);

            leaf_node
                .verify(&credential.public_key().unwrap(), &None)
                .unwrap();

            let expected_public = SecretKey::from_bytes(
                secret_key.as_ref(),
                Curve::from(cipher_suite.signature_scheme()),
            )
            .unwrap()
            .to_public()
            .unwrap();

            assert_eq!(
                HpkePublicKey::try_from(expected_public).unwrap(),
                leaf_node.public_key
            );
        }
    }

    #[test]
    fn test_node_generation_randomness() {
        let (credential, secret) =
            get_test_credential(CipherSuite::Curve25519ChaCha20V1, b"foo".to_vec());

        let (first_leaf, first_secret) = get_test_node(credential.clone(), &secret, None, None);

        for _ in 0..100 {
            let (next_leaf, next_secret) = get_test_node(credential.clone(), &secret, None, None);
            assert_ne!(first_secret, next_secret);
            assert_ne!(first_leaf.public_key, next_leaf.public_key);
        }
    }

    #[test]
    fn test_node_update_no_meta_changes() {
        for cipher_suite in CipherSuite::all() {
            let (credential, secret) = get_test_credential(cipher_suite, b"foo".to_vec());

            let (mut leaf, leaf_secret) = get_test_node(credential.clone(), &secret, None, None);
            let original_leaf = leaf.clone();
            let new_secret = leaf.update(b"group", None, None, &secret).unwrap();

            assert_ne!(new_secret, leaf_secret);
            assert_ne!(original_leaf.public_key, leaf.public_key);
            assert_eq!(leaf.capabilities, original_leaf.capabilities);
            assert_eq!(leaf.extensions, original_leaf.extensions);
            assert_eq!(leaf.credential, original_leaf.credential);
            assert_matches!(&leaf.leaf_node_source, LeafNodeSource::Update);

            leaf.verify(&credential.public_key().unwrap(), &Some(b"group"))
                .unwrap();
        }
    }

    #[test]
    fn test_node_update_meta_changes() {
        let (credential, secret) =
            get_test_credential(CipherSuite::Curve25519Aes128V1, b"foo".to_vec());

        let (mut leaf, _) = get_test_node(credential, &secret, None, None);
        let new_capabilities = get_test_capabilities();
        let new_extensions = get_test_extensions();

        leaf.update(
            b"group",
            Some(new_capabilities.clone()),
            Some(new_extensions.clone()),
            &secret,
        )
        .unwrap();

        assert_eq!(leaf.capabilities, new_capabilities);
        assert_eq!(leaf.extensions, new_extensions);
    }

    #[test]
    fn test_node_commit_no_meta_changes() {
        for cipher_suite in CipherSuite::all() {
            let (credential, secret) = get_test_credential(cipher_suite, b"foo".to_vec());

            let (mut leaf, leaf_secret) = get_test_node(credential.clone(), &secret, None, None);
            let original_leaf = leaf.clone();

            let test_parent_hash = ParentHash::from(vec![42u8; 32]);

            let new_secret = leaf
                .commit(b"group", None, None, &secret, |key| {
                    assert_ne!(original_leaf.public_key, key);
                    Ok(test_parent_hash.clone())
                })
                .unwrap();

            assert_ne!(new_secret, leaf_secret);
            assert_ne!(original_leaf.public_key, leaf.public_key);
            assert_eq!(leaf.capabilities, original_leaf.capabilities);
            assert_eq!(leaf.extensions, original_leaf.extensions);
            assert_eq!(leaf.credential, original_leaf.credential);
            assert_matches!(&leaf.leaf_node_source, LeafNodeSource::Commit(parent_hash) if parent_hash == &test_parent_hash);

            leaf.verify(&credential.public_key().unwrap(), &Some(b"group"))
                .unwrap();
        }
    }

    #[test]
    fn test_node_commit_parent_hash_error() {
        let (credential, secret) =
            get_test_credential(CipherSuite::Curve25519Aes128V1, b"foo".to_vec());

        let (mut leaf, _) = get_test_node(credential, &secret, None, None);

        let res = leaf.commit(b"group", None, None, &secret, |_| {
            Err(String::from("test").into())
        });

        assert!(res.is_err());
    }

    #[test]
    fn test_node_commit_meta_changes() {
        let (credential, secret) =
            get_test_credential(CipherSuite::Curve25519Aes128V1, b"foo".to_vec());

        let (mut leaf, _) = get_test_node(credential, &secret, None, None);
        let new_capabilities = get_test_capabilities();
        let new_extensions = get_test_extensions();
        let test_parent_hash = ParentHash::from(vec![42u8; 32]);

        leaf.commit(
            b"group",
            Some(new_capabilities.clone()),
            Some(new_extensions.clone()),
            &secret,
            |_| Ok(test_parent_hash.clone()),
        )
        .unwrap();

        assert_eq!(leaf.capabilities, new_capabilities);
        assert_eq!(leaf.extensions, new_extensions);
    }
}
