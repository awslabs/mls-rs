use crate::{
    signer::{SignatureError, Signer},
    tree_kem::leaf_node::LeafNodeError,
};

use super::*;
use ferriscrypt::asym::ec_key::{generate_keypair, EcKeyError};

#[derive(Debug, Error)]
pub enum KeyPackageGenerationError {
    #[error("internal signer error: {0:?}")]
    SignerError(Box<dyn std::error::Error>),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    LeafNodeError(#[from] LeafNodeError),
}

#[derive(Clone, Debug)]
pub struct KeyPackageGenerator<'a, S: Signer> {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub credential: &'a Credential,
    pub signing_key: &'a S,
}

#[derive(Clone, Debug)]
pub struct KeyPackageGeneration {
    pub key_package: KeyPackage,
    pub init_secret_key: HpkeSecretKey,
    pub leaf_node_secret_key: HpkeSecretKey,
}

impl<'a, S: Signer> KeyPackageGenerator<'a, S> {
    pub(super) fn sign(&self, package: &mut KeyPackage) -> Result<(), KeyPackageGenerationError> {
        package.sign(self.signing_key, &()).map_err(Into::into)
    }

    pub fn generate(
        &self,
        lifetime: LifetimeExt,
        capabilities: CapabilitiesExt,
        key_package_extensions: ExtensionList,
        leaf_node_extensions: ExtensionList,
    ) -> Result<KeyPackageGeneration, KeyPackageGenerationError> {
        let (public_init, secret_init) = generate_keypair(self.cipher_suite.kem_type().curve())?;

        let (leaf_node, leaf_node_secret) = LeafNode::generate(
            self.cipher_suite,
            self.credential.clone(),
            capabilities,
            leaf_node_extensions,
            self.signing_key,
            lifetime,
        )?;

        let mut package = KeyPackage {
            version: self.protocol_version,
            cipher_suite: self.cipher_suite,
            hpke_init_key: public_init.try_into()?,
            leaf_node,
            extensions: key_package_extensions,
            signature: vec![],
        };

        self.sign(&mut package)?;

        Ok(KeyPackageGeneration {
            key_package: package,
            init_secret_key: secret_init.try_into()?,
            leaf_node_secret_key: leaf_node_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::{Curve, PublicKey, SecretKey};
    use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

    use crate::{
        cipher_suite::CipherSuite,
        credential::{BasicCredential, Credential},
        extension::{CapabilitiesExt, ExtensionList, LifetimeExt, MlsExtension},
        key_package::{KeyPackageGenerationError, KeyPackageValidator},
        tree_kem::leaf_node::{LeafNodeError, LeafNodeSource},
        ProtocolVersion,
    };

    use super::KeyPackageGenerator;

    use crate::client_config::PassthroughCredentialValidator;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Debug, PartialEq, TlsSize, TlsSerialize, TlsDeserialize)]
    struct TestExt(u32);

    impl MlsExtension for TestExt {
        const IDENTIFIER: crate::extension::ExtensionType = 42;
    }

    fn test_credential(signing_key: &SecretKey) -> Credential {
        Credential::Basic(
            BasicCredential::new(b"test".to_vec(), signing_key.to_public().unwrap()).unwrap(),
        )
    }

    fn test_ext(val: u32) -> ExtensionList {
        let mut ext_list = ExtensionList::new();
        ext_list.set_extension(TestExt(val)).unwrap();
        ext_list
    }

    fn test_lifetime() -> LifetimeExt {
        LifetimeExt::years(1).unwrap()
    }

    #[test]
    fn test_key_generation() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let signing_key =
                SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

            let credential = test_credential(&signing_key);
            let key_package_ext = test_ext(32);
            let leaf_node_ext = test_ext(42);
            let lifetime = test_lifetime();

            let test_generator = KeyPackageGenerator {
                protocol_version,
                cipher_suite,
                credential: &credential,
                signing_key: &signing_key,
            };

            let mut capabilities = CapabilitiesExt::default();
            capabilities.extensions.push(42);
            capabilities.extensions.push(32);

            let generated = test_generator
                .generate(
                    lifetime.clone(),
                    capabilities.clone(),
                    key_package_ext.clone(),
                    leaf_node_ext.clone(),
                )
                .unwrap();

            assert_matches!(generated.key_package.leaf_node.leaf_node_source,
                            LeafNodeSource::Add(ref lt) if lt == &lifetime);

            assert_eq!(generated.key_package.leaf_node.capabilities, capabilities);
            assert_eq!(generated.key_package.leaf_node.extensions, leaf_node_ext);
            assert_eq!(generated.key_package.extensions, key_package_ext);

            assert_eq!(
                generated
                    .key_package
                    .leaf_node
                    .credential
                    .public_key()
                    .unwrap(),
                credential.public_key().unwrap()
            );

            assert_ne!(
                generated.key_package.hpke_init_key,
                generated.key_package.leaf_node.public_key
            );

            assert_eq!(generated.key_package.extensions, key_package_ext);
            assert_eq!(generated.key_package.cipher_suite, cipher_suite);
            assert_eq!(generated.key_package.version, protocol_version);

            let curve = test_generator.cipher_suite.kem_type().curve();

            let init_key_public = PublicKey::from_uncompressed_bytes(
                generated.key_package.hpke_init_key.as_ref(),
                curve,
            )
            .unwrap();

            let init_key_secret =
                SecretKey::from_bytes(generated.init_secret_key.as_ref(), curve).unwrap();

            assert_eq!(init_key_secret.curve(), curve);
            assert_eq!(init_key_public, init_key_secret.to_public().unwrap());

            let leaf_public = PublicKey::from_uncompressed_bytes(
                generated.key_package.leaf_node.public_key.as_ref(),
                curve,
            )
            .unwrap();

            let leaf_secret =
                SecretKey::from_bytes(generated.leaf_node_secret_key.as_ref(), curve).unwrap();

            assert_eq!(leaf_secret.curve(), curve);
            assert_eq!(leaf_public, leaf_secret.to_public().unwrap());

            let validator = KeyPackageValidator::new(
                protocol_version,
                cipher_suite,
                None,
                PassthroughCredentialValidator::new(),
            );

            validator
                .validate(generated.key_package, Default::default())
                .unwrap();
        }
    }

    #[test]
    fn test_credential_signature_mismatch() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let signing_key =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

        let credential = test_credential(
            &SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap(),
        );

        let test_generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite,
            credential: &credential,
            signing_key: &signing_key,
        };

        let generated = test_generator.generate(
            test_lifetime(),
            CapabilitiesExt::default(),
            ExtensionList::default(),
            ExtensionList::default(),
        );

        assert_matches!(
            generated,
            Err(KeyPackageGenerationError::LeafNodeError(
                LeafNodeError::CredentialSigningKeyMismatch
            ))
        );
    }

    #[test]
    fn test_randomness() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let signing_key =
                SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

            let credential = test_credential(&signing_key);

            let test_generator = KeyPackageGenerator {
                protocol_version,
                cipher_suite,
                credential: &credential,
                signing_key: &signing_key,
            };

            let first_key_package = test_generator
                .generate(
                    test_lifetime(),
                    CapabilitiesExt::default(),
                    ExtensionList::default(),
                    ExtensionList::default(),
                )
                .unwrap();

            (0..100).for_each(|_| {
                let next_key_package = test_generator
                    .generate(
                        test_lifetime(),
                        CapabilitiesExt::default(),
                        ExtensionList::default(),
                        ExtensionList::default(),
                    )
                    .unwrap();

                assert_ne!(
                    first_key_package.key_package.hpke_init_key,
                    next_key_package.key_package.hpke_init_key
                );

                assert_ne!(
                    first_key_package.key_package.leaf_node.public_key,
                    next_key_package.key_package.leaf_node.public_key
                );
            })
        }
    }
}
