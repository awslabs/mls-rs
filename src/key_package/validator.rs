use ferriscrypt::asym::ec_key::PublicKey;
use std::collections::HashSet;

use super::*;
use crate::client_config::CredentialValidator;
use crate::signing_identity::SigningIdentityError;
use crate::tree_kem::Lifetime;
use crate::{
    signer::SignatureError,
    tree_kem::leaf_node_validator::{
        LeafNodeValidationError, LeafNodeValidator, ValidationContext,
    },
};

#[derive(Debug, Error)]
pub enum KeyPackageValidationError {
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    LeafNodeValidationError(#[from] LeafNodeValidationError),
    #[error(transparent)]
    SigningIdentityError(#[from] SigningIdentityError),
    #[error("key lifetime not found")]
    MissingKeyLifetime,
    #[error("{0:?} is not within lifetime {1:?}")]
    InvalidKeyLifetime(MlsTime, Lifetime),
    #[error("required extension not found")]
    RequiredExtensionNotFound(ExtensionType),
    #[error("required proposal not found")]
    RequiredProposalNotFound(ProposalType),
    #[error("found cipher suite {0:?} expected {1:?}")]
    InvalidCipherSuite(CipherSuite, CipherSuite),
    #[error("found protocol version {0:?} expected {1:?}")]
    InvalidProtocolVersion(ProtocolVersion, ProtocolVersion),
    #[error("init key is not valid for cipher suite")]
    InvalidInitKey,
    #[error("init key can not be equal to leaf node public key")]
    InitLeafKeyEquality,
}

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum KeyPackageValidationOptions {
    SkipLifetimeCheck,
}

#[derive(Debug)]
pub struct KeyPackageValidator<'a, C: CredentialValidator> {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    leaf_node_validator: LeafNodeValidator<'a, C>,
}

impl<'a, C: CredentialValidator> KeyPackageValidator<'a, C> {
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
        credential_validator: C,
    ) -> KeyPackageValidator<C> {
        KeyPackageValidator {
            protocol_version,
            cipher_suite,
            leaf_node_validator: LeafNodeValidator::new(
                cipher_suite,
                required_capabilities,
                credential_validator,
            ),
        }
    }

    fn check_signature(&self, package: &KeyPackage) -> Result<(), KeyPackageValidationError> {
        // Verify that the signature on the KeyPackage is valid using the public key in the contained LeafNode's credential
        package
            .verify(
                &package
                    .leaf_node
                    .signing_identity
                    .public_key(self.cipher_suite)?,
                &(),
            )
            .map_err(Into::into)
    }

    pub fn check_if_valid(
        &self,
        package: &KeyPackage,
        options: HashSet<KeyPackageValidationOptions>,
    ) -> Result<(), KeyPackageValidationError> {
        self.validate_properties(package)?;

        self.leaf_node_validator
            .check_if_valid(&package.leaf_node, self.validation_context(options))
            .map_err(Into::into)
    }

    fn validate_properties(&self, package: &KeyPackage) -> Result<(), KeyPackageValidationError> {
        self.check_signature(package)?;

        // Verify that the protocol version matches
        if package.version != self.protocol_version {
            return Err(KeyPackageValidationError::InvalidProtocolVersion(
                package.version,
                self.protocol_version,
            ));
        }

        // Verify that the cipher suite matches
        if package.cipher_suite != self.cipher_suite {
            return Err(KeyPackageValidationError::InvalidCipherSuite(
                package.cipher_suite,
                self.cipher_suite,
            ));
        }

        // Verify that the public init key is valid
        PublicKey::from_uncompressed_bytes(
            package.hpke_init_key.as_ref(),
            self.cipher_suite.kem_type().curve(),
        )
        .map_err(|_| KeyPackageValidationError::InvalidInitKey)?;

        // Verify that the init key and the leaf node public key are different
        if package.hpke_init_key == package.leaf_node.public_key {
            return Err(KeyPackageValidationError::InitLeafKeyEquality);
        }

        Ok(())
    }

    fn validation_context(
        &self,
        options: HashSet<KeyPackageValidationOptions>,
    ) -> ValidationContext {
        let time_validation = if options.contains(&KeyPackageValidationOptions::SkipLifetimeCheck) {
            None
        } else {
            Some(MlsTime::now())
        };

        ValidationContext::Add(time_validation)
    }
}

#[cfg(test)]
mod tests {
    use crate::key_package::test_utils::test_key_package;
    use crate::key_package::test_utils::test_key_package_custom;
    use crate::signing_identity::test_utils::get_test_signing_identity;
    use crate::tree_kem::Capabilities;
    use assert_matches::assert_matches;
    use ferriscrypt::rand::SecureRng;

    use super::*;

    use crate::client_config::PassthroughCredentialValidator;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_standard_validation() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let test_package = test_key_package(protocol_version, cipher_suite);

            let validator = KeyPackageValidator::new(
                protocol_version,
                cipher_suite,
                None,
                PassthroughCredentialValidator::new(),
            );

            assert_matches!(
                validator.check_if_valid(&test_package, Default::default()),
                Ok(_)
            );
        }
    }

    fn invalid_signature_key_package(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> KeyPackage {
        let mut test_package = test_key_package(protocol_version, cipher_suite);
        test_package.signature = SecureRng::gen(32).unwrap();
        test_package
    }

    #[test]
    fn test_invalid_signature() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let test_package = invalid_signature_key_package(protocol_version, cipher_suite);
            let validator = KeyPackageValidator::new(
                protocol_version,
                cipher_suite,
                None,
                PassthroughCredentialValidator::new(),
            );

            assert_matches!(
                validator.check_if_valid(&test_package, Default::default()),
                Err(KeyPackageValidationError::SignatureError(_))
            );
        }
    }

    #[test]
    fn test_invalid_cipher_suite() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let version = ProtocolVersion::Mls10;
        let test_package = test_key_package(version, cipher_suite);

        let validator = KeyPackageValidator::new(
            version,
            CipherSuite::Curve25519ChaCha20,
            None,
            PassthroughCredentialValidator::new(),
        );

        assert_matches!(
            validator.check_if_valid(&test_package, Default::default()),
            Err(KeyPackageValidationError::InvalidCipherSuite(found, exp))
                if exp == CipherSuite::Curve25519ChaCha20 && found == cipher_suite
        );
    }

    fn test_init_key_manipulation<F>(
        cipher_suite: CipherSuite,
        protocol_version: ProtocolVersion,
        mut edit: F,
    ) -> KeyPackage
    where
        F: FnMut(&mut KeyPackage),
    {
        let (alternate_sining_id, secret) =
            get_test_signing_identity(cipher_suite, b"test".to_vec());

        let mut test_package =
            test_key_package_custom(protocol_version, cipher_suite, "test", |_| {
                let new_generator = KeyPackageGenerator {
                    protocol_version,
                    cipher_suite,
                    signing_identity: &alternate_sining_id,
                    signing_key: &secret,
                    credential_validator: &PassthroughCredentialValidator::new(),
                };

                new_generator
                    .generate(
                        Lifetime::years(1).unwrap(),
                        Capabilities::default(),
                        ExtensionList::default(),
                        ExtensionList::default(),
                    )
                    .unwrap()
            });

        edit(&mut test_package);
        test_package.sign(&secret, &()).unwrap();
        test_package
    }

    #[test]
    fn test_invalid_init_key() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let protocol_version = ProtocolVersion::Mls10;

        let key_package =
            test_init_key_manipulation(cipher_suite, protocol_version, |key_package| {
                key_package.hpke_init_key = HpkePublicKey::from(vec![42; 128]);
            });

        let validator = KeyPackageValidator::new(
            protocol_version,
            cipher_suite,
            None,
            PassthroughCredentialValidator::new(),
        );

        assert_matches!(
            validator.check_if_valid(&key_package, Default::default()),
            Err(KeyPackageValidationError::InvalidInitKey)
        );
    }

    #[test]
    fn test_matching_init_key() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let protocol_version = ProtocolVersion::Mls10;

        let key_package =
            test_init_key_manipulation(cipher_suite, protocol_version, |key_package| {
                key_package.hpke_init_key = key_package.leaf_node.public_key.clone();
            });

        let validator = KeyPackageValidator::new(
            protocol_version,
            cipher_suite,
            None,
            PassthroughCredentialValidator::new(),
        );

        assert_matches!(
            validator.check_if_valid(&key_package, Default::default()),
            Err(KeyPackageValidationError::InitLeafKeyEquality)
        );
    }

    fn invalid_expiration_leaf_node(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> KeyPackage {
        test_key_package_custom(protocol_version, cipher_suite, "foo", |generator| {
            generator
                .generate(
                    Lifetime {
                        not_before: 0,
                        not_after: 0,
                    },
                    Capabilities::default(),
                    ExtensionList::default(),
                    ExtensionList::default(),
                )
                .unwrap()
        })
    }

    #[test]
    fn test_expired() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let test_package = invalid_expiration_leaf_node(protocol_version, cipher_suite);

        let validator = KeyPackageValidator::new(
            protocol_version,
            cipher_suite,
            None,
            PassthroughCredentialValidator::new(),
        );

        assert_matches!(
            validator.check_if_valid(&test_package, Default::default()),
            Err(KeyPackageValidationError::LeafNodeValidationError(
                LeafNodeValidationError::InvalidLifetime(_, _)
            ))
        );
    }

    #[test]
    fn test_skip_expiration_check() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let test_package = invalid_expiration_leaf_node(protocol_version, cipher_suite);

        let validator = KeyPackageValidator::new(
            protocol_version,
            cipher_suite,
            None,
            PassthroughCredentialValidator::new(),
        );

        assert_matches!(
            validator.check_if_valid(
                &test_package,
                [KeyPackageValidationOptions::SkipLifetimeCheck].into(),
            ),
            Ok(_)
        );
    }

    #[test]
    fn test_required_capabilities_check() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let key_package =
            test_key_package_custom(protocol_version, cipher_suite, "test", |generator| {
                let mut capabilities = Capabilities::default();
                capabilities.extensions.push(42);

                generator
                    .generate(
                        Lifetime::years(1).unwrap(),
                        capabilities,
                        ExtensionList::default(),
                        ExtensionList::default(),
                    )
                    .unwrap()
            });

        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![42],
            proposals: vec![],
            credentials: vec![],
        };

        let validator = KeyPackageValidator::new(
            protocol_version,
            cipher_suite,
            Some(&required_capabilities),
            PassthroughCredentialValidator::new(),
        );

        assert_matches!(
            validator.check_if_valid(&key_package, Default::default()),
            Ok(_)
        );
    }

    #[test]
    fn test_required_capabilities_failure() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let key_package = test_key_package(protocol_version, cipher_suite);

        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![255],
            proposals: vec![],
            credentials: vec![],
        };

        let validator = KeyPackageValidator::new(
            protocol_version,
            cipher_suite,
            Some(&required_capabilities),
            PassthroughCredentialValidator::new(),
        );

        assert_matches!(
            validator.check_if_valid(&key_package, Default::default()),
            Err(KeyPackageValidationError::LeafNodeValidationError(_))
        );
    }

    #[test]
    fn test_leaf_node_validation_failure() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let key_package =
            test_key_package_custom(protocol_version, cipher_suite, "foo", |generator| {
                let mut package_gen = generator
                    .generate(
                        Lifetime::years(1).unwrap(),
                        Capabilities::default(),
                        ExtensionList::default(),
                        ExtensionList::default(),
                    )
                    .unwrap();

                package_gen.key_package.leaf_node.signature = SecureRng::gen(32).unwrap();
                generator.sign(&mut package_gen.key_package).unwrap();
                package_gen
            });

        let validator = KeyPackageValidator::new(
            protocol_version,
            cipher_suite,
            None,
            PassthroughCredentialValidator::new(),
        );

        assert_matches!(
            validator.check_if_valid(&key_package, Default::default()),
            Err(KeyPackageValidationError::LeafNodeValidationError(_))
        );
    }
}
