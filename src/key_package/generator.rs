use crate::tree_kem::leaf_secret::{LeafSecret, LeafSecretError};

use super::*;
use ferriscrypt::Signer;

#[derive(Debug, Error)]
pub enum KeyPackageGenerationError {
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    LeafSecretError(#[from] LeafSecretError),
    #[error(transparent)]
    KeyPackageValidationError(#[from] KeyPackageValidationError),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error("the provided signing key does not correspond to the provided credential")]
    CredentialSigningKeyMismatch,
}

#[derive(Clone, Debug)]
pub struct KeyPackageGenerator<'a> {
    pub cipher_suite: CipherSuite,
    pub credential: &'a Credential,
    pub extensions: &'a ExtensionList,
    pub signing_key: &'a SecretKey,
}

#[derive(Clone, Debug)]
pub struct KeyPackageGeneration {
    pub key_package: ValidatedKeyPackage,
    pub leaf_secret: LeafSecret,
    pub secret_key: HpkeSecretKey,
}

impl<'a> KeyPackageGenerator<'a> {
    pub fn sign(&self, package: &mut KeyPackage) -> Result<(), KeyPackageGenerationError> {
        package.signature = self.signing_key.sign(&package.to_signable_bytes()?)?;
        Ok(())
    }

    pub fn generate(
        &self,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
    ) -> Result<KeyPackageGeneration, KeyPackageGenerationError> {
        if self.credential.public_key()? != self.signing_key.to_public()? {
            return Err(KeyPackageGenerationError::CredentialSigningKeyMismatch);
        }

        let leaf_secret = LeafSecret::generate(self.cipher_suite)?;
        let (hpke_sec, hpke_pub) = leaf_secret.as_leaf_key_pair()?;

        let package = KeyPackage {
            version: self.cipher_suite.protocol_version(),
            cipher_suite: self.cipher_suite,
            hpke_init_key: hpke_pub,
            credential: self.credential.clone(),
            extensions: self.extensions.clone(),
            signature: vec![],
        };

        let validator = KeyPackageValidator {
            cipher_suite: self.cipher_suite,
            required_capabilities,
            options: [KeyPackageValidationOptions::SkipSignatureCheck].into(),
        };

        let mut package = validator.validate(package)?;

        self.sign(&mut package)?;

        Ok(KeyPackageGeneration {
            key_package: package,
            leaf_secret,
            secret_key: hpke_sec,
        })
    }
}

#[cfg(test)]
mod test {
    use std::time::SystemTime;

    use ferriscrypt::asym::ec_key::{Curve, SecretKey};

    use crate::{
        cipher_suite::{CipherSuite, ProtocolVersion},
        credential::{BasicCredential, Credential},
        extension::{
            CapabilitiesExt, ExtensionList, LifetimeExt, MlsExtension, RequiredCapabilitiesExt,
        },
        key_package::{KeyPackageGenerationError, KeyPackageValidator},
    };

    use super::KeyPackageGenerator;

    fn test_extensions() -> ExtensionList {
        let mut extensions = ExtensionList::new();
        extensions
            .set_extension(LifetimeExt::days(1, SystemTime::now()).unwrap())
            .unwrap();

        extensions
            .set_extension(CapabilitiesExt::default())
            .unwrap();

        extensions
    }

    fn test_credential(signing_key: &SecretKey) -> Credential {
        Credential::Basic(
            BasicCredential::new(b"test".to_vec(), signing_key.to_public().unwrap()).unwrap(),
        )
    }

    #[test]
    fn test_key_generation() {
        for cipher_suite in CipherSuite::all() {
            let signing_key =
                SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

            let extensions = test_extensions();
            let credential = test_credential(&signing_key);

            let test_generator = KeyPackageGenerator {
                cipher_suite,
                credential: &credential,
                extensions: &extensions,
                signing_key: &signing_key,
            };

            let generated = test_generator.generate(None).unwrap();

            assert_eq!(
                generated.key_package.credential.public_key().unwrap(),
                credential.public_key().unwrap()
            );
            assert_eq!(generated.key_package.extensions, extensions);
            assert_eq!(generated.key_package.cipher_suite, cipher_suite);
            assert_eq!(generated.key_package.version, ProtocolVersion::Mls10);

            assert_eq!(
                generated.leaf_secret.len(),
                cipher_suite.kem_type().sk_len()
            );

            let (secret_key, public_key) = generated.leaf_secret.as_leaf_key_pair().unwrap();
            assert_eq!(generated.secret_key, secret_key);
            assert_eq!(generated.key_package.hpke_init_key, public_key);

            let validator = KeyPackageValidator {
                cipher_suite,
                required_capabilities: None,
                options: Default::default(),
            };

            validator.validate(generated.key_package.into()).unwrap();
        }
    }

    fn test_key_generation_missing_ext(ext: u16) {
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let signing_key =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

        let mut extensions = test_extensions();
        extensions.retain(|e| e.extension_type != ext);

        let credential = test_credential(&signing_key);

        let test_generator = KeyPackageGenerator {
            cipher_suite,
            credential: &credential,
            extensions: &extensions,
            signing_key: &signing_key,
        };

        let generated = test_generator.generate(None);
        assert!(matches!(
            generated,
            Err(KeyPackageGenerationError::KeyPackageValidationError(_))
        ));
    }

    #[test]
    fn test_key_generation_missing_capabilities() {
        test_key_generation_missing_ext(CapabilitiesExt::IDENTIFIER);
    }

    #[test]
    fn test_key_generation_missing_lifetime() {
        test_key_generation_missing_ext(LifetimeExt::IDENTIFIER);
    }

    #[test]
    fn test_required_capabilities_requirements() {
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let signing_key =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

        let extensions = test_extensions();
        let credential = test_credential(&signing_key);

        let test_generator = KeyPackageGenerator {
            cipher_suite,
            credential: &credential,
            extensions: &extensions,
            signing_key: &signing_key,
        };

        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![255],
            proposals: vec![],
        };

        let generated = test_generator.generate(Some(&required_capabilities));
        assert!(matches!(
            generated,
            Err(KeyPackageGenerationError::KeyPackageValidationError(_))
        ));
    }

    #[test]
    fn test_credential_signature_mismatch() {
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let signing_key =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

        let extensions = test_extensions();
        let credential = test_credential(
            &SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap(),
        );

        let test_generator = KeyPackageGenerator {
            cipher_suite,
            credential: &credential,
            extensions: &extensions,
            signing_key: &signing_key,
        };

        let generated = test_generator.generate(None);
        assert!(matches!(
            generated,
            Err(KeyPackageGenerationError::CredentialSigningKeyMismatch)
        ));
    }

    #[test]
    fn test_randomness() {
        for cipher_suite in CipherSuite::all() {
            let signing_key =
                SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

            let extensions = test_extensions();
            let credential = test_credential(&signing_key);

            let test_generator = KeyPackageGenerator {
                cipher_suite,
                credential: &credential,
                extensions: &extensions,
                signing_key: &signing_key,
            };

            let first_key_package = test_generator.generate(None).unwrap();

            (0..100).for_each(|_| {
                let next_key_package = test_generator.generate(None).unwrap();
                assert_ne!(first_key_package.leaf_secret, next_key_package.leaf_secret)
            })
        }
    }
}
