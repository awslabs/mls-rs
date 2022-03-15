use crate::signer::{SignatureError, Signer};

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
    KeyPackageValidationError(#[from] KeyPackageValidationError),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error("the provided signing key does not correspond to the provided credential")]
    CredentialSigningKeyMismatch,
}

#[derive(Clone, Debug)]
pub struct KeyPackageGenerator<'a, S: Signer> {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub credential: &'a Credential,
    pub extensions: &'a ExtensionList,
    pub signing_key: &'a S,
}

#[derive(Clone, Debug)]
pub struct KeyPackageGeneration {
    pub key_package: ValidatedKeyPackage,
    pub secret_key: HpkeSecretKey,
}

impl<'a, S: Signer> KeyPackageGenerator<'a, S> {
    pub fn sign(&self, package: &mut KeyPackage) -> Result<(), KeyPackageGenerationError> {
        package.sign(self.signing_key, &()).map_err(Into::into)
    }

    pub fn generate(
        &self,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
    ) -> Result<KeyPackageGeneration, KeyPackageGenerationError> {
        if self.credential.public_key()?
            != self
                .signing_key
                .public_key()
                .map_err(|e| KeyPackageGenerationError::SignerError(e.into()))?
        {
            return Err(KeyPackageGenerationError::CredentialSigningKeyMismatch);
        }

        let (public, secret) = generate_keypair(self.cipher_suite.kem_type().curve())?;

        let package = KeyPackage {
            version: self.protocol_version,
            cipher_suite: self.cipher_suite,
            hpke_init_key: public.try_into()?,
            credential: self.credential.clone(),
            extensions: self.extensions.clone(),
            signature: vec![],
        };

        let validator = KeyPackageValidator {
            protocol_version: self.protocol_version,
            cipher_suite: self.cipher_suite,
            required_capabilities,
            options: [KeyPackageValidationOptions::SkipSignatureCheck].into(),
        };

        let mut package = validator.validate(package)?;

        self.sign(&mut package)?;

        Ok(KeyPackageGeneration {
            key_package: package,
            secret_key: secret.try_into()?,
        })
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::{Curve, PublicKey, SecretKey};

    use crate::{
        cipher_suite::CipherSuite,
        credential::{BasicCredential, Credential},
        extension::{
            CapabilitiesExt, ExtensionList, LifetimeExt, MlsExtension, RequiredCapabilitiesExt,
        },
        key_package::{KeyPackageGenerationError, KeyPackageValidator},
        ProtocolVersion,
    };

    use super::KeyPackageGenerator;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test_configure!(run_in_browser);

    fn test_extensions() -> ExtensionList {
        let mut extensions = ExtensionList::new();
        extensions
            .set_extension(LifetimeExt::days(1).unwrap())
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
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let signing_key =
                SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

            let extensions = test_extensions();
            let credential = test_credential(&signing_key);

            let test_generator = KeyPackageGenerator {
                protocol_version,
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
            assert_eq!(generated.key_package.version, protocol_version);

            let curve = test_generator.cipher_suite.kem_type().curve();

            let public = PublicKey::from_uncompressed_bytes(
                generated.key_package.hpke_init_key.as_ref(),
                curve,
            )
            .unwrap();

            let secret = SecretKey::from_bytes(generated.secret_key.as_ref(), curve).unwrap();

            assert_eq!(secret.curve(), curve);
            assert_eq!(public, secret.to_public().unwrap());

            let validator = KeyPackageValidator {
                protocol_version,
                cipher_suite,
                required_capabilities: None,
                options: Default::default(),
            };

            validator.validate(generated.key_package.into()).unwrap();
        }
    }

    fn test_key_generation_missing_ext(ext: u16) {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let signing_key =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

        let mut extensions = test_extensions();
        extensions.remove(ext);

        let credential = test_credential(&signing_key);

        let test_generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite,
            credential: &credential,
            extensions: &extensions,
            signing_key: &signing_key,
        };

        let generated = test_generator.generate(None);
        assert_matches!(
            generated,
            Err(KeyPackageGenerationError::KeyPackageValidationError(_))
        );
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
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let signing_key =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

        let extensions = test_extensions();
        let credential = test_credential(&signing_key);

        let test_generator = KeyPackageGenerator {
            protocol_version,
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
        assert_matches!(
            generated,
            Err(KeyPackageGenerationError::KeyPackageValidationError(_))
        );
    }

    #[test]
    fn test_credential_signature_mismatch() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let signing_key =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

        let extensions = test_extensions();
        let credential = test_credential(
            &SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap(),
        );

        let test_generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite,
            credential: &credential,
            extensions: &extensions,
            signing_key: &signing_key,
        };

        let generated = test_generator.generate(None);
        assert_matches!(
            generated,
            Err(KeyPackageGenerationError::CredentialSigningKeyMismatch)
        );
    }

    #[test]
    fn test_randomness() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let signing_key =
                SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

            let extensions = test_extensions();
            let credential = test_credential(&signing_key);

            let test_generator = KeyPackageGenerator {
                protocol_version,
                cipher_suite,
                credential: &credential,
                extensions: &extensions,
                signing_key: &signing_key,
            };

            let first_key_package = test_generator.generate(None).unwrap();

            (0..100).for_each(|_| {
                let next_key_package = test_generator.generate(None).unwrap();

                assert_ne!(
                    first_key_package.key_package.hpke_init_key,
                    next_key_package.key_package.hpke_init_key
                );

                assert_ne!(first_key_package.secret_key, next_key_package.secret_key);
            })
        }
    }
}
