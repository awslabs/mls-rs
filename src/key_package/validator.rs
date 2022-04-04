use super::*;
use crate::signer::SignatureError;
use std::{collections::HashSet, ops::DerefMut};

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
    #[error("key lifetime not found")]
    MissingKeyLifetime,
    #[error("capabilities extension not found")]
    MissingCapabilitiesExtension,
    #[error("{0:?} is not within lifetime {1:?}")]
    InvalidKeyLifetime(MlsTime, LifetimeExt),
    #[error("required extension not found")]
    RequiredExtensionNotFound(ExtensionType),
    #[error("required proposal not found")]
    RequiredProposalNotFound(ProposalType),
    #[error("found cipher suite {0:?} expected {1:?}")]
    InvalidCipherSuite(CipherSuite, CipherSuite),
    #[error("found protocol version {0:?} expected {1:?}")]
    InvalidProtocolVersion(ProtocolVersion, ProtocolVersion),
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct ValidatedKeyPackage(KeyPackage);

#[cfg(test)]
impl From<KeyPackage> for ValidatedKeyPackage {
    fn from(kp: KeyPackage) -> Self {
        ValidatedKeyPackage(kp)
    }
}

impl From<ValidatedKeyPackage> for KeyPackage {
    fn from(kp: ValidatedKeyPackage) -> Self {
        kp.0
    }
}

impl Deref for ValidatedKeyPackage {
    type Target = KeyPackage;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ValidatedKeyPackage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum KeyPackageValidationOptions {
    SkipSignatureCheck,
    SkipLifetimeCheck,
}

pub struct KeyPackageValidator<'a> {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub required_capabilities: Option<&'a RequiredCapabilitiesExt>,
    pub options: HashSet<KeyPackageValidationOptions>,
}

impl<'a> KeyPackageValidator<'a> {
    pub fn check_signature(&self, package: &KeyPackage) -> Result<(), KeyPackageValidationError> {
        // Verify that the signature on the KeyPackage is valid using the public key in the KeyPackage's credential
        package
            .verify(&package.credential.public_key()?, &())
            .map_err(Into::into)
    }

    pub fn validate_properties(
        &self,
        package: &KeyPackage,
    ) -> Result<(), KeyPackageValidationError> {
        if !self
            .options
            .contains(&KeyPackageValidationOptions::SkipSignatureCheck)
        {
            self.check_signature(package)?;
        }

        if !self
            .options
            .contains(&KeyPackageValidationOptions::SkipLifetimeCheck)
        {
            let time = MlsTime::now();

            // Ensure that the lifetime extension exists and that the key package is currently valid
            let lifetime_ext = package
                .extensions
                .get_extension::<LifetimeExt>()?
                .ok_or(KeyPackageValidationError::MissingKeyLifetime)?;

            let valid_lifetime = lifetime_ext.within_lifetime(time)?;

            if !valid_lifetime {
                return Err(KeyPackageValidationError::InvalidKeyLifetime(
                    time,
                    lifetime_ext,
                ));
            }
        }

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

        // This happens outside the if statement because regardless of additional checks the
        // capabilities extension is a required extension
        let capabilities_ext = package
            .extensions
            .get_extension::<CapabilitiesExt>()?
            .ok_or(KeyPackageValidationError::MissingCapabilitiesExtension)?;

        // If required capabilities are specified, verify this key package meets the requirements
        if let Some(required_capabilities) = self.required_capabilities {
            for extension in &required_capabilities.extensions {
                if !capabilities_ext.extensions.contains(extension) {
                    return Err(KeyPackageValidationError::RequiredExtensionNotFound(
                        *extension,
                    ));
                }
            }

            for proposal in &required_capabilities.proposals {
                if !capabilities_ext.proposals.contains(proposal) {
                    return Err(KeyPackageValidationError::RequiredProposalNotFound(
                        *proposal,
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn validate(
        &self,
        package: KeyPackage,
    ) -> Result<ValidatedKeyPackage, KeyPackageValidationError> {
        self.validate_properties(&package)?;
        Ok(ValidatedKeyPackage(package))
    }
}

#[cfg(test)]
mod tests {
    use crate::client::test_utils::get_basic_config;
    use crate::extension::MlsExtension;
    use crate::key_package::test_utils::test_key_package;
    use assert_matches::assert_matches;
    use ferriscrypt::rand::SecureRng;

    use super::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_standard_validation() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let test_package = test_key_package(protocol_version, cipher_suite);

            let validator = KeyPackageValidator {
                protocol_version,
                cipher_suite,
                required_capabilities: None,
                options: Default::default(),
            };

            let validated = validator.validate(test_package.clone()).unwrap();
            assert_eq!(validated.0, test_package);
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

            let validator = KeyPackageValidator {
                protocol_version,
                cipher_suite,
                required_capabilities: None,
                options: Default::default(),
            };

            let res = validator.validate(test_package);
            assert_matches!(res, Err(KeyPackageValidationError::SignatureError(_)));
        }
    }

    #[test]
    fn test_skip_signature_check() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;
        let test_package = invalid_signature_key_package(protocol_version, cipher_suite);

        let validator = KeyPackageValidator {
            protocol_version,
            cipher_suite,
            required_capabilities: None,
            options: [KeyPackageValidationOptions::SkipSignatureCheck].into(),
        };

        let res = validator.validate(test_package.clone()).unwrap();
        assert_eq!(res.0, test_package);
    }

    fn invalid_expiration_key_package(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> KeyPackage {
        let mut test_package = test_key_package(protocol_version, cipher_suite);
        test_package
            .extensions
            .set_extension(LifetimeExt {
                not_before: 0,
                not_after: 0,
            })
            .unwrap();

        test_package
    }

    #[test]
    fn test_expired() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let test_package = invalid_expiration_key_package(protocol_version, cipher_suite);

        let validator = KeyPackageValidator {
            protocol_version,
            cipher_suite,
            required_capabilities: None,
            options: [KeyPackageValidationOptions::SkipSignatureCheck].into(),
        };

        let res = validator.validate(test_package);

        assert_matches!(res, Err(KeyPackageValidationError::InvalidKeyLifetime(..)));
    }

    #[test]
    fn test_skip_expiration_check() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let test_package = invalid_expiration_key_package(protocol_version, cipher_suite);

        let validator = KeyPackageValidator {
            protocol_version,
            cipher_suite,
            required_capabilities: None,
            options: [
                KeyPackageValidationOptions::SkipSignatureCheck,
                KeyPackageValidationOptions::SkipLifetimeCheck,
            ]
            .into(),
        };

        let res = validator.validate(test_package.clone()).unwrap();
        assert_eq!(res.0, test_package);
    }

    #[test]
    fn test_required_capabilities_check() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let test_client = get_basic_config(cipher_suite, "foo")
            .with_supported_extension(42)
            .build_client();

        let key_package: KeyPackage = test_client
            .gen_key_package(
                protocol_version,
                cipher_suite,
                LifetimeExt::years(1).unwrap(),
            )
            .unwrap()
            .key_package
            .into();

        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![42],
            proposals: vec![],
        };

        let validator = KeyPackageValidator {
            protocol_version,
            cipher_suite,
            required_capabilities: Some(&required_capabilities),
            options: Default::default(),
        };

        let res = validator.validate(key_package.clone()).unwrap();
        assert_eq!(res.0, key_package);
    }

    #[test]
    fn test_required_extension_failure() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;
        let key_package = test_key_package(protocol_version, cipher_suite);

        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![255],
            proposals: vec![],
        };

        let validator = KeyPackageValidator {
            protocol_version,
            cipher_suite,
            required_capabilities: Some(&required_capabilities),
            options: Default::default(),
        };

        let res = validator.validate(key_package);
        assert_matches!(
            res,
            Err(KeyPackageValidationError::RequiredExtensionNotFound(_))
        );
    }

    #[test]
    fn test_required_proposal_failure() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;
        let key_package = test_key_package(protocol_version, cipher_suite);

        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![],
            proposals: vec![255],
        };

        let validator = KeyPackageValidator {
            protocol_version,
            cipher_suite,
            required_capabilities: Some(&required_capabilities),
            options: Default::default(),
        };

        let res = validator.validate(key_package);
        assert_matches!(
            res,
            Err(KeyPackageValidationError::RequiredProposalNotFound(_))
        );
    }

    fn test_missing_extension(id: u16) -> Result<ValidatedKeyPackage, KeyPackageValidationError> {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;
        let mut test_package = test_key_package(protocol_version, cipher_suite);

        test_package.extensions.remove(id);

        let validator = KeyPackageValidator {
            protocol_version,
            cipher_suite,
            required_capabilities: None,
            options: [KeyPackageValidationOptions::SkipSignatureCheck].into(),
        };

        validator.validate(test_package)
    }

    #[test]
    fn test_missing_lifetime() {
        let res = test_missing_extension(LifetimeExt::IDENTIFIER);
        assert_matches!(res, Err(KeyPackageValidationError::MissingKeyLifetime));
    }

    #[test]
    fn test_missing_capabilities() {
        let res = test_missing_extension(CapabilitiesExt::IDENTIFIER);

        assert_matches!(
            res,
            Err(KeyPackageValidationError::MissingCapabilitiesExtension)
        );
    }
}
