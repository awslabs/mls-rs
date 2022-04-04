use super::*;

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct UpdatePathNode {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub public_key: HpkePublicKey,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct UpdatePath {
    pub leaf_key_package: KeyPackage,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub nodes: Vec<UpdatePathNode>,
}

#[derive(Debug, Error)]
pub enum UpdatePathValidationError {
    #[error(transparent)]
    KeyPackageValidationError(#[from] KeyPackageValidationError),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedUpdatePath {
    pub leaf_key_package: ValidatedKeyPackage,
    pub nodes: Vec<UpdatePathNode>,
}

pub struct UpdatePathValidator<'a>(KeyPackageValidator<'a>);

impl<'a> UpdatePathValidator<'a> {
    pub fn new(validator: KeyPackageValidator<'a>) -> Self {
        Self(validator)
    }
}

impl<'a> UpdatePathValidator<'a> {
    pub fn validate(
        &self,
        path: UpdatePath,
    ) -> Result<ValidatedUpdatePath, UpdatePathValidationError> {
        let validated_key_package = self.0.validate(path.leaf_key_package)?;

        Ok(ValidatedUpdatePath {
            leaf_key_package: validated_key_package,
            nodes: path.nodes,
        })
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use ferriscrypt::{
        hpke::{kem::HpkePublicKey, HPKECiphertext},
        rand::SecureRng,
    };

    use crate::key_package::test_utils::test_key_package;

    use crate::{
        cipher_suite::CipherSuite,
        key_package::{KeyPackage, KeyPackageValidator},
        tree_kem::UpdatePathValidationError,
        ProtocolVersion,
    };

    use super::{UpdatePath, UpdatePathNode, UpdatePathValidator};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn test_update_path(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> UpdatePath {
        let key_package = test_key_package(protocol_version, cipher_suite);

        let ciphertext = HPKECiphertext {
            enc: SecureRng::gen(32).unwrap(),
            ciphertext: SecureRng::gen(32).unwrap(),
        }
        .into();

        UpdatePath {
            leaf_key_package: key_package,
            nodes: vec![UpdatePathNode {
                public_key: HpkePublicKey::from(SecureRng::gen(32).unwrap()),
                encrypted_path_secret: vec![ciphertext],
            }],
        }
    }

    #[test]
    fn test_valid_key_package() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;
        let update_path = test_update_path(protocol_version, cipher_suite);

        let validator = UpdatePathValidator(KeyPackageValidator {
            protocol_version,
            cipher_suite,
            required_capabilities: None,
            options: Default::default(),
        });

        let validated = validator.validate(update_path.clone()).unwrap();
        assert_eq!(validated.nodes, update_path.nodes);
        assert_eq!(
            KeyPackage::from(validated.leaf_key_package),
            update_path.leaf_key_package
        );
    }

    #[test]
    fn test_invalid_key_package() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;
        let mut update_path = test_update_path(protocol_version, cipher_suite);
        update_path.leaf_key_package.signature = SecureRng::gen(32).unwrap();

        let validator = UpdatePathValidator(KeyPackageValidator {
            protocol_version,
            cipher_suite,
            required_capabilities: None,
            options: Default::default(),
        });

        let validated = validator.validate(update_path);

        assert_matches!(
            validated,
            Err(UpdatePathValidationError::KeyPackageValidationError(_))
        );
    }
}
