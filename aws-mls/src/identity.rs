/// Basic credential identity provider.
pub mod basic;

/// X.509 certificate identity provider.
pub mod x509 {
    pub use aws_mls_identity_x509::*;
}

pub use aws_mls_core::identity::{
    Credential, CredentialType, CustomCredential, IdentityWarning, MlsCredential, SigningIdentity,
};

pub use aws_mls_core::group::RosterUpdate;

#[cfg(any(test, feature = "benchmark"))]
pub(crate) mod test_utils {
    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;
    use async_trait::async_trait;
    use aws_mls_core::{
        crypto::{CipherSuite, CipherSuiteProvider, SignatureSecretKey},
        error::IntoAnyError,
        extension::ExtensionList,
        group::RosterUpdate,
        identity::{
            Credential, CredentialType, IdentityProvider, IdentityWarning, SigningIdentity,
        },
        time::MlsTime,
    };

    use crate::crypto::test_utils::test_cipher_suite_provider;

    use super::basic::{BasicCredential, BasicIdentityProvider, BasicIdentityProviderError};

    #[derive(Debug, thiserror::Error)]
    #[error("expected basic or custom credential type 42 found: {0:?}")]
    pub struct BasicWithCustomProviderError(CredentialType);

    impl From<BasicIdentityProviderError> for BasicWithCustomProviderError {
        fn from(value: BasicIdentityProviderError) -> Self {
            BasicWithCustomProviderError(value.credential_type())
        }
    }

    impl IntoAnyError for BasicWithCustomProviderError {
        fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
            Ok(self.into())
        }
    }

    #[derive(Debug, Clone)]
    pub struct BasicWithCustomProvider {
        pub(crate) basic: BasicIdentityProvider,
        pub(crate) allow_any_custom: bool,
    }

    impl BasicWithCustomProvider {
        pub const CUSTOM_CREDENTIAL_TYPE: u16 = 42;

        pub fn new(basic: BasicIdentityProvider) -> BasicWithCustomProvider {
            BasicWithCustomProvider {
                basic,
                allow_any_custom: false,
            }
        }

        async fn resolve_custom_identity(
            &self,
            signing_id: &SigningIdentity,
        ) -> Result<Vec<u8>, BasicWithCustomProviderError> {
            self.basic.identity(signing_id).await.or_else(|_| {
                signing_id
                    .credential
                    .as_custom()
                    .map(|c| {
                        if c.credential_type() == CredentialType::from(Self::CUSTOM_CREDENTIAL_TYPE)
                            || self.allow_any_custom
                        {
                            Ok(c.data().to_vec())
                        } else {
                            Err(BasicWithCustomProviderError(c.credential_type()))
                        }
                    })
                    .transpose()?
                    .ok_or_else(|| {
                        BasicWithCustomProviderError(signing_id.credential.credential_type())
                    })
            })
        }
    }

    #[async_trait]
    impl IdentityProvider for BasicWithCustomProvider {
        type Error = BasicWithCustomProviderError;

        async fn validate_member(
            &self,
            _signing_identity: &SigningIdentity,
            _timestamp: Option<MlsTime>,
            _extensions: Option<&ExtensionList>,
        ) -> Result<(), Self::Error> {
            //TODO: Is it actually beneficial to check the key, or does that already happen elsewhere before
            //this point?
            Ok(())
        }

        #[cfg(feature = "external_proposal")]
        async fn validate_external_sender(
            &self,
            _signing_identity: &SigningIdentity,
            _timestamp: Option<MlsTime>,
            _extensions: Option<&ExtensionList>,
        ) -> Result<(), Self::Error> {
            //TODO: Is it actually beneficial to check the key, or does that already happen elsewhere before
            //this point?
            Ok(())
        }

        async fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
            self.resolve_custom_identity(signing_id).await
        }

        async fn valid_successor(
            &self,
            predecessor: &SigningIdentity,
            successor: &SigningIdentity,
        ) -> Result<bool, Self::Error> {
            let predecessor = self.resolve_custom_identity(predecessor).await?;
            let successor = self.resolve_custom_identity(successor).await?;

            Ok(predecessor == successor)
        }

        fn supported_types(&self) -> Vec<CredentialType> {
            vec![
                BasicCredential::credential_type(),
                CredentialType::new(Self::CUSTOM_CREDENTIAL_TYPE),
            ]
        }

        async fn identity_warnings(
            &self,
            _update: &RosterUpdate,
        ) -> Result<Vec<IdentityWarning>, Self::Error> {
            Ok(vec![])
        }
    }

    pub fn get_test_signing_identity(
        cipher_suite: CipherSuite,
        identity: Vec<u8>,
    ) -> (SigningIdentity, SignatureSecretKey) {
        let provider = test_cipher_suite_provider(cipher_suite);
        let (secret_key, public_key) = provider.signature_key_generate().unwrap();

        let basic = get_test_basic_credential(identity);

        (SigningIdentity::new(basic, public_key), secret_key)
    }

    pub fn get_test_basic_credential(identity: Vec<u8>) -> Credential {
        BasicCredential::new(identity).into_credential()
    }
}
