use crate::{
    cipher_suite::CipherSuite,
    external_client_config::ExternalClientConfig,
    group::{framing::MLSMessage, snapshot::ExternalSnapshot, ExternalGroup, GroupError},
    key_package::{
        KeyPackage, KeyPackageValidationError, KeyPackageValidationOptions,
        KeyPackageValidationOutput, KeyPackageValidator,
    },
    protocol_version::ProtocolVersion,
    provider::crypto::CryptoProvider,
    time::MlsTime,
};
use thiserror::Error;

pub use crate::external_client_builder::{
    ExternalBaseConfig, ExternalClientBuilder, Missing, MlsConfig, WithIdentityProvider,
    WithKeychain, WithProposalFilter,
};

#[derive(Debug, Error)]
pub enum ExternalClientError {
    #[error(transparent)]
    GroupError(#[from] GroupError),
    #[error(transparent)]
    KeyPackageValidationError(#[from] KeyPackageValidationError),
    #[error("unsupported cipher suite: {0:?}")]
    UnsupportedCipherSuite(CipherSuite),
}

pub struct ExternalClient<C> {
    config: C,
}

impl ExternalClient<()> {
    pub fn builder() -> ExternalClientBuilder<ExternalBaseConfig> {
        ExternalClientBuilder::new()
    }
}

impl<C> ExternalClient<C>
where
    C: ExternalClientConfig + Clone,
{
    pub(crate) fn new(config: C) -> Self {
        Self { config }
    }

    pub fn observe_group(
        &self,
        group_info: MLSMessage,
        tree_data: Option<&[u8]>,
    ) -> Result<ExternalGroup<C>, ExternalClientError> {
        ExternalGroup::join(self.config.clone(), group_info, tree_data).map_err(Into::into)
    }

    pub fn load_group(
        &self,
        snapshot: ExternalSnapshot,
    ) -> Result<ExternalGroup<C>, ExternalClientError> {
        ExternalGroup::from_snapshot(self.config.clone(), snapshot).map_err(Into::into)
    }

    pub fn validate_key_package(
        &self,
        package: &KeyPackage,
        protocol: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> Result<KeyPackageValidationOutput, ExternalClientError> {
        let cipher_suite_provider = self
            .config
            .crypto_provider()
            .cipher_suite_provider(cipher_suite)
            .ok_or_else(|| ExternalClientError::UnsupportedCipherSuite(cipher_suite))?;

        let keypackage_validator = KeyPackageValidator::new(
            protocol,
            &cipher_suite_provider,
            None,
            self.config.identity_provider(),
        );

        let options = KeyPackageValidationOptions {
            apply_lifetime_check: Some(MlsTime::now()),
        };

        keypackage_validator
            .check_if_valid(package, options)
            .map_err(Into::into)
    }
}
