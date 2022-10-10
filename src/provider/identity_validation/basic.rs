use crate::{
    cipher_suite::CipherSuite,
    identity::{CredentialType, CREDENTIAL_TYPE_BASIC},
    identity::{SigningIdentity, SigningIdentityError},
};

use super::IdentityValidator;

#[derive(Clone, Debug, Default)]
pub struct BasicIdentityValidator;

impl BasicIdentityValidator {
    pub fn new() -> Self {
        Self
    }
}

impl IdentityValidator for BasicIdentityValidator {
    type Error = SigningIdentityError;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error> {
        // Check that using the public key won't cause errors later
        signing_identity
            .public_key(cipher_suite)
            .map(|_| ())
            .map_err(Into::into)
    }

    fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
        Ok(signing_id.credential.credential_data.clone())
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error> {
        Ok(predecessor.credential.credential_data == successor.credential.credential_data)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CREDENTIAL_TYPE_BASIC]
    }
}
