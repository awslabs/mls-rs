use crate::{
    cipher_suite::CipherSuite, identity::CredentialType, signing_identity::SigningIdentity,
};

mod basic;
mod x509;

pub use self::basic::*;
pub use self::x509::*;

pub trait IdentityValidator {
    type Error: std::error::Error + Send + Sync + 'static;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error>;

    fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error>;

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error>;

    fn supported_types(&self) -> Vec<CredentialType>;
}

impl<T: IdentityValidator> IdentityValidator for &T {
    type Error = T::Error;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error> {
        (*self).validate(signing_identity, cipher_suite)
    }

    fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
        (*self).identity(signing_id)
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error> {
        (*self).valid_successor(predecessor, successor)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        (*self).supported_types()
    }
}
