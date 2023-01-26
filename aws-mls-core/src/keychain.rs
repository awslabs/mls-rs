use async_trait::async_trait;

use crate::{
    crypto::{CipherSuite, SignatureSecretKey},
    identity::SigningIdentity,
};

#[async_trait]
pub trait KeychainStorage: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn insert(
        &mut self,
        identity: SigningIdentity,
        signer: SignatureSecretKey,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error>;

    async fn delete(&mut self, identity: &SigningIdentity) -> Result<(), Self::Error>;

    async fn get_identities(
        &self,
        cipher_suite: CipherSuite,
    ) -> Result<Vec<(SigningIdentity, SignatureSecretKey)>, Self::Error>;

    async fn signer(
        &self,
        identity: &SigningIdentity,
    ) -> Result<Option<SignatureSecretKey>, Self::Error>;
}
