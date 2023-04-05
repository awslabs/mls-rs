use crate::{crypto::SignatureSecretKey, identity::SigningIdentity};
use alloc::boxed::Box;
use async_trait::async_trait;

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(not(feature = "std"))]
use core::error::Error;

/// Storage trait that maintains secret signature keys
/// indexed by public
/// [`SigningIdentity`](aws_mls_core::identity::SigningIdentity).
#[async_trait]
pub trait KeychainStorage: Send + Sync {
    /// Error type that the underlying storage mechanism returns on internal
    /// failure.
    type Error: Error + Send + Sync + 'static;

    /// Retrieve the
    /// [`SignatureSecretKey`](aws_mls_core::crypto::SignatureSecretKey)
    /// that is associated with `identity`.
    ///
    /// `None` should be returned in the event `identity` is not found.
    async fn signer(
        &self,
        identity: &SigningIdentity,
    ) -> Result<Option<SignatureSecretKey>, Self::Error>;
}
