// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::{crypto::SignatureSecretKey, error::IntoAnyError, identity::SigningIdentity};
#[cfg(not(sync))]
use alloc::boxed::Box;

/// Storage trait that maintains secret signature keys
/// indexed by public
/// [`SigningIdentity`](crate::identity::SigningIdentity).
#[maybe_async::maybe_async]
pub trait KeychainStorage: Send + Sync {
    /// Error type that the underlying storage mechanism returns on internal
    /// failure.
    type Error: IntoAnyError;

    /// Retrieve the
    /// [`SignatureSecretKey`](crate::crypto::SignatureSecretKey)
    /// that is associated with `identity`.
    ///
    /// `None` should be returned in the event `identity` is not found.
    async fn signer(
        &self,
        identity: &SigningIdentity,
    ) -> Result<Option<SignatureSecretKey>, Self::Error>;
}
