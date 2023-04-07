#[cfg(feature = "std")]
use alloc::sync::Arc;

#[cfg(not(feature = "std"))]
use portable_atomic_util::Arc;

use alloc::{boxed::Box, vec::Vec};
use core::convert::Infallible;

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;

use async_trait::async_trait;
use aws_mls_core::{
    crypto::{CipherSuite, SignatureSecretKey},
    identity::SigningIdentity,
    keychain::KeychainStorage,
};

#[cfg(feature = "std")]
use std::sync::Mutex;

#[cfg(not(feature = "std"))]
use spin::Mutex;

/// In memory keychain backed by a HashMap.
///
/// All clones of an instance of this type share the same underlying HashMap.

#[derive(Clone, Debug, Default)]
pub struct InMemoryKeychainStorage {
    #[cfg(feature = "std")]
    secret_keys: Arc<Mutex<HashMap<SigningIdentity, (CipherSuite, SignatureSecretKey)>>>,
    #[cfg(not(feature = "std"))]
    secret_keys: Arc<Mutex<BTreeMap<SigningIdentity, (CipherSuite, SignatureSecretKey)>>>,
}

impl InMemoryKeychainStorage {
    /// Create an empty keychain storage.
    pub fn new() -> InMemoryKeychainStorage {
        InMemoryKeychainStorage {
            secret_keys: Default::default(),
        }
    }

    /// Insert a signing identity into storage.
    ///
    /// The resulting entry will be indexed by `identity` and `cipher_suite`.
    pub fn insert(
        &mut self,
        identity: SigningIdentity,
        signer: SignatureSecretKey,
        cipher_suite: CipherSuite,
    ) {
        #[cfg(feature = "std")]
        let mut lock = self.secret_keys.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let mut lock = self.secret_keys.lock();

        lock.insert(identity, (cipher_suite, signer));
    }

    /// Retrieve the signing_key associated with a specific `identity`.
    pub fn signer(&self, identity: &SigningIdentity) -> Option<SignatureSecretKey> {
        #[cfg(feature = "std")]
        let lock = self.secret_keys.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let lock = self.secret_keys.lock();

        lock.get(identity).map(|v| v.1.clone())
    }

    /// Delete the entry for `identity`.
    pub fn delete(&mut self, identity: &SigningIdentity) {
        #[cfg(feature = "std")]
        let mut lock = self.secret_keys.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let mut lock = self.secret_keys.lock();

        lock.remove(identity);
    }

    /// Get the set of identities stored that can be used with `cipher_suite`.
    pub fn identities_supporting_ciphersuite(
        &self,
        cipher_suite: CipherSuite,
    ) -> Vec<(SigningIdentity, SignatureSecretKey)> {
        #[cfg(feature = "std")]
        let all_keys = self.secret_keys.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let all_keys = self.secret_keys.lock();

        all_keys
            .iter()
            .filter_map(|(signing_id, (cs, key))| {
                if cs == &cipher_suite {
                    Some((signing_id.clone(), key.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// All identities and signing keys held in storage.
    pub fn identities(&self) -> Vec<(SigningIdentity, SignatureSecretKey)> {
        #[cfg(feature = "std")]
        let map = self.secret_keys.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let map = self.secret_keys.lock();

        map.iter().map(|(k, v)| (k.clone(), v.1.clone())).collect()
    }
}

#[async_trait]
impl KeychainStorage for InMemoryKeychainStorage {
    type Error = Infallible;

    async fn signer(
        &self,
        identity: &SigningIdentity,
    ) -> Result<Option<SignatureSecretKey>, Self::Error> {
        Ok(self.signer(identity))
    }
}
