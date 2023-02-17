use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use aws_mls_core::{
    crypto::{CipherSuite, SignatureSecretKey},
    identity::SigningIdentity,
    keychain::KeychainStorage,
};

#[derive(Clone, Debug, Default)]
/// In memory keychain backed by a HashMap.
///
/// All clones of an instance of this type share the same underlying HashMap.
pub struct InMemoryKeychainStorage {
    secret_keys: Arc<Mutex<HashMap<SigningIdentity, (CipherSuite, SignatureSecretKey)>>>,
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
        self.secret_keys
            .lock()
            .unwrap()
            .insert(identity, (cipher_suite, signer));
    }

    /// Retrieve the signing_key associated with a specific `identity`.
    pub fn signer(&self, identity: &SigningIdentity) -> Option<SignatureSecretKey> {
        self.secret_keys
            .lock()
            .unwrap()
            .get(identity)
            .map(|v| v.1.clone())
    }

    /// Delete the entry for `identity`.
    pub fn delete(&mut self, identity: &SigningIdentity) {
        self.secret_keys.lock().unwrap().remove(identity);
    }

    /// Get the set of identities stored that can be used with `cipher_suite`.
    pub fn identities_supporting_ciphersuite(
        &self,
        cipher_suite: CipherSuite,
    ) -> Vec<(SigningIdentity, SignatureSecretKey)> {
        let all_keys = self.secret_keys.lock().unwrap();

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
        let map = self.secret_keys.lock().unwrap();
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
