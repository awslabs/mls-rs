use crate::{cipher_suite::CipherSuite, signer::Signer, signing_identity::SigningIdentity};
use ferriscrypt::asym::ec_key::SecretKey;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub trait Keychain {
    type Signer: Signer;

    fn default_identity(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<(SigningIdentity, Self::Signer)>;

    fn signer(&self, identity: &SigningIdentity) -> Option<Self::Signer>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryKeychain {
    secret_keys: Arc<Mutex<HashMap<SigningIdentity, SecretKey>>>,
}

impl InMemoryKeychain {
    pub fn insert(
        &mut self,
        identity: SigningIdentity,
        secret_key: SecretKey,
    ) -> Option<SecretKey> {
        self.secret_keys
            .lock()
            .unwrap()
            .insert(identity, secret_key)
    }

    pub fn export(&self) -> Vec<(SigningIdentity, SecretKey)> {
        let map = self.secret_keys.lock().unwrap_or_else(|e| e.into_inner());
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

impl Keychain for InMemoryKeychain {
    fn default_identity(&self, cipher_suite: CipherSuite) -> Option<(SigningIdentity, SecretKey)> {
        let cipher_suite_curve = cipher_suite.signature_key_curve();

        self.secret_keys
            .lock()
            .unwrap()
            .iter()
            .find_map(|(identity, sk)| {
                identity
                    .public_key(cipher_suite)
                    .ok()
                    .filter(|pk| pk.curve() == cipher_suite_curve)
                    .map(|_| (identity.clone(), sk.clone()))
            })
    }

    type Signer = SecretKey;

    fn signer(&self, identity: &SigningIdentity) -> Option<Self::Signer> {
        self.secret_keys.lock().unwrap().get(identity).cloned()
    }
}
