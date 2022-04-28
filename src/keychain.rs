use crate::{cipher_suite::CipherSuite, credential::Credential, signer::Signer};
use ferriscrypt::asym::ec_key::{Curve, SecretKey};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub trait Keychain {
    type Signer: Signer;

    fn default_credential(&self, cipher_suite: CipherSuite) -> Option<(Credential, Self::Signer)>;
    fn signer(&self, credential: &Credential) -> Option<Self::Signer>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryKeychain {
    secret_keys: Arc<Mutex<HashMap<Credential, SecretKey>>>,
}

impl InMemoryKeychain {
    pub fn insert(&mut self, credential: Credential, secret_key: SecretKey) -> Option<SecretKey> {
        self.secret_keys
            .lock()
            .unwrap()
            .insert(credential, secret_key)
    }
}

impl Keychain for InMemoryKeychain {
    fn default_credential(&self, cipher_suite: CipherSuite) -> Option<(Credential, SecretKey)> {
        let cipher_suite_curve = Curve::from(cipher_suite.signature_scheme());

        self.secret_keys
            .lock()
            .unwrap()
            .iter()
            .find_map(|(credential, sk)| {
                credential
                    .public_key()
                    .ok()
                    .filter(|pk| pk.curve() == cipher_suite_curve)
                    .map(|_| (credential.clone(), sk.clone()))
            })
    }

    type Signer = SecretKey;

    fn signer(&self, credential: &Credential) -> Option<Self::Signer> {
        self.secret_keys.lock().unwrap().get(credential).cloned()
    }
}
