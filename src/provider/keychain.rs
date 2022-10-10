use crate::{cipher_suite::CipherSuite, identity::SigningIdentity};
use ferriscrypt::asym::ec_key::SecretKey;
use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

pub use crate::signer::Signer;

pub trait Keychain {
    type Signer: Signer;
    type Error: std::error::Error + Send + Sync + 'static;

    fn insert(
        &mut self,
        identity: SigningIdentity,
        signer: Self::Signer,
    ) -> Result<(), Self::Error>;

    fn delete(&mut self, identity: &SigningIdentity) -> Result<(), Self::Error>;

    fn default_identity(
        &self,
        cipher_suite: CipherSuite,
    ) -> Result<Option<(SigningIdentity, Self::Signer)>, Self::Error>;

    fn signer(&self, identity: &SigningIdentity) -> Result<Option<Self::Signer>, Self::Error>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryKeychain {
    secret_keys: Arc<Mutex<HashMap<SigningIdentity, SecretKey>>>,
    pub default_identity: Option<SigningIdentity>,
}

impl InMemoryKeychain {
    pub fn insert(&mut self, identity: SigningIdentity, signer: SecretKey) {
        self.secret_keys.lock().unwrap().insert(identity, signer);
    }

    pub fn default_identity(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<(SigningIdentity, SecretKey)> {
        if let Some(identity) = &self.default_identity {
            if identity.public_key(cipher_suite).is_ok() {
                return self
                    .secret_keys
                    .lock()
                    .unwrap()
                    .get_key_value(identity)
                    .map(|(id, sk)| (id.clone(), sk.clone()));
            }
        }

        self.secret_keys
            .lock()
            .unwrap()
            .iter()
            .find_map(|(identity, sk)| {
                identity
                    .public_key(cipher_suite)
                    .ok()
                    .map(|_| (identity.clone(), sk.clone()))
            })
    }

    pub fn signer(&self, identity: &SigningIdentity) -> Option<SecretKey> {
        self.secret_keys.lock().unwrap().get(identity).cloned()
    }

    pub fn delete(&mut self, identity: &SigningIdentity) {
        self.secret_keys.lock().unwrap().remove(identity);
    }

    #[cfg(feature = "benchmark")]
    pub fn export(&self) -> Vec<(SigningIdentity, SecretKey)> {
        let map = self.secret_keys.lock().unwrap();
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

impl Keychain for InMemoryKeychain {
    type Signer = SecretKey;
    type Error = Infallible;

    fn default_identity(
        &self,
        cipher_suite: CipherSuite,
    ) -> Result<Option<(SigningIdentity, SecretKey)>, Self::Error> {
        Ok(self.default_identity(cipher_suite))
    }

    fn signer(&self, identity: &SigningIdentity) -> Result<Option<Self::Signer>, Self::Error> {
        Ok(self.signer(identity))
    }

    fn insert(
        &mut self,
        identity: SigningIdentity,
        signer: Self::Signer,
    ) -> Result<(), Self::Error> {
        self.insert(identity, signer);
        Ok(())
    }

    fn delete(&mut self, identity: &SigningIdentity) -> Result<(), Self::Error> {
        self.delete(identity);
        Ok(())
    }
}
