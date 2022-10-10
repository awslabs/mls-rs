#[cfg(test)]
use crate::client_builder::test_utils::TestIdentitySelector;
use crate::{cipher_suite::CipherSuite, identity::SigningIdentity};
use ferriscrypt::asym::ec_key::SecretKey;
use indexmap::IndexMap;
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};

pub use crate::signer::Signer;

pub trait IdentitySelectionStrategy<S> {
    fn select_identity(
        &self,
        identities: Vec<(SigningIdentity, S)>,
        existing: Option<&SigningIdentity>,
        cipher_suite: CipherSuite,
    ) -> Option<(SigningIdentity, S)>;
}

#[derive(Debug, Clone)]
pub struct FirstIdentitySelector;

impl<S> IdentitySelectionStrategy<S> for FirstIdentitySelector {
    fn select_identity(
        &self,
        identities: Vec<(SigningIdentity, S)>,
        _existing: Option<&SigningIdentity>,
        _cipher_suite: CipherSuite,
    ) -> Option<(SigningIdentity, S)> {
        identities.into_iter().next()
    }
}

pub trait KeychainStorage {
    type Signer: Signer;
    type Error: std::error::Error + Send + Sync + 'static;
    type IdentitySelectionStrategy: IdentitySelectionStrategy<Self::Signer>;

    fn insert(
        &mut self,
        identity: SigningIdentity,
        signer: Self::Signer,
    ) -> Result<(), Self::Error>;

    fn delete(&mut self, identity: &SigningIdentity) -> Result<(), Self::Error>;

    fn get_identities(
        &self,
        cipher_suite: CipherSuite,
    ) -> Result<Vec<(SigningIdentity, Self::Signer)>, Self::Error>;

    fn selection_strategy(&self) -> Self::IdentitySelectionStrategy;

    fn get_identity(
        &self,
        cipher_suite: CipherSuite,
        existing: Option<&SigningIdentity>,
    ) -> Result<Option<(SigningIdentity, Self::Signer)>, Self::Error> {
        self.get_identities(cipher_suite).map(|i| {
            self.selection_strategy()
                .select_identity(i, existing, cipher_suite)
        })
    }

    fn signer(&self, identity: &SigningIdentity) -> Result<Option<Self::Signer>, Self::Error>;
}

#[derive(Clone, Debug)]
pub struct InMemoryKeychain<IS>
where
    IS: IdentitySelectionStrategy<SecretKey>,
{
    selection_strategy: IS,
    secret_keys: Arc<Mutex<IndexMap<SigningIdentity, SecretKey>>>,
}

impl Default for InMemoryKeychain<FirstIdentitySelector> {
    fn default() -> Self {
        Self {
            selection_strategy: FirstIdentitySelector,
            secret_keys: Default::default(),
        }
    }
}

impl<IS> InMemoryKeychain<IS>
where
    IS: IdentitySelectionStrategy<SecretKey>,
{
    pub fn new(selection_strategy: IS) -> InMemoryKeychain<IS> {
        InMemoryKeychain {
            selection_strategy,
            secret_keys: Default::default(),
        }
    }

    pub fn insert(&mut self, identity: SigningIdentity, signer: SecretKey) {
        self.secret_keys.lock().unwrap().insert(identity, signer);
    }

    pub fn signer(&self, identity: &SigningIdentity) -> Option<SecretKey> {
        self.secret_keys.lock().unwrap().get(identity).cloned()
    }

    pub fn delete(&mut self, identity: &SigningIdentity) {
        self.secret_keys.lock().unwrap().remove(identity);
    }

    fn get_identities(&self, cipher_suite: CipherSuite) -> Vec<(SigningIdentity, SecretKey)> {
        let all_keys = self.secret_keys.lock().unwrap();

        all_keys
            .iter()
            .filter_map(|(signing_id, key)| {
                if key.curve() == cipher_suite.signature_key_curve() {
                    Some((signing_id.clone(), key.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    #[cfg(feature = "benchmark")]
    pub fn export(&self) -> Vec<(SigningIdentity, SecretKey)> {
        let map = self.secret_keys.lock().unwrap();
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

#[cfg(test)]
impl InMemoryKeychain<TestIdentitySelector> {
    pub fn replace_identity(&mut self, identity: SigningIdentity, key: SecretKey) {
        self.selection_strategy.replacement = Some((identity, key))
    }
}

impl<IS> KeychainStorage for InMemoryKeychain<IS>
where
    IS: IdentitySelectionStrategy<SecretKey> + Clone,
{
    type Signer = SecretKey;
    type Error = Infallible;
    type IdentitySelectionStrategy = IS;

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

    fn get_identities(
        &self,
        cipher_suite: CipherSuite,
    ) -> Result<Vec<(SigningIdentity, Self::Signer)>, Self::Error> {
        Ok(self.get_identities(cipher_suite))
    }

    fn selection_strategy(&self) -> Self::IdentitySelectionStrategy {
        self.selection_strategy.clone()
    }
}
