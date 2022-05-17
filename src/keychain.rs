use crate::{
    cipher_suite::CipherSuite,
    credential::{Credential, CredentialError},
    signer::Signer,
};
use ferriscrypt::asym::ec_key::{Curve, PublicKey, SecretKey};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(
    Debug,
    Clone,
    Eq,
    Hash,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct SigningIdentity {
    pub credential: Credential,
}

impl SigningIdentity {
    pub fn new(credential: Credential) -> SigningIdentity {
        SigningIdentity { credential }
    }

    pub fn public_key(&self) -> Result<PublicKey, CredentialError> {
        self.credential.public_key()
    }
}

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
}

impl Keychain for InMemoryKeychain {
    fn default_identity(&self, cipher_suite: CipherSuite) -> Option<(SigningIdentity, SecretKey)> {
        let cipher_suite_curve = Curve::from(cipher_suite.signature_scheme());

        self.secret_keys
            .lock()
            .unwrap()
            .iter()
            .find_map(|(identity, sk)| {
                identity
                    .public_key()
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

#[cfg(test)]
pub(crate) mod test_utils {
    use super::SigningIdentity;
    use crate::{cipher_suite::CipherSuite, credential::test_utils::get_test_basic_credential};
    use ferriscrypt::asym::ec_key::SecretKey;

    pub fn get_test_signing_identity(
        cipher_suite: CipherSuite,
        identity: Vec<u8>,
    ) -> (SigningIdentity, SecretKey) {
        let basic = get_test_basic_credential(identity, cipher_suite.signature_scheme());
        (SigningIdentity::new(basic.credential), basic.secret)
    }
}
