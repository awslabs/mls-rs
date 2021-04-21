use crate::ciphersuite::{CipherSuiteError, KemKeyPair};
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(test)] {
        use crate::ciphersuite::test_util::MockCipherSuite as CipherSuite;
    } else {
        use crate::ciphersuite::{CipherSuite};
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeSecrets {
    pub path_secret: Vec<u8>,
    pub key_pair: KemKeyPair,
}

pub struct NodeSecretGenerator {
    cipher_suite: CipherSuite,
    pub next_path_secret: Vec<u8>,
}

impl NodeSecretGenerator {
    // The first secret generated will be based on the path_secret passed in,
    // and will ratchet forward after that
    pub fn new_from_path_secret(cipher_suite: CipherSuite, path_secret: Vec<u8>) -> Self {
        Self {
            cipher_suite,
            next_path_secret: path_secret,
        }
    }

    pub fn next_secret(&mut self) -> Result<NodeSecrets, CipherSuiteError> {
        let path_secret = self.next_path_secret.clone();
        let node_secret = self.cipher_suite.derive_secret(&path_secret, "node")?;
        let key_pair = self.cipher_suite.derive_kem_key_pair(&node_secret)?;

        self.next_path_secret = self.cipher_suite.derive_secret(&path_secret, "path")?;

        Ok(NodeSecrets {
            path_secret,
            key_pair,
        })
    }
}

impl Iterator for NodeSecretGenerator {
    type Item = Result<NodeSecrets, CipherSuiteError>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_secret())
    }
}
