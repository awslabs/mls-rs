use super::*;
use crate::identity::{CredentialError, CredentialType};
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use itertools::Itertools;
use serde_with::serde_as;
use std::collections::hash_map::Entry;

#[derive(Debug, Error)]
pub enum TreeIndexError {
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error("credential signature keys must be unique, duplicate key found at index: {0:?}")]
    DuplicateSignatureKeys(LeafIndex),
    #[error("hpke keys must be unique, duplicate key found at index: {0:?}")]
    DuplicateHpkeKey(LeafIndex),
    #[error("identities must be unique, duplicate identity found at index {0:?}")]
    DuplicateIdentity(LeafIndex),
    #[error("In-use credential type {0} not supported by new leaf at index {1:?}")]
    InUseCredentialTypeUnsupportedByNewLeaf(CredentialType, LeafIndex),
    #[error("Not all members support the credential type used by new leaf")]
    CredentialTypeOfNewLeafIsUnsupported(CredentialType),
}

#[serde_as]
#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TreeIndex {
    #[serde_as(as = "HashMap<VecAsBase64, _>")]
    credential_signature_key: HashMap<Vec<u8>, LeafIndex>,
    #[serde_as(as = "HashMap<VecAsBase64, _>")]
    hpke_key: HashMap<Vec<u8>, LeafIndex>,
    #[serde_as(as = "HashMap<VecAsBase64, _>")]
    identities: HashMap<Vec<u8>, LeafIndex>,
    #[serde_as(as = "Vec<(_,_)>")]
    credential_type_counters: HashMap<CredentialType, CredentialTypeCounters>,
}

impl TreeIndex {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn insert(
        &mut self,
        index: LeafIndex,
        leaf_node: &LeafNode,
        identity: Vec<u8>,
    ) -> Result<(), TreeIndexError> {
        let old_leaf_count = self.credential_signature_key.len();

        let pub_key = leaf_node.signing_identity.signature_key.deref().clone();
        let credential_entry = self.credential_signature_key.entry(pub_key);

        if let Entry::Occupied(entry) = credential_entry {
            return Err(TreeIndexError::DuplicateSignatureKeys(*entry.get()));
        }

        let hpke_key = leaf_node.public_key.as_ref().to_vec();
        let hpke_entry = self.hpke_key.entry(hpke_key);

        if let Entry::Occupied(entry) = hpke_entry {
            return Err(TreeIndexError::DuplicateHpkeKey(*entry.get()));
        }

        let identity_entry = self.identities.entry(identity);
        if let Entry::Occupied(entry) = identity_entry {
            return Err(TreeIndexError::DuplicateIdentity(*entry.get()));
        }

        let in_use_cred_type_unsupported_by_new_leaf = self
            .credential_type_counters
            .iter()
            .filter_map(|(cred_type, counters)| Some(*cred_type).filter(|_| counters.used > 0))
            .find(|cred_type| !leaf_node.capabilities.credentials.contains(cred_type));

        if let Some(cred_type) = in_use_cred_type_unsupported_by_new_leaf {
            return Err(TreeIndexError::InUseCredentialTypeUnsupportedByNewLeaf(
                cred_type, index,
            ));
        }

        let new_leaf_cred_type = leaf_node.signing_identity.credential.credential_type;

        let cred_type_counters = self
            .credential_type_counters
            .entry(new_leaf_cred_type)
            .or_default();

        if cred_type_counters.supported != old_leaf_count {
            return Err(TreeIndexError::CredentialTypeOfNewLeafIsUnsupported(
                new_leaf_cred_type,
            ));
        }

        cred_type_counters.used += 1;

        leaf_node
            .capabilities
            .credentials
            .iter()
            .copied()
            .unique()
            .for_each(|cred_type| {
                self.credential_type_counters
                    .entry(cred_type)
                    .or_default()
                    .supported += 1;
            });

        identity_entry.or_insert(index);
        credential_entry.or_insert(index);
        hpke_entry.or_insert(index);

        Ok(())
    }

    pub fn remove(&mut self, leaf_node: &LeafNode, identity: &[u8]) {
        let existed = self.identities.remove(identity).is_some();
        let pub_key = leaf_node.signing_identity.signature_key.deref();
        self.credential_signature_key.remove(pub_key);
        self.hpke_key.remove(leaf_node.public_key.as_ref());

        if !existed {
            return;
        }

        let leaf_cred_type = leaf_node.signing_identity.credential.credential_type;

        if let Some(counters) = self.credential_type_counters.get_mut(&leaf_cred_type) {
            counters.used -= 1;
        }

        leaf_node
            .capabilities
            .credentials
            .iter()
            .unique()
            .for_each(|cred_type| {
                if let Some(counters) = self.credential_type_counters.get_mut(cred_type) {
                    counters.supported -= 1;
                }
            });
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.credential_signature_key.len()
    }
}

#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
struct CredentialTypeCounters {
    supported: usize,
    used: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cipher_suite::CipherSuite,
        tree_kem::leaf_node::test_utils::{get_basic_test_node, get_test_client_identity},
    };
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Clone, Debug)]
    struct TestData {
        pub leaf_node: LeafNode,
        pub index: LeafIndex,
    }

    fn get_test_data(index: LeafIndex) -> TestData {
        let cipher_suite = CipherSuite::P256Aes128;
        let leaf_node = get_basic_test_node(cipher_suite, &format!("foo{}", index.0));

        TestData { leaf_node, index }
    }

    fn test_setup() -> (Vec<TestData>, TreeIndex) {
        let test_data = (0..10)
            .map(|i| get_test_data(LeafIndex(i)))
            .collect::<Vec<TestData>>();

        let mut test_index = TreeIndex::new();

        test_data.clone().into_iter().for_each(|d| {
            test_index
                .insert(
                    d.index,
                    &d.leaf_node,
                    get_test_client_identity(&d.leaf_node),
                )
                .unwrap()
        });

        (test_data, test_index)
    }

    #[test]
    fn test_insert() {
        let (test_data, test_index) = test_setup();

        assert_eq!(test_index.credential_signature_key.len(), test_data.len());
        assert_eq!(test_index.hpke_key.len(), test_data.len());

        test_data.into_iter().enumerate().for_each(|(i, d)| {
            let pub_key = d.leaf_node.signing_identity.signature_key;

            assert_eq!(
                test_index.credential_signature_key.get(pub_key.deref()),
                Some(&LeafIndex(i as u32))
            );

            assert_eq!(
                test_index.hpke_key.get(d.leaf_node.public_key.as_ref()),
                Some(&LeafIndex(i as u32))
            );
        })
    }

    #[test]
    fn test_insert_duplicate_credential_key() {
        let (test_data, mut test_index) = test_setup();

        let before_error = test_index.clone();

        let mut new_key_package = get_basic_test_node(CipherSuite::P256Aes128, "foo");
        new_key_package.signing_identity = test_data[1].leaf_node.signing_identity.clone();

        let res = test_index.insert(
            test_data[1].index,
            &new_key_package,
            get_test_client_identity(&new_key_package),
        );

        assert_matches!(res, Err(TreeIndexError::DuplicateSignatureKeys(index))
                        if index == test_data[1].index);

        assert_eq!(before_error, test_index);
    }

    #[test]
    fn test_insert_duplicate_hpke_key() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let (test_data, mut test_index) = test_setup();
        let before_error = test_index.clone();

        let mut new_leaf_node = get_basic_test_node(cipher_suite, "foo");
        new_leaf_node.public_key = test_data[1].leaf_node.public_key.clone();

        let res = test_index.insert(
            test_data[1].index,
            &new_leaf_node,
            get_test_client_identity(&new_leaf_node),
        );

        assert_matches!(res, Err(TreeIndexError::DuplicateHpkeKey(index))
                        if index == test_data[1].index);

        assert_eq!(before_error, test_index);
    }

    #[test]
    fn test_remove() {
        let (test_data, mut test_index) = test_setup();

        test_index.remove(
            &test_data[1].leaf_node,
            &get_test_client_identity(&test_data[1].leaf_node),
        );

        assert_eq!(
            test_index.credential_signature_key.len(),
            test_data.len() - 1
        );

        assert_eq!(test_index.hpke_key.len(), test_data.len() - 1);

        let pub_key = test_data[1]
            .leaf_node
            .signing_identity
            .signature_key
            .deref();

        assert_eq!(test_index.credential_signature_key.get(pub_key), None);

        assert_eq!(
            test_index
                .hpke_key
                .get(test_data[1].leaf_node.public_key.as_ref()),
            None
        );
    }
}
