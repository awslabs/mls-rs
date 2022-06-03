use std::collections::hash_map::Entry;

use super::*;
use crate::credential::CredentialError;

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
}

#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TreeIndex {
    #[serde(with = "crate::serde_utils::map_as_seq")]
    credential_signature_key: HashMap<Vec<u8>, LeafIndex>,
    #[serde(with = "crate::serde_utils::map_as_seq")]
    hpke_key: HashMap<Vec<u8>, LeafIndex>,
}

impl TreeIndex {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn can_insert(&self, leaf_node: &LeafNode) -> Result<(), TreeIndexError> {
        self.can_insert_or_update(None, leaf_node)
    }

    pub fn can_update(
        &self,
        current_index: LeafIndex,
        new_leaf_node: &LeafNode,
    ) -> Result<(), TreeIndexError> {
        self.can_insert_or_update(Some(current_index), new_leaf_node)
    }

    fn can_insert_or_update(
        &self,
        current_index: Option<LeafIndex>,
        new_leaf_node: &LeafNode,
    ) -> Result<(), TreeIndexError> {
        let different = |i: &LeafIndex| Some(*i) != current_index;

        self.credential_signature_key
            .get(&*new_leaf_node.signing_identity.signature_key)
            .copied()
            .filter(different)
            .map_or(Ok(()), |index| {
                Err(TreeIndexError::DuplicateSignatureKeys(index))
            })?;

        self.hpke_key
            .get(new_leaf_node.public_key.as_ref())
            .copied()
            .filter(different)
            .map_or(Ok(()), |index| Err(TreeIndexError::DuplicateHpkeKey(index)))?;

        Ok(())
    }

    pub fn insert(&mut self, index: LeafIndex, leaf_node: &LeafNode) -> Result<(), TreeIndexError> {
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

        credential_entry.or_insert(index);
        hpke_entry.or_insert(index);

        Ok(())
    }

    pub fn remove(&mut self, leaf_node: &LeafNode) -> Result<(), TreeIndexError> {
        let pub_key = leaf_node.signing_identity.signature_key.deref();

        self.credential_signature_key.remove(pub_key);
        self.hpke_key.remove(leaf_node.public_key.as_ref());

        Ok(())
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.credential_signature_key.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cipher_suite::CipherSuite, tree_kem::leaf_node::test_utils::get_basic_test_node};
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
        let leaf_node = get_basic_test_node(cipher_suite, "foo");

        TestData { leaf_node, index }
    }

    fn test_setup() -> (Vec<TestData>, TreeIndex) {
        let test_data = (0..10)
            .map(|i| get_test_data(LeafIndex(i)))
            .collect::<Vec<TestData>>();

        let mut test_index = TreeIndex::new();

        test_data
            .clone()
            .into_iter()
            .for_each(|d| test_index.insert(d.index, &d.leaf_node).unwrap());

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

        let res = test_index.insert(test_data[1].index, &new_key_package);

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

        let res = test_index.insert(test_data[1].index, &new_leaf_node);

        assert_matches!(res, Err(TreeIndexError::DuplicateHpkeKey(index))
                        if index == test_data[1].index);

        assert_eq!(before_error, test_index);
    }

    #[test]
    fn test_remove() {
        let (test_data, mut test_index) = test_setup();

        test_index.remove(&test_data[1].leaf_node).unwrap();

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
