use std::collections::hash_map::Entry;

use super::*;
use crate::credential::CredentialError;

#[derive(Debug, Error)]
pub enum TreeIndexError {
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(
        "can't insert {0}, credential signature keys must be unique, duplicate key found at index: {1:?}",
    )]
    DuplicateSignatureKeys(String, LeafIndex),
    #[error("can't insert {0}, hpke keys must be unique, duplicate key found at index: {1:?}")]
    DuplicateHpkeKey(String, LeafIndex),
    #[error("can't insert {0}, this leaf node is already inserted at index: {1:?}")]
    DuplicateLeafNode(String, LeafIndex),
}

#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TreeIndex {
    #[serde(with = "crate::serde_utils::map_as_seq")]
    leaves: HashMap<LeafNodeRef, LeafIndex>,
    #[serde(with = "crate::serde_utils::map_as_seq")]
    credential_signature_key: HashMap<Vec<u8>, LeafIndex>,
    #[serde(with = "crate::serde_utils::map_as_seq")]
    hpke_key: HashMap<Vec<u8>, LeafIndex>,
}

impl TreeIndex {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn insert(
        &mut self,
        leaf_node_ref: LeafNodeRef,
        index: LeafIndex,
        leaf_node: &LeafNode,
    ) -> Result<(), TreeIndexError> {
        let packages_entry = self.leaves.entry(leaf_node_ref.clone());

        if let Entry::Occupied(entry) = packages_entry {
            return Err(TreeIndexError::DuplicateLeafNode(
                entry.key().to_string(),
                *entry.get(),
            ));
        }

        let pub_key = leaf_node.credential.public_key()?.to_uncompressed_bytes()?;
        let credential_entry = self.credential_signature_key.entry(pub_key);

        if let Entry::Occupied(entry) = credential_entry {
            return Err(TreeIndexError::DuplicateSignatureKeys(
                leaf_node_ref.to_string(),
                *entry.get(),
            ));
        }

        let hpke_key = leaf_node.public_key.as_ref().to_vec();
        let hpke_entry = self.hpke_key.entry(hpke_key);

        if let Entry::Occupied(entry) = hpke_entry {
            return Err(TreeIndexError::DuplicateHpkeKey(
                leaf_node_ref.to_string(),
                *entry.get(),
            ));
        }

        packages_entry.or_insert(index);
        credential_entry.or_insert(index);
        hpke_entry.or_insert(index);

        Ok(())
    }

    pub fn remove(
        &mut self,
        leaf_node_ref: &LeafNodeRef,
        leaf_node: &LeafNode,
    ) -> Result<(), TreeIndexError> {
        self.leaves.remove(leaf_node_ref);

        let pub_key = leaf_node.credential.public_key()?.to_uncompressed_bytes()?;

        self.credential_signature_key.remove(&pub_key);
        self.hpke_key.remove(leaf_node.public_key.as_ref());

        Ok(())
    }

    pub fn get_leaf_node_index(&self, leaf_node_ref: &LeafNodeRef) -> Option<LeafIndex> {
        self.leaves.get(leaf_node_ref).cloned()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn leaf_node_refs(&self) -> impl Iterator<Item = &'_ LeafNodeRef> {
        self.leaves.keys()
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
        pub leaf_node_ref: LeafNodeRef,
        pub index: LeafIndex,
    }

    fn get_test_data(index: LeafIndex) -> TestData {
        let cipher_suite = CipherSuite::P256Aes128;

        let leaf_node = get_basic_test_node(cipher_suite, "foo");
        let leaf_node_ref = leaf_node.to_reference(cipher_suite).unwrap();

        TestData {
            leaf_node,
            leaf_node_ref,
            index,
        }
    }

    fn test_setup() -> (Vec<TestData>, TreeIndex) {
        let test_data = (0..10)
            .map(|i| get_test_data(LeafIndex(i)))
            .collect::<Vec<TestData>>();

        let mut test_index = TreeIndex::new();

        test_data.clone().into_iter().for_each(|d| {
            test_index
                .insert(d.leaf_node_ref, d.index, &d.leaf_node)
                .unwrap()
        });

        (test_data, test_index)
    }

    #[test]
    fn test_insert() {
        let (test_data, test_index) = test_setup();

        assert_eq!(test_index.leaves.len(), test_data.len());
        assert_eq!(test_index.credential_signature_key.len(), test_data.len());
        assert_eq!(test_index.hpke_key.len(), test_data.len());

        test_data.into_iter().enumerate().for_each(|(i, d)| {
            assert_eq!(
                test_index.leaves.get(&d.leaf_node_ref),
                Some(&LeafIndex(i as u32))
            );

            let pub_key = d
                .leaf_node
                .credential
                .public_key()
                .unwrap()
                .to_uncompressed_bytes()
                .unwrap();

            assert_eq!(
                test_index.credential_signature_key.get(&pub_key),
                Some(&LeafIndex(i as u32))
            );

            assert_eq!(
                test_index.hpke_key.get(d.leaf_node.public_key.as_ref()),
                Some(&LeafIndex(i as u32))
            );
        })
    }

    #[test]
    fn test_get_key_package_index() {
        let (test_data, test_index) = test_setup();

        let fetched_package_index = test_index.get_leaf_node_index(&test_data[0].leaf_node_ref);
        assert_eq!(fetched_package_index, Some(test_data[0].index));

        let not_found_ref = LeafNodeRef::from([0u8; 16]);
        assert_eq!(test_index.get_leaf_node_index(&not_found_ref), None)
    }

    #[test]
    fn test_insert_duplicate_kp() {
        let (test_data, mut test_index) = test_setup();

        let before_error = test_index.clone();

        let res = test_index.insert(
            test_data[1].leaf_node_ref.clone(),
            test_data[1].index,
            &test_data[1].leaf_node,
        );

        assert_matches!(res, Err(TreeIndexError::DuplicateLeafNode(kpr, index))
                        if kpr == test_data[1].leaf_node_ref.to_string()
                        && index == test_data[1].index);

        assert_eq!(before_error, test_index);
    }

    #[test]
    fn test_insert_duplicate_credential_key() {
        let (test_data, mut test_index) = test_setup();

        let before_error = test_index.clone();

        let mut new_key_package = get_basic_test_node(CipherSuite::P256Aes128, "foo");
        new_key_package.credential = test_data[1].leaf_node.credential.clone();

        let res = test_index.insert(
            new_key_package
                .to_reference(CipherSuite::P256Aes128)
                .unwrap(),
            test_data[1].index,
            &new_key_package,
        );

        assert_matches!(res, Err(TreeIndexError::DuplicateSignatureKeys(kpr, index))
                        if kpr == new_key_package.to_reference(CipherSuite::P256Aes128).unwrap().to_string()
                        && index == test_data[1].index);

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
            new_leaf_node.to_reference(cipher_suite).unwrap(),
            test_data[1].index,
            &new_leaf_node,
        );

        assert_matches!(res, Err(TreeIndexError::DuplicateHpkeKey(kpr, index))
                        if kpr == new_leaf_node.to_reference(cipher_suite).unwrap().to_string()
                        && index == test_data[1].index);

        assert_eq!(before_error, test_index);
    }

    #[test]
    fn test_remove() {
        let (test_data, mut test_index) = test_setup();

        test_index
            .remove(&test_data[1].leaf_node_ref, &test_data[1].leaf_node)
            .unwrap();

        assert_eq!(test_index.leaves.len(), test_data.len() - 1);
        assert_eq!(
            test_index.credential_signature_key.len(),
            test_data.len() - 1
        );
        assert_eq!(test_index.hpke_key.len(), test_data.len() - 1);
        assert_eq!(test_index.leaves.get(&test_data[1].leaf_node_ref), None);

        let pub_key = test_data[1]
            .leaf_node
            .credential
            .public_key()
            .unwrap()
            .to_uncompressed_bytes()
            .unwrap();

        assert_eq!(test_index.credential_signature_key.get(&pub_key), None);

        assert_eq!(
            test_index
                .hpke_key
                .get(test_data[1].leaf_node.public_key.as_ref()),
            None
        );
    }
}
