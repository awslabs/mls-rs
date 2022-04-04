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
    #[error("can't insert {0}, this package is already inserted at index: {1:?}")]
    DuplicateKeyPackage(String, LeafIndex),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TreeIndex {
    packages: HashMap<KeyPackageRef, LeafIndex>,
    credential_signature_key: HashMap<Vec<u8>, LeafIndex>,
    hpke_key: HashMap<Vec<u8>, LeafIndex>,
}

impl TreeIndex {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn insert(
        &mut self,
        key_package_ref: KeyPackageRef,
        index: LeafIndex,
        key_package: &KeyPackage,
    ) -> Result<(), TreeIndexError> {
        let packages_entry = self.packages.entry(key_package_ref.clone());

        if let Entry::Occupied(entry) = packages_entry {
            return Err(TreeIndexError::DuplicateKeyPackage(
                entry.key().to_string(),
                *entry.get(),
            ));
        }

        let pub_key = key_package
            .credential
            .public_key()?
            .to_uncompressed_bytes()?;

        let credential_entry = self.credential_signature_key.entry(pub_key);

        if let Entry::Occupied(entry) = credential_entry {
            return Err(TreeIndexError::DuplicateSignatureKeys(
                key_package_ref.to_string(),
                *entry.get(),
            ));
        }

        let hpke_key = key_package.hpke_init_key.as_ref().to_vec();
        let hpke_entry = self.hpke_key.entry(hpke_key);

        if let Entry::Occupied(entry) = hpke_entry {
            return Err(TreeIndexError::DuplicateHpkeKey(
                key_package_ref.to_string(),
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
        key_package_ref: &KeyPackageRef,
        key_package: &KeyPackage,
    ) -> Result<(), TreeIndexError> {
        self.packages.remove(key_package_ref);

        let pub_key = key_package
            .credential
            .public_key()?
            .to_uncompressed_bytes()?;

        self.credential_signature_key.remove(&pub_key);
        self.hpke_key.remove(key_package.hpke_init_key.as_ref());

        Ok(())
    }

    pub fn get_key_package_index(&self, key_package_ref: &KeyPackageRef) -> Option<LeafIndex> {
        self.packages.get(key_package_ref).cloned()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    pub fn key_package_refs(&self) -> impl Iterator<Item = &'_ KeyPackageRef> {
        self.packages.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cipher_suite::CipherSuite, key_package::test_utils::test_key_package, ProtocolVersion,
    };
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Clone, Debug)]
    struct TestData {
        pub key_package: KeyPackage,
        pub key_package_ref: KeyPackageRef,
        pub index: LeafIndex,
    }

    fn get_test_data(index: LeafIndex) -> TestData {
        let key_package = test_key_package(ProtocolVersion::Mls10, CipherSuite::P256Aes128V1);
        let key_package_ref = key_package.to_reference().unwrap();

        TestData {
            key_package,
            key_package_ref,
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
                .insert(d.key_package_ref, d.index, &d.key_package)
                .unwrap()
        });

        (test_data, test_index)
    }

    #[test]
    fn test_insert() {
        let (test_data, test_index) = test_setup();

        assert_eq!(test_index.packages.len(), test_data.len());
        assert_eq!(test_index.credential_signature_key.len(), test_data.len());
        assert_eq!(test_index.hpke_key.len(), test_data.len());

        test_data.into_iter().enumerate().for_each(|(i, d)| {
            assert_eq!(
                test_index.packages.get(&d.key_package_ref),
                Some(&LeafIndex(i as u32))
            );

            let pub_key = d
                .key_package
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
                test_index
                    .hpke_key
                    .get(d.key_package.hpke_init_key.as_ref()),
                Some(&LeafIndex(i as u32))
            );
        })
    }

    #[test]
    fn test_get_key_package_index() {
        let (test_data, test_index) = test_setup();

        let fetched_package_index = test_index.get_key_package_index(&test_data[0].key_package_ref);
        assert_eq!(fetched_package_index, Some(test_data[0].index));

        let not_found_ref = KeyPackageRef::from([0u8; 16]);
        assert_eq!(test_index.get_key_package_index(&not_found_ref), None)
    }

    #[test]
    fn test_insert_duplicate_kp() {
        let (test_data, mut test_index) = test_setup();

        let before_error = test_index.clone();

        let res = test_index.insert(
            test_data[1].key_package_ref.clone(),
            test_data[1].index,
            &test_data[1].key_package,
        );

        assert_matches!(res, Err(TreeIndexError::DuplicateKeyPackage(kpr, index))
                        if kpr == test_data[1].key_package_ref.to_string()
                        && index == test_data[1].index);

        assert_eq!(before_error, test_index);
    }

    #[test]
    fn test_insert_duplicate_credential_key() {
        let (test_data, mut test_index) = test_setup();

        let before_error = test_index.clone();

        let mut new_key_package =
            test_key_package(ProtocolVersion::Mls10, CipherSuite::P256Aes128V1);
        new_key_package.credential = test_data[1].key_package.credential.clone();

        let res = test_index.insert(
            new_key_package.to_reference().unwrap(),
            test_data[1].index,
            &new_key_package,
        );

        assert_matches!(res, Err(TreeIndexError::DuplicateSignatureKeys(kpr, index))
                        if kpr == new_key_package.to_reference().unwrap().to_string()
                        && index == test_data[1].index);

        assert_eq!(before_error, test_index);
    }

    #[test]
    fn test_insert_duplicate_hpke_key() {
        let (test_data, mut test_index) = test_setup();

        let before_error = test_index.clone();

        let mut new_key_package =
            test_key_package(ProtocolVersion::Mls10, CipherSuite::P256Aes128V1);
        new_key_package.hpke_init_key = test_data[1].key_package.hpke_init_key.clone();

        let res = test_index.insert(
            new_key_package.to_reference().unwrap(),
            test_data[1].index,
            &new_key_package,
        );

        assert_matches!(res, Err(TreeIndexError::DuplicateHpkeKey(kpr, index))
                        if kpr == new_key_package.to_reference().unwrap().to_string()
                        && index == test_data[1].index);

        assert_eq!(before_error, test_index);
    }

    #[test]
    fn test_remove() {
        let (test_data, mut test_index) = test_setup();

        test_index
            .remove(&test_data[1].key_package_ref, &test_data[1].key_package)
            .unwrap();

        assert_eq!(test_index.packages.len(), test_data.len() - 1);
        assert_eq!(
            test_index.credential_signature_key.len(),
            test_data.len() - 1
        );
        assert_eq!(test_index.hpke_key.len(), test_data.len() - 1);
        assert_eq!(test_index.packages.get(&test_data[1].key_package_ref), None);

        let pub_key = test_data[1]
            .key_package
            .credential
            .public_key()
            .unwrap()
            .to_uncompressed_bytes()
            .unwrap();

        assert_eq!(test_index.credential_signature_key.get(&pub_key), None);

        assert_eq!(
            test_index
                .hpke_key
                .get(test_data[1].key_package.hpke_init_key.as_ref()),
            None
        );
    }
}
