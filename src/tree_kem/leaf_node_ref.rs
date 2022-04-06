use super::leaf_node::{LeafNode, LeafNodeError};
use crate::{cipher_suite::CipherSuite, hash_reference::HashReference};
use std::ops::Deref;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct LeafNodeRef(HashReference);

impl Deref for LeafNodeRef {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ToString for LeafNodeRef {
    fn to_string(&self) -> String {
        hex::encode(self.deref())
    }
}

impl From<[u8; 16]> for LeafNodeRef {
    fn from(v: [u8; 16]) -> Self {
        Self(HashReference::from(v))
    }
}

impl LeafNode {
    pub fn to_reference(&self, cipher_suite: CipherSuite) -> Result<LeafNodeRef, LeafNodeError> {
        Ok(LeafNodeRef(HashReference::from_value(
            &self.tls_serialize_detached()?,
            b"MLS 1.0 Leaf Node Reference",
            cipher_suite,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        client::test_utils::get_test_credential,
        tree_kem::{
            leaf_node::test_utils::{get_test_capabilities, get_test_extensions, get_test_node},
            parent_hash::ParentHash,
        },
    };
    use tls_codec::Deserialize;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        input: Vec<u8>,
        #[serde(with = "hex::serde")]
        output: Vec<u8>,
    }

    impl TestCase {
        fn generate(path: &str) {
            let capabilities = get_test_capabilities();
            let extensions = get_test_extensions();

            let mut test_cases = Vec::new();

            for cipher_suite in CipherSuite::all() {
                let (credential, secret) = get_test_credential(cipher_suite, b"foo".to_vec());

                let (mut leaf_node, _secret_key) = get_test_node(
                    cipher_suite,
                    credential.clone(),
                    &secret,
                    Some(capabilities.clone()),
                    Some(extensions.clone()),
                );

                let initial_test_case = TestCase {
                    cipher_suite: cipher_suite as u16,
                    input: leaf_node.tls_serialize_detached().unwrap(),
                    output: leaf_node.to_reference(cipher_suite).unwrap().to_vec(),
                };

                test_cases.push(initial_test_case);

                leaf_node
                    .update(cipher_suite, b"test", None, None, &secret)
                    .unwrap();

                let update_test_case = TestCase {
                    cipher_suite: cipher_suite as u16,
                    input: leaf_node.tls_serialize_detached().unwrap(),
                    output: leaf_node.to_reference(cipher_suite).unwrap().to_vec(),
                };

                test_cases.push(update_test_case);

                leaf_node
                    .commit(cipher_suite, b"test", None, None, &secret, |_| {
                        Ok(ParentHash::empty())
                    })
                    .unwrap();

                let commit_test_case = TestCase {
                    cipher_suite: cipher_suite as u16,
                    input: leaf_node.tls_serialize_detached().unwrap(),
                    output: leaf_node.to_reference(cipher_suite).unwrap().to_vec(),
                };

                test_cases.push(commit_test_case);
            }

            std::fs::write(path, serde_json::to_string_pretty(&test_cases).unwrap()).unwrap();
        }
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(leaf_node_ref, TestCase::generate)
    }

    #[test]
    fn test_leaf_node_ref() {
        let cases = load_test_cases();

        for one_case in cases {
            let cipher_suite = CipherSuite::from_raw(one_case.cipher_suite);

            if cipher_suite.is_none() {
                println!("Skipping test for unsupported cipher suite");
                continue;
            }

            let leaf_node = LeafNode::tls_deserialize(&mut one_case.input.as_slice()).unwrap();
            let leaf_node_ref = leaf_node.to_reference(cipher_suite.unwrap()).unwrap();

            let expected_out = LeafNodeRef(HashReference::from(
                <[u8; 16]>::try_from(one_case.output).unwrap(),
            ));

            assert_eq!(expected_out, leaf_node_ref);
        }
    }
}
