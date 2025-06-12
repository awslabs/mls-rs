// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use super::framing::ContentType;
use crate::{client::MlsError, group::secret_tree::SecretTree, tree_kem::node::NodeIndex};
use mls_rs_core::crypto::CipherSuiteProvider;

#[allow(unused_imports)]
use super::secret_tree::KeyType;

/// Key generation authentication used when encrypting a group message.
///
/// Defends against in-group forgery attacks where group members can replay messages sent
/// by other members, see https://eprint.iacr.org/2025/554.
#[cfg(feature = "private_message")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
#[non_exhaustive]
pub enum GenerationAuth {
    /// No generation authentication.
    #[default]
    None,

    /// Prepends the 4-byte generation in big endian as plaintext to PrivateMessage's
    /// authenticated data.
    ///
    /// # Warnings
    ///
    /// * This sends the generation in the clear, allowing non-group members observing
    ///   payloads to order messages and learn how many messages a member has sent.
    /// * The entire group MUST cryptographically agree on the variant used to avoid an
    ///   attacker pretending that an unauthenticated generation ciphertext is
    ///   authenticated in another mode.
    #[cfg(feature = "generation_authentication_in_plaintext")]
    Plaintext,
}

impl GenerationAuth {
    /// Prepend the ratchet's next key generation to `authenticated_data`.
    #[allow(unused_variables)]
    pub(super) fn prepend_to_auth_data<CS: CipherSuiteProvider>(
        &self,
        secret_tree: &mut SecretTree<NodeIndex>,
        cipher_suite_provider: &CS,
        self_index: u32,
        content_type: ContentType,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, MlsError> {
        match self {
            GenerationAuth::None => Ok(authenticated_data),

            #[cfg(feature = "generation_authentication_in_plaintext")]
            GenerationAuth::Plaintext => {
                let key_type = match content_type {
                    ContentType::Application => KeyType::Application,
                    _ => KeyType::Handshake,
                };
                let generation = secret_tree.peek_next_key_generation(
                    cipher_suite_provider,
                    self_index,
                    key_type,
                )?;
                Ok([&generation.to_be_bytes(), authenticated_data.as_slice()].concat())
            }
        }
    }

    /// Verify `sender_data_generation` matches the key generation prefix in
    /// `authenticated_data`.
    #[allow(unused_variables)]
    pub(super) fn verify(
        &self,
        sender_data_generation: u32,
        authenticated_data: &[u8],
    ) -> Result<(), MlsError> {
        match self {
            GenerationAuth::None => Ok(()),

            #[cfg(feature = "generation_authentication_in_plaintext")]
            GenerationAuth::Plaintext => {
                if authenticated_data.len() < 4 {
                    return Err(MlsError::MissingAuthGeneration);
                }
                let auth_generation = u32::from_be_bytes(
                    authenticated_data[0..4]
                        .try_into()
                        .map_err(|_| MlsError::TryFromSliceError)?,
                );
                if sender_data_generation != auth_generation {
                    return Err(MlsError::GenerationMismatch {
                        auth_generation,
                        sender_data_generation,
                    });
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cipher_suite::CipherSuite, crypto::test_utils::TestCryptoProvider, CryptoProvider,
    };

    #[cfg(all(
        feature = "private_message",
        feature = "generation_authentication_in_plaintext"
    ))]
    use {
        crate::group::test_utils::random_bytes, assert_matches::assert_matches, zeroize::Zeroizing,
    };

    #[cfg(feature = "private_message")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    fn test_none_prepend_to_auth_data() {
        let gen_auth = GenerationAuth::None;
        let mut secret_tree = SecretTree::empty();
        let crypto_provider = &TestCryptoProvider::new()
            .cipher_suite_provider(CipherSuite::P256_AES128)
            .unwrap();

        for auth_data in [b"".to_vec(), b"authenticate me".to_vec()] {
            assert_eq!(
                gen_auth
                    .prepend_to_auth_data(
                        &mut secret_tree,
                        crypto_provider,
                        0,
                        ContentType::Application,
                        auth_data.clone()
                    )
                    .unwrap(),
                auth_data
            );
        }
    }

    #[cfg(feature = "private_message")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    fn test_none_verify() {
        let gen_auth = GenerationAuth::None;
        for auth_data in [b"".to_vec(), b"authenticate me".to_vec()] {
            assert!(gen_auth.verify(5u32, &auth_data).is_ok());
        }
    }

    #[cfg(all(
        feature = "private_message",
        feature = "generation_authentication_in_plaintext"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    fn test_plaintext_prepend_to_auth_data() {
        let gen_auth = GenerationAuth::Plaintext;
        let crypto_provider = &TestCryptoProvider::new()
            .cipher_suite_provider(CipherSuite::P256_AES128)
            .unwrap();
        let mut secret_tree = SecretTree::new(
            16u32,
            Zeroizing::new(random_bytes(crypto_provider.kdf_extract_size())),
        );

        for auth_data in [b"".to_vec(), b"authenticate me".to_vec()] {
            assert_eq!(
                gen_auth
                    .prepend_to_auth_data(
                        &mut secret_tree,
                        crypto_provider,
                        12,
                        ContentType::Application,
                        auth_data.clone()
                    )
                    .unwrap(),
                [&0u32.to_be_bytes(), auth_data.as_slice()].concat()
            );
        }
    }

    #[cfg(all(
        feature = "private_message",
        feature = "generation_authentication_in_plaintext"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    fn test_plaintext_prepend_to_auth_data_errors() {
        let gen_auth = GenerationAuth::Plaintext;
        let crypto_provider = &TestCryptoProvider::new()
            .cipher_suite_provider(CipherSuite::P256_AES128)
            .unwrap();
        let mut secret_tree = SecretTree::new(
            16u32,
            Zeroizing::new(random_bytes(crypto_provider.kdf_extract_size())),
        );

        assert_matches!(
            gen_auth.prepend_to_auth_data(
                &mut secret_tree,
                crypto_provider,
                100,
                ContentType::Application,
                b"".to_vec()
            ),
            Err(MlsError::InvalidLeafConsumption)
        );
    }

    #[cfg(all(
        feature = "private_message",
        feature = "generation_authentication_in_plaintext"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    fn test_plaintext_verify() {
        let gen_auth = GenerationAuth::Plaintext;
        for auth_data in [
            5u32.to_be_bytes().to_vec(),
            [&5u32.to_be_bytes(), b"authenticate me".as_slice()].concat(),
        ] {
            assert!(gen_auth.verify(5u32, &auth_data).is_ok());
        }
    }

    #[cfg(all(
        feature = "private_message",
        feature = "generation_authentication_in_plaintext"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    fn test_plaintext_verify_errors() {
        let gen_auth = GenerationAuth::Plaintext;
        assert_matches!(
            gen_auth.verify(0u32, b""),
            Err(MlsError::MissingAuthGeneration)
        );
        assert_matches!(
            gen_auth.verify(0u32, b"1"),
            Err(MlsError::MissingAuthGeneration)
        );
        assert_matches!(
            gen_auth.verify(0u32, &10u32.to_be_bytes()),
            Err(MlsError::GenerationMismatch { .. })
        );
    }
}
