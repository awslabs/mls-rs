// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use super::{ciphertext_processor::GroupStateProvider, framing::ContentType, secret_tree::KeyType};
use crate::{client::MlsError, tree_kem::node::NodeIndex};
use mls_rs_core::crypto::CipherSuiteProvider;

/// Key generation authentication used when encrypting a group message.
/// Defends against in-group forgery attacks where group members can replay messages sent
/// by other members, see https://eprint.iacr.org/2025/554.
#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::ffi_type)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum GenerationAuthMode {
    /// No generation authentication.
    #[default]
    None,
    /// Prepends the 4-byte generation in big endian as plaintext to PrivateMessage's
    /// authenticated data.
    ///
    /// # Warning
    ///
    /// This sends the generation in the clear, allowing non-group members observing
    /// payloads to order messages and learn how many messages a member has sent.
    Plaintext,
}

impl GenerationAuthMode {
    /// Prepend the key generation to `authenticated_data` based on the mode.
    pub(super) fn prepend_generation<GS: GroupStateProvider, CS: CipherSuiteProvider>(
        &self,
        group_state: &mut GS,
        cipher_suite_provider: &CS,
        content_type: ContentType,
        authenticated_data: &mut Vec<u8>,
    ) -> Result<Vec<u8>, MlsError> {
        match self {
            GenerationAuthMode::None => Ok(authenticated_data.to_vec()),

            GenerationAuthMode::Plaintext => {
                let key_type = match content_type {
                    ContentType::Application => KeyType::Application,
                    _ => KeyType::Handshake,
                };
                let self_index = NodeIndex::from(group_state.self_index());
                let generation = group_state
                    .epoch_secrets_mut()
                    .secret_tree
                    .peek_next_key_generation(cipher_suite_provider, self_index, key_type)?;

                let mut res = generation.to_be_bytes().to_vec();
                res.append(authenticated_data);
                Ok(res)
            }
        }
    }

    /// Verify `sender_data_generation` matches the key generation prefix in
    /// `authenticated_data`.
    pub(super) fn verify_generation(
        &self,
        sender_data_generation: u32,
        authenticated_data: &[u8],
    ) -> Result<(), MlsError> {
        match self {
            GenerationAuthMode::None => Ok(()),

            GenerationAuthMode::Plaintext => {
                if authenticated_data.len() < 4 {
                    return Err(MlsError::MissingAuthGeneration);
                }
                let auth_generation = u32::from_be_bytes(authenticated_data[0..4].try_into()?);
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
