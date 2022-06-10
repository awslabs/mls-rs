use crate::{
    cipher_suite::CipherSuite,
    epoch::PublicEpochRepository,
    group::{
        message_verifier::verify_plaintext_signature, proposal_effects, transcript_hashes,
        ConfirmationTag, Content, ExternalGroupConfig, GroupContext, GroupCore, GroupError,
        InterimTranscriptHash, MLSMessage, MLSMessageCommitContent, MLSMessagePayload,
        ProposalCache, ProtocolVersion, PublicEpoch, StateUpdate, VerifiedPlaintext,
    },
    message::{ExternalProcessedMessage, ExternalProcessedMessagePayload},
    tree_kem::TreeKemPublic,
};
use ferriscrypt::asym::ec_key::PublicKey;
use tls_codec::Deserialize;

use super::message_verifier::SignaturePublicKeysContainer;

#[derive(Clone, Debug)]
pub struct ExternalGroup<C> {
    config: C,
    core: GroupCore,
    current_epoch: PublicEpoch,
    interim_transcript_hash: InterimTranscriptHash,
}

impl<C: ExternalGroupConfig> ExternalGroup<C> {
    pub fn new(
        config: C,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        context: GroupContext,
        public_tree: TreeKemPublic,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<Self, GroupError> {
        Ok(Self {
            config,
            current_epoch: PublicEpoch {
                identifier: context.epoch,
                cipher_suite,
                public_tree,
            },
            interim_transcript_hash: InterimTranscriptHash::create(
                cipher_suite,
                &context.confirmed_transcript_hash,
                confirmation_tag.into(),
            )?,
            core: GroupCore {
                protocol_version,
                cipher_suite,
                proposals: ProposalCache::new(
                    protocol_version,
                    cipher_suite,
                    context.group_id.clone(),
                ),
                context,
            },
        })
    }

    pub fn process_incoming_bytes<F>(
        &mut self,
        message: &[u8],
        external_key_id_to_signing_key: F,
    ) -> Result<ExternalProcessedMessage, GroupError>
    where
        F: FnMut(&[u8]) -> Option<PublicKey>,
    {
        self.process_incoming_message(
            MLSMessage::tls_deserialize(&mut &*message)?,
            external_key_id_to_signing_key,
        )
    }

    pub fn process_incoming_message<F>(
        &mut self,
        message: MLSMessage,
        external_key_id_to_signing_key: F,
    ) -> Result<ExternalProcessedMessage, GroupError>
    where
        F: FnMut(&[u8]) -> Option<PublicKey>,
    {
        if message.version != self.core.protocol_version {
            return Err(GroupError::InvalidProtocol(
                self.core.protocol_version,
                message.version,
            ));
        }

        let (payload, sender, authenticated_data) = match message.payload {
            MLSMessagePayload::Plain(plaintext) => {
                if !self.epoch_is_known(plaintext.content.epoch)? {
                    return Err(GroupError::EpochNotFound(plaintext.content.epoch));
                }
                let plaintext = if self.config.signatures_are_checked() {
                    verify_plaintext_signature(
                        SignaturePublicKeysContainer::RatchetTree(&self.current_epoch.public_tree),
                        &self.core.context,
                        plaintext,
                        false,
                        external_key_id_to_signing_key,
                        self.current_epoch.cipher_suite,
                    )?
                } else {
                    VerifiedPlaintext {
                        encrypted: false,
                        plaintext,
                    }
                };
                let plaintext = self.core.validate_incoming_message(plaintext)?;
                let credential = plaintext.credential(&self.current_epoch.public_tree)?;
                let authenticated_data = plaintext.plaintext.content.authenticated_data.clone();
                (
                    self.process_incoming_plaintext(plaintext)?,
                    credential,
                    authenticated_data,
                )
            }
            MLSMessagePayload::Cipher(ciphertext) => {
                if !self.epoch_is_known(ciphertext.epoch)? {
                    return Err(GroupError::EpochNotFound(ciphertext.epoch));
                }
                let authenticated_data = ciphertext.authenticated_data.clone();
                (
                    ExternalProcessedMessagePayload::Ciphertext(ciphertext),
                    None,
                    authenticated_data,
                )
            }
            MLSMessagePayload::Welcome(welcome) => (
                ExternalProcessedMessagePayload::Welcome(welcome),
                None,
                Vec::new(),
            ),
            MLSMessagePayload::GroupInfo(info) => (
                ExternalProcessedMessagePayload::GroupInfo(info),
                None,
                Vec::new(),
            ),
            MLSMessagePayload::KeyPackage(key_package) => {
                let sender = key_package.leaf_node.signing_identity.credential.clone();
                (
                    ExternalProcessedMessagePayload::KeyPackage(key_package),
                    Some(sender),
                    Vec::new(),
                )
            }
        };

        Ok(ExternalProcessedMessage {
            sender_credential: sender,
            message: payload,
            authenticated_data,
        })
    }

    fn process_incoming_plaintext(
        &mut self,
        plaintext: VerifiedPlaintext,
    ) -> Result<ExternalProcessedMessagePayload, GroupError> {
        match plaintext.plaintext.content.content {
            Content::Application(_) => Err(GroupError::UnencryptedApplicationMessage),
            Content::Proposal(proposal) => Ok(ExternalProcessedMessagePayload::Proposal(proposal)),
            Content::Commit(_) => Ok(ExternalProcessedMessagePayload::Commit(
                self.process_commit(plaintext)?,
            )),
        }
    }

    fn process_commit(&mut self, plaintext: VerifiedPlaintext) -> Result<StateUpdate, GroupError> {
        if plaintext.content.epoch != self.current_epoch.identifier {
            return Err(GroupError::InvalidPlaintextEpoch);
        }

        let commit_content = MLSMessageCommitContent::new(&plaintext, plaintext.encrypted)?;
        let proposal_effects = proposal_effects(
            &self.core.proposals,
            &commit_content,
            self.core.context.extensions.get_extension()?,
            self.config.credential_validator(),
            &self.current_epoch.public_tree,
        )?;

        let provisional_state = self.core.apply_proposals(
            &self.current_epoch.public_tree,
            proposal_effects,
            self.config.credential_validator(),
        )?;

        let state_update = StateUpdate::from(&provisional_state);

        // Verify that the path value is populated if the proposals vector contains any Update
        // or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.
        if provisional_state.path_update_required && commit_content.commit.path.is_none() {
            return Err(GroupError::CommitMissingPath);
        }

        let mut provisional_group_context = provisional_state.group_context;

        // Bump up the epoch in the provisional group context
        provisional_group_context.epoch = provisional_state.epoch;

        // Update the new GroupContext's confirmed and interim transcript hashes using the new Commit.
        let (interim_transcript_hash, confirmed_transcript_hash) = transcript_hashes(
            self.core.cipher_suite,
            &self.interim_transcript_hash,
            commit_content,
            (&*plaintext).into(),
        )?;

        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash;
        provisional_group_context.tree_hash = provisional_state.public_tree.tree_hash()?;

        let next_epoch = PublicEpoch {
            identifier: provisional_group_context.epoch,
            cipher_suite: self.core.cipher_suite,
            public_tree: provisional_state.public_tree,
        };

        self.core.context = provisional_group_context;

        self.config
            .epoch_repo()
            .insert(std::mem::replace(&mut self.current_epoch, next_epoch))
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        self.interim_transcript_hash = interim_transcript_hash;
        self.core.proposals.clear();

        Ok(state_update)
    }

    fn epoch_is_known(&self, id: u64) -> Result<bool, GroupError> {
        Ok(self.current_epoch.identifier == id
            || self
                .config
                .epoch_repo()
                .get(id)
                .map_err(|e| GroupError::EpochRepositoryError(e.into()))?
                .is_some())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        group::{
            test_utils::{test_group, TestGroup},
            Content, ExternalGroup, GroupError, InMemoryExternalGroupConfig, MLSMessage,
            MLSMessagePayload,
        },
        message::{ExternalProcessedMessage, ExternalProcessedMessagePayload},
        ProtocolVersion,
    };
    use assert_matches::assert_matches;

    const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    fn test_group_with_one_commit(v: ProtocolVersion, cs: CipherSuite) -> TestGroup {
        let mut group = test_group(v, cs);
        let (commit, _) = group.commit(Vec::new()).unwrap();
        group.process_pending_commit(commit).unwrap();
        group
    }

    fn make_external_group(
        group: &TestGroup,
    ) -> Result<ExternalGroup<InMemoryExternalGroupConfig>, GroupError> {
        make_external_group_with_config(group, Default::default())
    }

    fn make_external_group_with_config(
        group: &TestGroup,
        config: InMemoryExternalGroupConfig,
    ) -> Result<ExternalGroup<InMemoryExternalGroupConfig>, GroupError> {
        let public_tree = group.group.current_epoch_tree().unwrap();

        ExternalGroup::new(
            config,
            group.group.protocol_version(),
            public_tree.cipher_suite,
            group.group.context().clone(),
            public_tree.clone(),
            &group
                .group
                .external_commit_info(&group.signing_key)
                .unwrap()
                .confirmation_tag,
        )
    }

    fn process_message(
        group: &mut ExternalGroup<InMemoryExternalGroupConfig>,
        payload: MLSMessagePayload,
    ) -> Result<ExternalProcessedMessage, GroupError> {
        group.process_incoming_message(
            MLSMessage {
                version: TEST_PROTOCOL_VERSION,
                payload,
            },
            |_| None,
        )
    }

    #[test]
    fn external_group_can_be_created() {
        ProtocolVersion::all()
            .flat_map(|v| CipherSuite::all().map(move |cs| (v, cs)))
            .for_each(|(v, cs)| {
                make_external_group(&test_group_with_one_commit(v, cs)).unwrap();
            });
    }

    #[test]
    fn external_group_can_process_commit() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice).unwrap();
        let (commit, _) = alice.commit(Vec::new()).unwrap();
        process_message(&mut server, commit.plaintext.into()).unwrap();
    }

    #[test]
    fn external_group_can_process_commit_adding_member() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice).unwrap();
        let (_, commit) = alice.join("bob");

        let update = match process_message(&mut server, commit.into()).unwrap().message {
            ExternalProcessedMessagePayload::Commit(update) => update,
            _ => panic!("Expected processed commit"),
        };

        assert_eq!(update.added.len(), 1);
        assert_eq!(server.current_epoch.public_tree.get_leaf_nodes().len(), 2);
    }

    #[test]
    fn external_group_rejects_commit_not_for_current_epoch() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice).unwrap();
        let (commit, _) = alice.commit(Vec::new()).unwrap();
        alice.process_pending_commit(commit.clone()).unwrap();
        process_message(&mut server, commit.plaintext.clone().into()).unwrap();

        assert_matches!(
            process_message(&mut server, commit.plaintext.into()),
            Err(GroupError::InvalidPlaintextEpoch)
        );
    }

    #[test]
    fn external_group_can_reject_message_with_invalid_signature() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut server = make_external_group_with_config(
            &alice,
            InMemoryExternalGroupConfig {
                signatures_checked: true,
                ..Default::default()
            },
        )
        .unwrap();

        let (mut commit, _) = alice.commit(Vec::new()).unwrap();
        commit.plaintext.auth.signature = Vec::new().into();

        assert_matches!(
            process_message(&mut server, commit.plaintext.into()),
            Err(GroupError::SignatureError(_))
        );
    }
    #[test]
    fn external_group_can_skip_signature_check() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut server = make_external_group_with_config(
            &alice,
            InMemoryExternalGroupConfig {
                signatures_checked: false,
                ..Default::default()
            },
        )
        .unwrap();

        let (commit, _) = alice.commit(Vec::new()).unwrap();
        assert_matches!(process_message(&mut server, commit.plaintext.into()), Ok(_));
    }

    #[test]
    fn external_group_rejects_unencrypted_application_message() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice).unwrap();
        let plaintext = alice.make_plaintext(Content::Application(b"hello".to_vec()));
        assert_matches!(
            process_message(&mut server, plaintext.into()),
            Err(GroupError::UnencryptedApplicationMessage)
        );
    }
}
