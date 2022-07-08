use crate::{
    cipher_suite::CipherSuite,
    client_config::ProposalFilterInit,
    epoch::PublicEpochRepository,
    extension::ExternalSendersExt,
    group::{
        message_verifier::verify_plaintext_signature, proposal_effects, transcript_hashes, Content,
        ExternalGroupConfig, GroupCore, GroupError, InterimTranscriptHash, MLSMessage,
        MLSMessageCommitContent, MLSMessagePayload, PublicEpoch, StateUpdate, VerifiedPlaintext,
    },
    message::{ExternalProcessedMessage, ExternalProcessedMessagePayload},
    signer::{Signable, Signer},
    signing_identity::SigningIdentity,
    tree_kem::TreeKemPublic,
    AddProposal, Proposal, RemoveProposal,
};
use tls_codec::Deserialize;

use super::{
    commit_sender, find_tree,
    framing::{MLSPlaintext, Sender},
    message_signature::MessageSigningContext,
    message_verifier::SignaturePublicKeysContainer,
    GroupInfo, ProposalRef,
};

#[derive(Clone, Debug)]
pub struct ExternalGroup<C> {
    config: C,
    core: GroupCore,
}

impl<C: ExternalGroupConfig> ExternalGroup<C> {
    pub fn new(
        config: C,
        group_info: GroupInfo,
        public_tree: Option<TreeKemPublic>,
    ) -> Result<Self, GroupError> {
        let public_tree = find_tree(public_tree, &group_info)?;
        let context = group_info.group_context;

        let public_epoch = PublicEpoch {
            identifier: context.epoch,
            cipher_suite: context.cipher_suite,
            public_tree,
        };

        let interim_transcript_hash = InterimTranscriptHash::create(
            context.cipher_suite,
            &context.confirmed_transcript_hash,
            (&group_info.confirmation_tag).into(),
        )?;

        Ok(Self {
            config,
            core: GroupCore::new(context, public_epoch, interim_transcript_hash),
        })
    }

    #[inline(always)]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.core.cipher_suite()
    }

    pub fn process_incoming_bytes(
        &mut self,
        message: &[u8],
    ) -> Result<ExternalProcessedMessage, GroupError> {
        self.process_incoming_message(MLSMessage::tls_deserialize(&mut &*message)?)
    }

    pub fn process_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<ExternalProcessedMessage, GroupError> {
        let protocol_version = self.core.protocol_version();

        if message.version != protocol_version {
            return Err(GroupError::InvalidProtocol(
                protocol_version,
                message.version,
            ));
        }

        let (payload, sender, authenticated_data) = match message.payload {
            MLSMessagePayload::Plain(plaintext) => {
                let plaintext = if self.config.signatures_are_checked() {
                    verify_plaintext_signature(
                        SignaturePublicKeysContainer::RatchetTree(
                            &self.core.current_epoch.public_tree,
                        ),
                        &self.core.context,
                        plaintext,
                        false,
                        &self.core.external_signers(),
                        self.core.current_epoch.cipher_suite,
                    )?
                } else {
                    VerifiedPlaintext {
                        encrypted: false,
                        plaintext,
                    }
                };

                let plaintext = self.core.validate_incoming_message(plaintext)?;
                let credential = plaintext.credential(&self.core.current_epoch.public_tree)?;
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
            Content::Proposal(ref proposal) => {
                let proposal_ref = ProposalRef::from_plaintext(
                    self.cipher_suite(),
                    &plaintext,
                    plaintext.encrypted,
                )?;

                self.core.proposals.insert(
                    proposal_ref,
                    proposal.clone(),
                    plaintext.plaintext.content.sender,
                );

                Ok(ExternalProcessedMessagePayload::Proposal(proposal.clone()))
            }
            Content::Commit(_) => Ok(ExternalProcessedMessagePayload::Commit(
                self.process_commit(plaintext)?,
            )),
        }
    }

    fn process_commit(&mut self, plaintext: VerifiedPlaintext) -> Result<StateUpdate, GroupError> {
        let commit_content = MLSMessageCommitContent::new(&plaintext, plaintext.encrypted)?;
        let proposal_effects = proposal_effects(
            None,
            &self.core.proposals,
            &commit_content,
            self.core.context.extensions.get_extension()?,
            self.config.credential_validator(),
            &self.core.current_epoch.public_tree,
            self.config.proposal_filter(ProposalFilterInit::new(
                &self.core.current_epoch.public_tree,
                &self.core.context,
                plaintext.plaintext.content.sender.clone(),
            )),
        )?;

        let mut provisional_state = self.core.apply_proposals(
            &self.core.current_epoch.public_tree,
            proposal_effects,
            self.config.credential_validator(),
        )?;

        let sender = commit_sender(&commit_content, &provisional_state)?;

        provisional_state
            .public_tree
            .update_hashes(&mut vec![sender], &[])?;

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
            self.core.cipher_suite(),
            &self.core.interim_transcript_hash,
            commit_content,
            (&*plaintext).into(),
        )?;

        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash;
        provisional_group_context.tree_hash = provisional_state.public_tree.tree_hash()?;

        let next_epoch = PublicEpoch {
            identifier: provisional_group_context.epoch,
            cipher_suite: self.core.cipher_suite(),
            public_tree: provisional_state.public_tree,
        };

        self.core.context = provisional_group_context;

        self.config
            .epoch_repo()
            .insert(std::mem::replace(&mut self.core.current_epoch, next_epoch))
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        self.core.interim_transcript_hash = interim_transcript_hash;
        self.core.proposals.clear();

        Ok(state_update)
    }

    fn epoch_is_known(&self, id: u64) -> Result<bool, GroupError> {
        Ok(self.core.current_epoch.identifier == id
            || self
                .config
                .epoch_repo()
                .get(id)
                .map_err(|e| GroupError::EpochRepositoryError(e.into()))?
                .is_some())
    }

    pub fn propose_add<S: Signer>(
        &self,
        proposal: AddProposal,
        authenticated_data: Vec<u8>,
        signing_identity: &SigningIdentity,
        signer: &S,
    ) -> Result<MLSMessage, GroupError> {
        self.propose(
            Proposal::Add(proposal),
            authenticated_data,
            signing_identity,
            signer,
        )
    }

    pub fn propose_remove<S: Signer>(
        &self,
        proposal: RemoveProposal,
        authenticated_data: Vec<u8>,
        signing_identity: &SigningIdentity,
        signer: &S,
    ) -> Result<MLSMessage, GroupError> {
        self.propose(
            Proposal::Remove(proposal),
            authenticated_data,
            signing_identity,
            signer,
        )
    }

    fn propose<S: Signer>(
        &self,
        proposal: Proposal,
        authenticated_data: Vec<u8>,
        signing_identity: &SigningIdentity,
        signer: &S,
    ) -> Result<MLSMessage, GroupError> {
        let external_senders_ext = self
            .core
            .context
            .extensions
            .get_extension::<ExternalSendersExt>()?
            .ok_or(GroupError::ExternalProposalsDisabled)?;

        let sender_index = external_senders_ext
            .allowed_senders
            .into_iter()
            .position(|allowed_signer| *signing_identity == allowed_signer)
            .ok_or(GroupError::InvalidExternalSigningIdentity)?;

        let sender = Sender::External(sender_index as u32);

        let mut message = MLSPlaintext::new(
            self.core.context.group_id.clone(),
            self.core.context.epoch,
            sender,
            Content::Proposal(proposal),
            authenticated_data,
        );

        let signing_context = MessageSigningContext {
            group_context: None,
            encrypted: false,
        };

        message.sign(signer, &signing_context)?;

        Ok(MLSMessage {
            version: self.core.protocol_version(),
            payload: MLSMessagePayload::Plain(message),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        extension::{ExtensionList, ExternalSendersExt},
        group::{
            framing::MLSPlaintext,
            proposal::ProposalOrRef,
            proposal_ref::ProposalRef,
            test_utils::{test_group, TestGroup},
            Content, ExternalGroup, GroupError, InMemoryExternalGroupConfig, MLSMessage,
            MLSMessagePayload,
        },
        key_package::test_utils::test_key_package_with_id,
        message::{ExternalProcessedMessage, ExternalProcessedMessagePayload},
        signing_identity::{test_utils::get_test_signing_identity, SigningIdentity},
        tree_kem::node::LeafIndex,
        AddProposal, Proposal, ProtocolVersion, RemoveProposal,
    };
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::SecretKey;

    const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    fn test_group_with_one_commit(v: ProtocolVersion, cs: CipherSuite) -> TestGroup {
        let mut group = test_group(v, cs);
        let (commit, _) = group.commit(Vec::new()).unwrap();
        group.process_pending_commit(commit).unwrap();
        group
    }

    fn test_group_two_members(
        v: ProtocolVersion,
        cs: CipherSuite,
        ext_identity: Option<SigningIdentity>,
    ) -> TestGroup {
        let mut group = test_group_with_one_commit(v, cs);

        let bob_key_package = test_key_package_with_id(v, cs, "bob");

        let add_proposal = AddProposal {
            key_package: bob_key_package,
        };

        let mut proposals = vec![Proposal::Add(add_proposal)];

        if let Some(ext_signer) = ext_identity {
            let mut ext_list = ExtensionList::new();

            ext_list
                .set_extension(ExternalSendersExt {
                    allowed_senders: vec![ext_signer],
                })
                .unwrap();

            proposals.push(Proposal::GroupContextExtensions(ext_list))
        }

        let (commit, _) = group.commit(proposals).unwrap();
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
            group.group.external_commit_info(&group.signing_key)?,
            Some(public_tree.clone()),
        )
    }

    fn process_message(
        group: &mut ExternalGroup<InMemoryExternalGroupConfig>,
        payload: MLSMessagePayload,
    ) -> Result<ExternalProcessedMessage, GroupError> {
        group.process_incoming_message(MLSMessage {
            version: TEST_PROTOCOL_VERSION,
            payload,
        })
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
    fn external_group_can_process_proposals_by_reference() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice).unwrap();

        let bob_key_package =
            test_key_package_with_id(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let add_proposal = Proposal::Add(AddProposal {
            key_package: bob_key_package,
        });

        let packet = alice.propose(add_proposal.clone());

        let proposal_process = process_message(&mut server, packet.into()).unwrap();

        assert_matches!(
            proposal_process.message,
            ExternalProcessedMessagePayload::Proposal(ref p) if p == &add_proposal
        );

        let (commit, _) = alice.commit(vec![]).unwrap();
        let commit_result = process_message(&mut server, commit.plaintext.into()).unwrap();

        assert_matches!(commit_result.message, ExternalProcessedMessagePayload::Commit(state_update) if state_update.added.contains(&LeafIndex(1)));
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

        assert_eq!(
            server.core.current_epoch.public_tree.get_leaf_nodes().len(),
            2
        );
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
            Err(GroupError::InvalidPlaintextEpoch(1))
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

    fn setup_extern_proposal_test(
        extern_proposals_allowed: bool,
    ) -> (SigningIdentity, SecretKey, TestGroup) {
        let (server_identity, server_key) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"server".to_vec());

        let alice = test_group_two_members(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            extern_proposals_allowed.then(|| server_identity.clone()),
        );

        (server_identity, server_key, alice)
    }

    fn test_external_proposal<F>(proposal_creation: F)
    where
        F: Fn(
            &ExternalGroup<InMemoryExternalGroupConfig>,
            &SigningIdentity,
            &SecretKey,
        ) -> MLSPlaintext,
    {
        let (server_identity, server_key, mut alice) = setup_extern_proposal_test(true);

        let server = make_external_group(&alice).unwrap();

        let external_proposal = proposal_creation(&server, &server_identity, &server_key);

        let proposal_ref =
            ProposalRef::from_plaintext(TEST_CIPHER_SUITE, &external_proposal, false).unwrap();

        // Alice receives the proposal
        alice.process_message(external_proposal).unwrap();

        // Alice commits the proposal
        let (commit_data, _) = alice.commit(vec![]).unwrap();

        let commit = match &commit_data.plaintext.content.content {
            Content::Commit(commit) => commit,
            _ => panic!("not a commit"),
        };

        // The proposal should be in the resulting commit
        assert!(commit
            .proposals
            .contains(&ProposalOrRef::Reference(proposal_ref)))
    }

    #[test]
    fn external_group_can_propose_add() {
        test_external_proposal(|ext_group, signing_id, secret_key| {
            let charlie_key_package =
                test_key_package_with_id(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

            let add_proposal = AddProposal {
                key_package: charlie_key_package,
            };

            ext_group
                .propose_add(add_proposal, vec![], signing_id, secret_key)
                .unwrap()
                .into_plaintext()
                .unwrap()
        })
    }

    #[test]
    fn external_group_can_propose_remove() {
        test_external_proposal(|ext_group, signing_id, secret_key| {
            let remove_proposal = RemoveProposal {
                to_remove: LeafIndex(1),
            };

            ext_group
                .propose_remove(remove_proposal, vec![], signing_id, secret_key)
                .unwrap()
                .into_plaintext()
                .unwrap()
        })
    }

    #[test]
    fn external_group_external_proposal_not_allowed() {
        let (signing_id, secret_key, alice) = setup_extern_proposal_test(false);
        let server = make_external_group(&alice).unwrap();

        let charlie_key_package =
            test_key_package_with_id(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let add_proposal = AddProposal {
            key_package: charlie_key_package,
        };

        let res = server.propose_add(add_proposal, vec![], &signing_id, &secret_key);

        assert_matches!(res, Err(GroupError::ExternalProposalsDisabled));
    }

    #[test]
    fn external_group_external_signing_identity_invalid() {
        let (server_identity, server_key) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"server".to_vec());

        let alice = test_group_two_members(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            Some(get_test_signing_identity(TEST_CIPHER_SUITE, b"not server".to_vec()).0),
        );

        let server = make_external_group(&alice).unwrap();

        let remove_proposal = RemoveProposal {
            to_remove: LeafIndex(1),
        };

        let res = server.propose_remove(remove_proposal, vec![], &server_identity, &server_key);

        assert_matches!(res, Err(GroupError::InvalidExternalSigningIdentity));
    }
}
