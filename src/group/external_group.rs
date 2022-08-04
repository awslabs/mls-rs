use crate::{
    cipher_suite::CipherSuite,
    client_config::ProposalFilterInit,
    extension::ExternalSendersExt,
    group::{
        proposal_effects, transcript_hashes, Content, GroupCore, GroupError, InterimTranscriptHash,
        MLSMessage, MLSMessagePayload, StateUpdate,
    },
    message::{Event, ExternalEvent, ProcessedMessage},
    signer::Signer,
    signing_identity::SigningIdentity,
    AddProposal, ExternalClientConfig, Proposal, RemoveProposal,
};
use tls_codec::Deserialize;

use super::{
    commit_sender, find_tree,
    framing::{MLSPlaintext, Sender, WireFormat},
    message_signature::MLSAuthenticatedContent,
    ProposalRef,
};

#[derive(Clone, Debug)]
pub struct ExternalGroup<C> {
    config: C,
    core: GroupCore,
}

impl<C: ExternalClientConfig> ExternalGroup<C> {
    pub fn join(
        config: C,
        group_info: MLSMessage,
        tree_data: Option<&[u8]>,
    ) -> Result<Self, GroupError> {
        let wire_format = group_info.wire_format();

        let group_info = group_info.into_group_info().ok_or_else(|| {
            GroupError::UnexpectedMessageType(vec![WireFormat::GroupInfo], wire_format)
        })?;

        let public_tree = find_tree(tree_data, &group_info)?;
        let context = group_info.group_context;

        let interim_transcript_hash = InterimTranscriptHash::create(
            context.cipher_suite,
            &context.confirmed_transcript_hash,
            &group_info.confirmation_tag,
        )?;

        Ok(Self {
            config,
            core: GroupCore::new(context, public_tree, interim_transcript_hash),
        })
    }

    #[inline(always)]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.core.cipher_suite()
    }

    pub fn process_incoming_bytes(
        &mut self,
        message: &[u8],
    ) -> Result<ProcessedMessage<ExternalEvent>, GroupError> {
        self.process_incoming_message(MLSMessage::tls_deserialize(&mut &*message)?)
    }

    pub fn process_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<ProcessedMessage<ExternalEvent>, GroupError> {
        self.core.check_metadata(&message)?;

        let wire_format = message.wire_format();

        let auth_content = match message.payload {
            MLSMessagePayload::Plain(plaintext) => self
                .core
                .verify_plaintext_authentication(None, None, plaintext),
            MLSMessagePayload::Cipher(ciphertext) => {
                return Ok(ProcessedMessage {
                    event: ExternalEvent::Ciphertext(ciphertext),
                    sender_index: None,
                    authenticated_data: vec![],
                })
            }
            _ => Err(GroupError::UnexpectedMessageType(
                vec![WireFormat::Plain, WireFormat::Cipher],
                wire_format,
            )),
        }?;

        let authenticated_data = auth_content.content.authenticated_data.clone();

        let sender_index = match auth_content.content.sender {
            Sender::Member(index) => Some(index.0),
            _ => None,
        };

        let message_payload = match auth_content.content.content {
            Content::Application(data) => Ok(Event::ApplicationMessage(data)),
            Content::Commit(_) => self.process_commit(auth_content).map(Event::Commit),
            Content::Proposal(ref proposal) => {
                let proposal_ref = ProposalRef::from_content(self.cipher_suite(), &auth_content)?;

                self.core.proposals.insert(
                    proposal_ref,
                    proposal.clone(),
                    auth_content.content.sender,
                );

                Ok(Event::Proposal(proposal.clone()))
            }
        }?;

        Ok(ProcessedMessage {
            event: message_payload.try_into()?,
            sender_index,
            authenticated_data,
        })
    }

    fn process_commit(
        &mut self,
        auth_content: MLSAuthenticatedContent,
    ) -> Result<StateUpdate, GroupError> {
        let (commit, sender) = match auth_content.content.content {
            Content::Commit(ref commit) => Ok((commit, &auth_content.content.sender)),
            _ => Err(GroupError::NotCommitContent(
                auth_content.content.content_type(),
            )),
        }?;

        let proposal_effects = proposal_effects(
            None,
            &self.core.proposals,
            commit,
            sender,
            self.core.context.extensions.get_extension()?,
            self.config.credential_validator(),
            &self.core.current_tree,
            self.config.proposal_filter(ProposalFilterInit::new(
                &self.core.current_tree,
                &self.core.context,
                auth_content.content.sender.clone(),
            )),
        )?;

        let mut provisional_state = self.core.apply_proposals(proposal_effects)?;

        let sender = commit_sender(sender, &provisional_state)?;

        provisional_state
            .public_tree
            .update_hashes(&mut vec![sender], &[])?;

        let state_update = StateUpdate::from(&provisional_state);

        // Verify that the path value is populated if the proposals vector contains any Update
        // or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.
        if provisional_state.path_update_required && commit.path.is_none() {
            return Err(GroupError::CommitMissingPath);
        }

        let mut provisional_group_context = provisional_state.group_context;

        // Bump up the epoch in the provisional group context
        provisional_group_context.epoch = provisional_state.epoch;

        // Update the new GroupContext's confirmed and interim transcript hashes using the new Commit.
        let (interim_transcript_hash, confirmed_transcript_hash) = transcript_hashes(
            self.core.cipher_suite(),
            &self.core.interim_transcript_hash,
            &auth_content,
        )?;

        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash;
        provisional_group_context.tree_hash = provisional_state.public_tree.tree_hash()?;

        self.core.current_tree = provisional_state.public_tree;
        self.core.context = provisional_group_context;
        self.core.interim_transcript_hash = interim_transcript_hash;
        self.core.proposals.clear();

        Ok(state_update)
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

        let auth_content = MLSAuthenticatedContent::new_signed(
            &self.core.context,
            sender,
            Content::Proposal(proposal),
            signer,
            WireFormat::Plain,
            authenticated_data,
        )?;

        let plaintext = MLSPlaintext {
            content: auth_content.content,
            auth: auth_content.auth,
            membership_tag: None,
        };

        Ok(MLSMessage {
            version: self.core.protocol_version(),
            payload: MLSMessagePayload::Plain(plaintext),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        extension::{ExtensionList, ExternalSendersExt},
        group::{
            proposal::ProposalOrRef,
            proposal_ref::ProposalRef,
            test_utils::{test_group, TestGroup},
            Content, ExternalGroup, GroupError, MLSMessage, MLSMessagePayload,
        },
        key_package::test_utils::test_key_package_with_id,
        message::ExternalEvent,
        signing_identity::{test_utils::get_test_signing_identity, SigningIdentity},
        tree_kem::node::LeafIndex,
        AddProposal, InMemoryExternalClientConfig, Proposal, ProtocolVersion, RemoveProposal,
    };
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::SecretKey;

    const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    fn test_group_with_one_commit(v: ProtocolVersion, cs: CipherSuite) -> TestGroup {
        let mut group = test_group(v, cs);
        group.commit(Vec::new()).unwrap();
        group.process_pending_commit().unwrap();
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

        group.commit(proposals).unwrap();
        group.process_pending_commit().unwrap();
        group
    }

    fn make_external_group(group: &TestGroup) -> ExternalGroup<InMemoryExternalClientConfig> {
        make_external_group_with_config(group, Default::default())
    }

    fn make_external_group_with_config(
        group: &TestGroup,
        config: InMemoryExternalClientConfig,
    ) -> ExternalGroup<InMemoryExternalClientConfig> {
        let public_tree = group.group.export().unwrap().current_tree_data;

        ExternalGroup::join(
            config,
            group.group.group_info_message().unwrap(),
            Some(&public_tree),
        )
        .unwrap()
    }

    #[test]
    fn external_group_can_be_created() {
        ProtocolVersion::all()
            .flat_map(|v| CipherSuite::all().map(move |cs| (v, cs)))
            .for_each(|(v, cs)| {
                make_external_group(&test_group_with_one_commit(v, cs));
            });
    }

    #[test]
    fn external_group_can_process_commit() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice);
        let (commit, _) = alice.commit(Vec::new()).unwrap();
        server.process_incoming_message(commit).unwrap();
    }

    #[test]
    fn external_group_can_process_proposals_by_reference() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice);

        let bob_key_package =
            test_key_package_with_id(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let add_proposal = Proposal::Add(AddProposal {
            key_package: bob_key_package,
        });

        let packet = alice.propose(add_proposal.clone());

        let proposal_process = server.process_incoming_message(packet).unwrap();

        assert_matches!(
            proposal_process.event,
            ExternalEvent::Proposal(ref p) if p == &add_proposal
        );

        let (commit, _) = alice.commit(vec![]).unwrap();
        let commit_result = server.process_incoming_message(commit).unwrap();

        assert_matches!(commit_result.event, ExternalEvent::Commit(state_update) if state_update.added.contains(&LeafIndex(1)));
    }

    #[test]
    fn external_group_can_process_commit_adding_member() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice);
        let (_, commit) = alice.join("bob");

        let update = match server.process_incoming_message(commit).unwrap().event {
            ExternalEvent::Commit(update) => update,
            _ => panic!("Expected processed commit"),
        };

        assert_eq!(update.added.len(), 1);
        assert_eq!(server.core.current_tree.get_leaf_nodes().len(), 2);
    }

    #[test]
    fn external_group_rejects_commit_not_for_current_epoch() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice);

        let (mut commit, _) = alice.commit(vec![]).unwrap();

        match commit.payload {
            MLSMessagePayload::Plain(ref mut plain) => plain.content.epoch = 0,
            _ => panic!("Unexpected non-plaintext data"),
        };

        assert_matches!(
            server.process_incoming_message(commit),
            Err(GroupError::InvalidEpoch(0))
        );
    }

    #[test]
    fn external_group_can_reject_message_with_invalid_signature() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut server =
            make_external_group_with_config(&alice, InMemoryExternalClientConfig::default());

        let (mut commit, _) = alice.commit(Vec::new()).unwrap();

        match commit.payload {
            MLSMessagePayload::Plain(ref mut plain) => plain.auth.signature = Vec::new().into(),
            _ => panic!("Unexpected non-plaintext data"),
        };

        assert_matches!(
            server.process_incoming_message(commit),
            Err(GroupError::SignatureError(_))
        );
    }

    #[test]
    fn external_group_rejects_unencrypted_application_message() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice);
        let plaintext = alice.make_plaintext(Content::Application(b"hello".to_vec()));

        assert_matches!(
            server.process_incoming_message(plaintext),
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
            &ExternalGroup<InMemoryExternalClientConfig>,
            &SigningIdentity,
            &SecretKey,
        ) -> MLSMessage,
    {
        let (server_identity, server_key, mut alice) = setup_extern_proposal_test(true);
        let server = make_external_group(&alice);

        // Create an external proposal
        let external_proposal = proposal_creation(&server, &server_identity, &server_key);
        let auth_content = external_proposal.clone().into_plaintext().unwrap().into();
        let proposal_ref = ProposalRef::from_content(TEST_CIPHER_SUITE, &auth_content).unwrap();

        // Alice receives the proposal
        alice.process_message(external_proposal).unwrap();

        // Alice commits the proposal
        let (commit_data, _) = alice.commit(vec![]).unwrap();

        let commit = match commit_data.into_plaintext().unwrap().content.content {
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
        })
    }

    #[test]
    fn external_group_external_proposal_not_allowed() {
        let (signing_id, secret_key, alice) = setup_extern_proposal_test(false);
        let server = make_external_group(&alice);

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

        let server = make_external_group(&alice);

        let remove_proposal = RemoveProposal {
            to_remove: LeafIndex(1),
        };

        let res = server.propose_remove(remove_proposal, vec![], &server_identity, &server_key);

        assert_matches!(res, Err(GroupError::InvalidExternalSigningIdentity));
    }
}
