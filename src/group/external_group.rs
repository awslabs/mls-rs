use crate::{
    cipher_suite::CipherSuite,
    client_config::ProposalFilterInit,
    extension::ExternalSendersExt,
    group::{Content, GroupCore, GroupError, InterimTranscriptHash, MLSMessage, MLSMessagePayload},
    signer::Signer,
    signing_identity::SigningIdentity,
    tree_kem::{node::LeafIndex, path_secret::PathSecret, TreeKemPrivate},
    AddProposal, ExternalClientConfig, Proposal, RemoveProposal,
};

use super::{
    confirmation_tag::ConfirmationTag,
    find_tree,
    framing::{MLSCiphertext, MLSPlaintext, Sender, WireFormat},
    message_processor::{EventOrContent, MessageProcessor, ProcessedMessage, ProvisionalState},
    message_signature::MLSAuthenticatedContent,
    ExternalEvent, ProposalRef,
};

#[derive(Clone, Debug)]
pub struct ExternalGroup<C> {
    config: C,
    core: GroupCore,
}

impl<C: ExternalClientConfig + Clone> ExternalGroup<C> {
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
            core: GroupCore::new(
                context,
                public_tree,
                interim_transcript_hash,
                group_info.confirmation_tag,
            ),
        })
    }

    #[inline(always)]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.core.cipher_suite()
    }

    pub fn process_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<ProcessedMessage<ExternalEvent>, GroupError> {
        MessageProcessor::process_incoming_message(self, message)
    }

    pub fn propose_add<S: Signer>(
        &mut self,
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
        &mut self,
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
        &mut self,
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
            sender.clone(),
            Content::Proposal(proposal.clone()),
            signer,
            WireFormat::Plain,
            authenticated_data,
        )?;

        self.core.proposals.insert(
            ProposalRef::from_content(self.core.cipher_suite(), &auth_content)?,
            proposal,
            sender,
        );

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

impl<C> MessageProcessor<ExternalEvent> for ExternalGroup<C>
where
    C: ExternalClientConfig + Clone,
{
    type ProposalFilter = C::ProposalFilter;
    type CredentialValidator = C::CredentialValidator;

    fn self_index(&self) -> Option<LeafIndex> {
        None
    }

    fn proposal_filter(&self, init: ProposalFilterInit<'_>) -> Self::ProposalFilter {
        self.config.proposal_filter(init)
    }

    fn verify_plaintext_authentication(
        &self,
        message: MLSPlaintext,
    ) -> Result<EventOrContent<ExternalEvent>, GroupError> {
        let auth_content = crate::group::message_verifier::verify_plaintext_authentication(
            message, None, None, &self.core,
        )?;

        Ok(EventOrContent::Content(auth_content))
    }

    fn process_ciphertext(
        &mut self,
        cipher_text: MLSCiphertext,
    ) -> Result<EventOrContent<ExternalEvent>, GroupError> {
        Ok(EventOrContent::Event(ExternalEvent::Ciphertext(
            cipher_text,
        )))
    }

    fn update_key_schedule(
        &mut self,
        _secrets: Option<(TreeKemPrivate, PathSecret)>,
        interim_transcript_hash: InterimTranscriptHash,
        confirmation_tag: ConfirmationTag,
        provisional_public_state: ProvisionalState,
    ) -> Result<(), GroupError> {
        self.core.context = provisional_public_state.group_context;
        self.core.proposals.clear();
        self.core.interim_transcript_hash = interim_transcript_hash;
        self.core.current_tree = provisional_public_state.public_tree;
        self.core.confirmation_tag = confirmation_tag;

        Ok(())
    }

    fn credential_validator(&self) -> Self::CredentialValidator {
        self.config.credential_validator()
    }

    fn group_state(&self) -> &GroupCore {
        &self.core
    }

    fn group_state_mut(&mut self) -> &mut GroupCore {
        &mut self.core
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
            Content, ExternalEvent, ExternalGroup, GroupError, MLSMessage, MLSMessagePayload,
        },
        key_package::test_utils::test_key_package_with_id,
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
        alice.group.process_pending_commit().unwrap();
        server.process_incoming_message(commit).unwrap();

        assert_eq!(alice.group.core, server.core);
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
        alice.group.process_pending_commit().unwrap();

        let commit_result = server.process_incoming_message(commit).unwrap();

        assert_matches!(commit_result.event, ExternalEvent::Commit(state_update) if state_update.added.contains(&LeafIndex(1)));

        assert_eq!(alice.group.core, server.core);
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

        assert_eq!(alice.group.core, server.core);
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
            &mut ExternalGroup<InMemoryExternalClientConfig>,
            &SigningIdentity,
            &SecretKey,
        ) -> MLSMessage,
    {
        let (server_identity, server_key, mut alice) = setup_extern_proposal_test(true);
        let mut server = make_external_group(&alice);

        // Create an external proposal
        let external_proposal = proposal_creation(&mut server, &server_identity, &server_key);
        let auth_content = external_proposal.clone().into_plaintext().unwrap().into();
        let proposal_ref = ProposalRef::from_content(TEST_CIPHER_SUITE, &auth_content).unwrap();

        // Alice receives the proposal
        alice.process_message(external_proposal).unwrap();

        // Alice commits the proposal
        let (commit_data, _) = alice.commit(vec![]).unwrap();

        let commit = match commit_data
            .clone()
            .into_plaintext()
            .unwrap()
            .content
            .content
        {
            Content::Commit(commit) => commit,
            _ => panic!("not a commit"),
        };

        // The proposal should be in the resulting commit
        assert!(commit
            .proposals
            .contains(&ProposalOrRef::Reference(proposal_ref)));

        alice.process_pending_commit().unwrap();
        server.process_incoming_message(commit_data).unwrap();

        assert_eq!(alice.group.core, server.core);
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
        let mut server = make_external_group(&alice);

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

        let mut server = make_external_group(&alice);

        let remove_proposal = RemoveProposal {
            to_remove: LeafIndex(1),
        };

        let res = server.propose_remove(remove_proposal, vec![], &server_identity, &server_key);

        assert_matches!(res, Err(GroupError::InvalidExternalSigningIdentity));
    }
}
