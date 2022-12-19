use tls_codec::Serialize;

use super::{
    check_protocol_version,
    confirmation_tag::ConfirmationTag,
    framing::{MLSCiphertext, MLSPlaintext, Sender, WireFormat},
    message_processor::{EventOrContent, MessageProcessor, ProcessedMessage, ProvisionalState},
    message_signature::MLSAuthenticatedContent,
    proposal::{AddProposal, Proposal, RemoveProposal},
    validate_group_info, ExternalEvent, Member, ProposalRef,
};
use crate::{
    cipher_suite::CipherSuite,
    client_config::{MakeProposalFilter, ProposalFilterInit},
    extension::ExternalSendersExt,
    external_client_config::ExternalClientConfig,
    group::{
        Content, GroupError, GroupState, InterimTranscriptHash, MLSMessage, MLSMessagePayload,
    },
    identity::SigningIdentity,
    key_package::{KeyPackage, KeyPackageValidator},
    protocol_version::ProtocolVersion,
    provider::{identity::IdentityProvider, keychain::KeychainStorage},
    psk::PassThroughPskIdValidator,
    tree_kem::{node::LeafIndex, path_secret::PathSecret, TreeKemPrivate},
};

#[derive(Clone, Debug)]
pub struct ExternalGroup<C> {
    pub(crate) config: C,
    pub(crate) state: GroupState,
}

impl<C: ExternalClientConfig + Clone> ExternalGroup<C> {
    pub(crate) fn join(
        config: C,
        group_info: MLSMessage,
        tree_data: Option<&[u8]>,
    ) -> Result<Self, GroupError> {
        let wire_format = group_info.wire_format();

        let protocol_version =
            check_protocol_version(&config.supported_protocol_versions(), group_info.version)?;

        let group_info = group_info.into_group_info().ok_or_else(|| {
            GroupError::UnexpectedMessageType(vec![WireFormat::GroupInfo], wire_format)
        })?;

        let join_context = validate_group_info(
            &config.supported_protocol_versions(),
            &config.supported_cipher_suites(),
            protocol_version,
            group_info,
            tree_data,
            &config.identity_provider(),
        )?;

        let interim_transcript_hash = InterimTranscriptHash::create(
            join_context.group_context.cipher_suite,
            &join_context.group_context.confirmed_transcript_hash,
            &join_context.confirmation_tag,
        )?;

        Ok(Self {
            config,
            state: GroupState::new(
                join_context.group_context,
                join_context.public_tree,
                interim_transcript_hash,
                join_context.confirmation_tag,
            ),
        })
    }

    pub fn process_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<
        ProcessedMessage<ExternalEvent<<C::IdentityProvider as IdentityProvider>::IdentityEvent>>,
        GroupError,
    > {
        MessageProcessor::process_incoming_message(self, message, self.config.cache_proposals())
    }

    pub fn insert_proposal_from_message(&mut self, message: MLSMessage) -> Result<(), GroupError> {
        let ptxt = match message.payload {
            MLSMessagePayload::Plain(p) => Ok(p),
            _ => Err(GroupError::UnexpectedMessageType(
                vec![WireFormat::Plain],
                message.wire_format(),
            )),
        }?;

        let auth_content: MLSAuthenticatedContent = ptxt.into();
        let proposal_ref = ProposalRef::from_content(self.cipher_suite(), &auth_content)?;
        let sender = auth_content.content.sender;

        let proposal = match auth_content.content.content {
            Content::Proposal(p) => Ok(p),
            content => Err(GroupError::NotProposalContent(content.content_type())),
        }?;

        self.insert_proposal(proposal, proposal_ref, sender);

        Ok(())
    }

    pub fn insert_proposal(
        &mut self,
        proposal: Proposal,
        proposal_ref: ProposalRef,
        sender: Sender,
    ) {
        self.group_state_mut()
            .proposals
            .insert(proposal_ref, proposal, sender)
    }

    pub fn propose_add(
        &mut self,
        key_package: KeyPackage,
        signing_identity: &SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        // Check that this proposal has a valid lifetime and signature. Required capabilities are
        // not checked as they may be changed in another proposal in the same commit.
        let key_package_validator = KeyPackageValidator::new(
            self.protocol_version(),
            self.cipher_suite(),
            None,
            self.config.identity_provider(),
        );

        key_package_validator.check_if_valid(&key_package, Default::default())?;

        self.propose(
            Proposal::Add(AddProposal { key_package }),
            signing_identity,
            authenticated_data,
        )
    }

    pub fn propose_remove(
        &mut self,
        index: u32,
        signing_identity: &SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let to_remove = LeafIndex(index);

        // Verify that this leaf is actually in the tree
        self.group_state().public_tree.get_leaf_node(to_remove)?;

        self.propose(
            Proposal::Remove(RemoveProposal { to_remove }),
            signing_identity,
            authenticated_data,
        )
    }

    fn propose(
        &mut self,
        proposal: Proposal,
        signing_identity: &SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let external_senders_ext = self
            .state
            .context
            .extensions
            .get_extension::<ExternalSendersExt>()?
            .ok_or(GroupError::ExternalProposalsDisabled)?;

        let signer = self
            .config
            .keychain()
            .signer(signing_identity)
            .map_err(|e| GroupError::KeychainError(e.into()))?
            .ok_or(GroupError::SignerNotFound)?;

        let sender_index = external_senders_ext
            .allowed_senders
            .iter()
            .position(|allowed_signer| signing_identity == allowed_signer)
            .ok_or(GroupError::InvalidExternalSigningIdentity)?;

        let sender = Sender::External(sender_index as u32);

        let auth_content = MLSAuthenticatedContent::new_signed(
            &self.state.context,
            sender.clone(),
            Content::Proposal(proposal.clone()),
            &signer,
            WireFormat::Plain,
            authenticated_data,
        )?;

        self.state.proposals.insert(
            ProposalRef::from_content(self.state.cipher_suite(), &auth_content)?,
            proposal,
            sender,
        );

        let plaintext = MLSPlaintext {
            content: auth_content.content,
            auth: auth_content.auth,
            membership_tag: None,
        };

        Ok(MLSMessage::new(
            self.state.protocol_version(),
            MLSMessagePayload::Plain(plaintext),
        ))
    }

    #[inline(always)]
    pub fn group_state(&self) -> &GroupState {
        &self.state
    }

    #[inline(always)]
    pub fn group_id(&self) -> &[u8] {
        &self.group_state().context.group_id
    }

    #[inline(always)]
    pub fn current_epoch(&self) -> u64 {
        self.group_state().context.epoch
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.group_state().context.protocol_version
    }

    pub fn cipher_suite(&self) -> CipherSuite {
        self.group_state().context.cipher_suite
    }

    pub fn export_tree(&self) -> Result<Vec<u8>, GroupError> {
        self.group_state()
            .public_tree
            .export_node_data()
            .tls_serialize_detached()
            .map_err(Into::into)
    }

    pub fn roster(&self) -> Vec<Member> {
        self.group_state().roster()
    }

    pub fn transcript_hash(&self) -> &Vec<u8> {
        &self.group_state().context.confirmed_transcript_hash
    }
}

impl<C> MessageProcessor for ExternalGroup<C>
where
    C: ExternalClientConfig + Clone,
{
    type ProposalFilter = <C::MakeProposalFilter as MakeProposalFilter>::Filter;
    type IdentityProvider = C::IdentityProvider;
    type ExternalPskIdValidator = PassThroughPskIdValidator;
    type EventType = ExternalEvent<<Self::IdentityProvider as IdentityProvider>::IdentityEvent>;

    fn self_index(&self) -> Option<LeafIndex> {
        None
    }

    fn proposal_filter(&self, init: ProposalFilterInit) -> Self::ProposalFilter {
        self.config.proposal_filter(init)
    }

    fn verify_plaintext_authentication(
        &self,
        message: MLSPlaintext,
    ) -> Result<EventOrContent<Self::EventType>, GroupError> {
        let auth_content = crate::group::message_verifier::verify_plaintext_authentication(
            message,
            None,
            None,
            &self.state,
        )?;

        Ok(EventOrContent::Content(auth_content))
    }

    fn process_ciphertext(
        &mut self,
        cipher_text: MLSCiphertext,
    ) -> Result<EventOrContent<Self::EventType>, GroupError> {
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
        self.state.context = provisional_public_state.group_context;
        self.state.proposals.clear();
        self.state.interim_transcript_hash = interim_transcript_hash;
        self.state.public_tree = provisional_public_state.public_tree;
        self.state.confirmation_tag = confirmation_tag;

        Ok(())
    }

    fn identity_provider(&self) -> Self::IdentityProvider {
        self.config.identity_provider()
    }

    fn external_psk_id_validator(&self) -> Self::ExternalPskIdValidator {
        PassThroughPskIdValidator
    }

    fn group_state(&self) -> &GroupState {
        &self.state
    }

    fn group_state_mut(&mut self) -> &mut GroupState {
        &mut self.state
    }

    fn can_continue_processing(&self, _provisional_state: &ProvisionalState) -> bool {
        true
    }

    fn min_epoch_available(&self) -> Option<u64> {
        self.config
            .max_epoch_jitter()
            .map(|j| self.state.context.epoch - j)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::{
        external_client_builder::test_utils::{
            TestExternalClientBuilder, TestExternalClientConfig,
        },
        group::test_utils::TestGroup,
    };

    use super::ExternalGroup;

    pub(crate) fn make_external_group(
        group: &TestGroup,
    ) -> ExternalGroup<TestExternalClientConfig> {
        make_external_group_with_config(
            group,
            TestExternalClientBuilder::new_for_test().build_config(),
        )
    }

    pub(crate) fn make_external_group_with_config(
        group: &TestGroup,
        config: TestExternalClientConfig,
    ) -> ExternalGroup<TestExternalClientConfig> {
        let public_tree = group.group.export_tree().unwrap();

        ExternalGroup::join(
            config,
            group.group.group_info_message(true).unwrap(),
            Some(&public_tree),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::{CipherSuite, MaybeCipherSuite},
        extension::{ExtensionList, ExternalSendersExt},
        external_client_builder::test_utils::{
            TestExternalClientBuilder, TestExternalClientConfig,
        },
        group::{
            external_group::test_utils::make_external_group_with_config,
            proposal::{AddProposal, Proposal, ProposalOrRef},
            proposal_ref::ProposalRef,
            test_utils::{test_group, TestGroup},
            Content, ExternalEvent, ExternalGroup, GroupError, MLSMessage, MLSMessagePayload,
        },
        identity::{test_utils::get_test_signing_identity, SigningIdentity},
        key_package::test_utils::test_key_package,
        protocol_version::{MaybeProtocolVersion, ProtocolVersion},
    };
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::SecretKey;

    use super::test_utils::make_external_group;

    const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    fn test_group_with_one_commit(v: ProtocolVersion, cs: CipherSuite) -> TestGroup {
        let mut group = test_group(v, cs);
        group.group.commit(Vec::new()).unwrap();
        group.process_pending_commit().unwrap();
        group
    }

    fn test_group_two_members(
        v: ProtocolVersion,
        cs: CipherSuite,
        ext_identity: Option<SigningIdentity>,
    ) -> TestGroup {
        let mut group = test_group_with_one_commit(v, cs);

        let bob_key_package = test_key_package(v, cs, "bob");

        let mut commit_builder = group
            .group
            .commit_builder()
            .add_member(bob_key_package)
            .unwrap();

        if let Some(ext_signer) = ext_identity {
            let mut ext_list = ExtensionList::new();

            ext_list
                .set_extension(ExternalSendersExt {
                    allowed_senders: vec![ext_signer],
                })
                .unwrap();

            commit_builder = commit_builder.set_group_context_ext(ext_list).unwrap();
        }

        commit_builder.build().unwrap();

        group.process_pending_commit().unwrap();
        group
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
        let commit_output = alice.group.commit(Vec::new()).unwrap();
        alice.group.apply_pending_commit().unwrap();

        server
            .process_incoming_message(commit_output.commit_message)
            .unwrap();

        assert_eq!(alice.group.state, server.state);
    }

    #[test]
    fn external_group_can_process_proposals_by_reference() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice);

        let bob_key_package = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let add_proposal = Proposal::Add(AddProposal {
            key_package: bob_key_package,
        });

        let packet = alice.propose(add_proposal.clone());

        let proposal_process = server.process_incoming_message(packet).unwrap();

        assert_matches!(
            proposal_process.event,
            ExternalEvent::Proposal((ref p, _)) if p == &add_proposal
        );

        let commit_output = alice.group.commit(vec![]).unwrap();
        alice.group.apply_pending_commit().unwrap();

        let commit_result = server
            .process_incoming_message(commit_output.commit_message)
            .unwrap();

        assert_matches!(
            commit_result.event,
            ExternalEvent::Commit(state_update) if state_update.roster_update.added.iter().any(|added| added.index() == 1)
        );

        assert_eq!(alice.group.state, server.state);
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

        assert_eq!(update.roster_update.added.len(), 1);
        assert_eq!(server.state.public_tree.get_leaf_nodes().len(), 2);

        assert_eq!(alice.group.state, server.state);
    }

    #[test]
    fn external_group_rejects_commit_not_for_current_epoch() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice);

        let mut commit_output = alice.group.commit(vec![]).unwrap();

        match commit_output.commit_message.payload {
            MLSMessagePayload::Plain(ref mut plain) => plain.content.epoch = 0,
            _ => panic!("Unexpected non-plaintext data"),
        };

        assert_matches!(
            server.process_incoming_message(commit_output.commit_message),
            Err(GroupError::InvalidEpoch(0))
        );
    }

    #[test]
    fn external_group_can_reject_message_with_invalid_signature() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut server = make_external_group_with_config(
            &alice,
            TestExternalClientBuilder::new_for_test().build_config(),
        );

        let mut commit_output = alice.group.commit(Vec::new()).unwrap();

        match commit_output.commit_message.payload {
            MLSMessagePayload::Plain(ref mut plain) => plain.auth.signature = Vec::new().into(),
            _ => panic!("Unexpected non-plaintext data"),
        };

        assert_matches!(
            server.process_incoming_message(commit_output.commit_message),
            Err(GroupError::InvalidSignature)
        );
    }

    #[test]
    fn external_group_rejects_unencrypted_application_message() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut server = make_external_group(&alice);
        let plaintext = alice.make_plaintext(Content::Application(b"hello".to_vec().into()));

        assert_matches!(
            server.process_incoming_message(plaintext),
            Err(GroupError::UnencryptedApplicationMessage)
        );
    }

    #[test]
    fn external_group_will_reject_unsupported_cipher_suites() {
        let alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let config = TestExternalClientBuilder::new_for_test()
            .cipher_suite(CipherSuite::Curve25519ChaCha20)
            .build_config();

        let res = ExternalGroup::join(config, alice.group.group_info_message(true).unwrap(), None)
            .map(|_| ());

        assert_matches!(
            res,
            Err(GroupError::UnsupportedCipherSuite(cs)) if cs == MaybeCipherSuite::from(
                CipherSuite::Curve25519Aes128
            )
        );
    }

    #[test]
    fn external_group_will_reject_unsupported_protocol_versions() {
        let alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let config = TestExternalClientBuilder::new_for_test().build_config();

        let mut group_info = alice.group.group_info_message(true).unwrap();
        group_info.version = MaybeProtocolVersion::from_raw_value(64);

        let res = ExternalGroup::join(config, group_info, None).map(|_| ());

        assert_matches!(
            res,
            Err(GroupError::UnsupportedProtocolVersion(v)) if v ==
                MaybeProtocolVersion::from_raw_value(64)
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
        F: Fn(&mut ExternalGroup<TestExternalClientConfig>, &SigningIdentity) -> MLSMessage,
    {
        let (server_identity, server_key, mut alice) = setup_extern_proposal_test(true);
        let mut server = make_external_group(&alice);

        server
            .config
            .0
            .keychain
            .insert(server_identity.clone(), server_key);

        // Create an external proposal
        let external_proposal = proposal_creation(&mut server, &server_identity);
        let auth_content = external_proposal.clone().into_plaintext().unwrap().into();
        let proposal_ref = ProposalRef::from_content(TEST_CIPHER_SUITE, &auth_content).unwrap();

        // Alice receives the proposal
        alice.process_message(external_proposal).unwrap();

        // Alice commits the proposal
        let commit_output = alice.group.commit(vec![]).unwrap();

        let commit = match commit_output
            .commit_message
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

        server
            .process_incoming_message(commit_output.commit_message)
            .unwrap();

        assert_eq!(alice.group.state, server.state);
    }

    #[test]
    fn external_group_can_propose_add() {
        test_external_proposal(|ext_group, ext_identity| {
            let charlie_key_package =
                test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "charlie");

            ext_group
                .propose_add(charlie_key_package, ext_identity, vec![])
                .unwrap()
        })
    }

    #[test]
    fn external_group_can_propose_remove() {
        test_external_proposal(|ext_group, ext_identity| {
            ext_group.propose_remove(1, ext_identity, vec![]).unwrap()
        })
    }

    #[test]
    fn external_group_external_proposal_not_allowed() {
        let (signing_id, secret_key, alice) = setup_extern_proposal_test(false);
        let mut server = make_external_group(&alice);

        server
            .config
            .0
            .keychain
            .insert(signing_id.clone(), secret_key);

        let charlie_key_package =
            test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "charlie");

        let res = server.propose_add(charlie_key_package, &signing_id, vec![]);

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

        server
            .config
            .0
            .keychain
            .insert(server_identity.clone(), server_key);

        let res = server.propose_remove(1, &server_identity, vec![]);

        assert_matches!(res, Err(GroupError::InvalidExternalSigningIdentity));
    }

    #[test]
    fn external_group_errors_on_old_epoch() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut server = make_external_group_with_config(
            &alice,
            TestExternalClientBuilder::new_for_test()
                .max_epoch_jitter(0)
                .build_config(),
        );

        let old_application_msg = alice
            .group
            .encrypt_application_message(&[], vec![])
            .unwrap();

        let commit_output = alice.group.commit(vec![]).unwrap();

        server
            .process_incoming_message(commit_output.commit_message)
            .unwrap();

        let res = server.process_incoming_message(old_application_msg);

        assert_matches!(res, Err(GroupError::InvalidEpoch(1)));
    }

    #[test]
    fn proposals_can_be_cached_externally() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut server = make_external_group_with_config(
            &alice,
            TestExternalClientBuilder::new_for_test()
                .cache_proposals(false)
                .build_config(),
        );

        let proposal = alice.group.propose_update(vec![]).unwrap();

        let commit_output = alice.group.commit(vec![]).unwrap();

        server.process_incoming_message(proposal.clone()).unwrap();
        server.insert_proposal_from_message(proposal).unwrap();
        server
            .process_incoming_message(commit_output.commit_message)
            .unwrap();
    }

    #[test]
    fn external_group_can_observe_since_creation() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let info = alice.group.group_info_message(true).unwrap();

        let config = TestExternalClientBuilder::new_for_test().build_config();
        let mut server = ExternalGroup::join(config, info, None).unwrap();

        for _ in 0..2 {
            let commit = alice.group.commit(vec![]).unwrap().commit_message;
            alice.process_pending_commit().unwrap();
            server.process_incoming_message(commit).unwrap();
        }
    }
}
