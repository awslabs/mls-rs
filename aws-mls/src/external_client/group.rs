use async_trait::async_trait;
use aws_mls_codec::MlsEncode;
use aws_mls_core::{
    crypto::CipherSuiteProvider, extension::ExtensionList, group::Member,
    identity::IdentityProvider, keychain::KeychainStorage, psk::ExternalPskId,
};
use serde_with::serde_as;

use crate::{
    cipher_suite::CipherSuite,
    client::MlsError,
    extension::ExternalSendersExt,
    external_client::ExternalClientConfig,
    group::{
        cipher_suite_provider,
        confirmation_tag::ConfirmationTag,
        framing::{Content, MLSMessagePayload, PrivateMessage, PublicMessage, WireFormat},
        member_from_leaf_node,
        message_processor::{
            ApplicationMessageDescription, CommitMessageDescription, EventOrContent,
            MessageProcessor, ProposalMessageDescription, ProvisionalState,
        },
        message_signature::AuthenticatedContent,
        proposal::{
            AddProposal, CustomProposal, PreSharedKeyProposal, Proposal, ReInitProposal,
            RemoveProposal,
        },
        proposal_ref::ProposalRef,
        snapshot::RawGroupState,
        state::GroupState,
        transcript_hash::InterimTranscriptHash,
        validate_group_info, Sender,
    },
    identity::SigningIdentity,
    key_package::KeyPackageValidator,
    protocol_version::ProtocolVersion,
    psk::{
        JustPreSharedKeyID, PassThroughPskIdValidator, PreSharedKeyID, PskGroupId, PskNonce,
        ResumptionPSKUsage, ResumptionPsk,
    },
    tree_kem::{node::LeafIndex, path_secret::PathSecret, TreeKemPrivate},
    CryptoProvider, MLSMessage,
};

/// The result of processing an [ExternalGroup](ExternalGroup) message using
/// [process_incoming_message](ExternalGroup::process_incoming_message)
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ExternalReceivedMessage {
    /// State update as the result of a successful commit.
    Commit(CommitMessageDescription),
    /// Received proposal and its unique identifier.
    Proposal(ProposalMessageDescription),
    /// Encrypted message that can not be processed.
    Ciphertext,
}

/// A handle to an observed group that can track plaintext control messages
/// and the resulting group state.
#[derive(Clone)]
pub struct ExternalGroup<C>
where
    C: ExternalClientConfig,
{
    pub(crate) config: C,
    pub(crate) cipher_suite_provider: <C::CryptoProvider as CryptoProvider>::CipherSuiteProvider,
    pub(crate) state: GroupState,
}

impl<C: ExternalClientConfig + Clone> ExternalGroup<C> {
    pub(crate) async fn join(
        config: C,
        group_info: MLSMessage,
        tree_data: Option<&[u8]>,
    ) -> Result<Self, MlsError> {
        let wire_format = group_info.wire_format();
        let protocol_version = group_info.version;

        if !config.version_supported(protocol_version) {
            return Err(MlsError::UnsupportedProtocolVersion(protocol_version));
        }

        let group_info = group_info.into_group_info().ok_or_else(|| {
            MlsError::UnexpectedMessageType(vec![WireFormat::GroupInfo], wire_format)
        })?;

        let cipher_suite_provider = cipher_suite_provider(
            config.crypto_provider(),
            group_info.group_context.cipher_suite,
        )?;

        let join_context = validate_group_info(
            protocol_version,
            group_info,
            tree_data,
            &config.identity_provider(),
            &cipher_suite_provider,
        )
        .await?;

        let interim_transcript_hash = InterimTranscriptHash::create(
            &cipher_suite_provider,
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
            cipher_suite_provider,
        })
    }

    /// Process a message that was sent to the group.
    ///
    /// * Proposals will be stored in the group state and processed by the
    /// same rules as a standard group.
    ///
    /// * Commits will result in the same outcome as a standard group.
    /// However, the integrity of the resulting group state can only be partially
    /// verified, since the external group does have access to the group
    /// secrets required to do a complete check.
    ///
    /// * Application messages are always encrypted so they result in a no-op
    /// that returns [ExternalEvent::Ciphertext](ExternalEvent::Ciphertext)
    ///
    /// # Warning
    ///
    /// Processing an encrypted commit or proposal message has the same result
    /// as processing an encrypted application message. Proper tracking of
    /// the group state requires that all proposal and commit messages are
    /// readable.
    pub async fn process_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<ExternalReceivedMessage, MlsError> {
        MessageProcessor::process_incoming_message(self, message, self.config.cache_proposals())
            .await
    }

    /// Replay a proposal message into the group skipping all validation steps.
    pub fn insert_proposal_from_message(&mut self, message: MLSMessage) -> Result<(), MlsError> {
        let ptxt = match message.payload {
            MLSMessagePayload::Plain(p) => Ok(p),
            _ => Err(MlsError::UnexpectedMessageType(
                vec![WireFormat::PublicMessage],
                message.wire_format(),
            )),
        }?;

        let auth_content: AuthenticatedContent = ptxt.into();
        let proposal_ref = ProposalRef::from_content(&self.cipher_suite_provider, &auth_content)?;
        let sender = auth_content.content.sender;

        let proposal = match auth_content.content.content {
            Content::Proposal(p) => Ok(p),
            content => Err(MlsError::NotProposalContent(content.content_type())),
        }?;

        self.insert_proposal(proposal, proposal_ref, sender);

        Ok(())
    }

    /// Force insert a proposal directly into the internal state of the group
    /// with no validation.
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

    /// Create an external proposal to request that a group add a new member
    ///
    /// # Warning
    ///
    /// In order for the proposal generated by this function to be successfully
    /// committed, the group needs to have `signing_identity` as an entry
    /// within an [ExternalSendersExt](crate::extension::built_in::ExternalSendersExt)
    /// as part of its group context extensions.
    pub async fn propose_add(
        &mut self,
        key_package: MLSMessage,
        signing_identity: &SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, MlsError> {
        let wire_format = key_package.wire_format();

        let key_package = key_package.into_key_package().ok_or_else(|| {
            MlsError::UnexpectedMessageType(vec![WireFormat::KeyPackage], wire_format)
        })?;

        // Check that this proposal has a valid lifetime and signature. Required capabilities are
        // not checked as they may be changed in another proposal in the same commit.
        let id_provider = self.config.identity_provider();

        let key_package_validator = KeyPackageValidator::new(
            self.protocol_version(),
            &self.cipher_suite_provider,
            None,
            &id_provider,
            Some(&self.state.context.extensions),
        );

        key_package_validator
            .check_if_valid(&key_package, Default::default())
            .await?;

        self.propose(
            Proposal::Add(AddProposal { key_package }),
            signing_identity,
            authenticated_data,
        )
        .await
    }

    /// Create an external proposal to request that a group remove an existing member
    ///
    /// # Warning
    ///
    /// In order for the proposal generated by this function to be successfully
    /// committed, the group needs to have `signing_identity` as an entry
    /// within an [ExternalSendersExt](crate::extension::built_in::ExternalSendersExt)
    /// as part of its group context extensions.
    pub async fn propose_remove(
        &mut self,
        index: u32,
        signing_identity: &SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, MlsError> {
        let to_remove = LeafIndex(index);

        // Verify that this leaf is actually in the tree
        self.group_state().public_tree.get_leaf_node(to_remove)?;

        self.propose(
            Proposal::Remove(RemoveProposal { to_remove }),
            signing_identity,
            authenticated_data,
        )
        .await
    }

    /// Create an external proposal to request that a group inserts an external
    /// pre shared key into its state.
    ///
    /// # Warning
    ///
    /// In order for the proposal generated by this function to be successfully
    /// committed, the group needs to have `signing_identity` as an entry
    /// within an [ExternalSendersExt](crate::extension::built_in::ExternalSendersExt)
    /// as part of its group context extensions.
    pub async fn propose_external_psk(
        &mut self,
        psk: ExternalPskId,
        signing_identity: &SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, MlsError> {
        let proposal = self.psk_proposal(JustPreSharedKeyID::External(psk))?;
        self.propose(proposal, signing_identity, authenticated_data)
            .await
    }

    /// Create an external proposal to request that a group adds a pre shared key
    /// from a previous epoch to the current group state.
    ///
    /// # Warning
    ///
    /// In order for the proposal generated by this function to be successfully
    /// committed, the group needs to have `signing_identity` as an entry
    /// within an [ExternalSendersExt](crate::extension::built_in::ExternalSendersExt)
    /// as part of its group context extensions.
    pub async fn propose_resumption_psk(
        &mut self,
        psk_epoch: u64,
        signing_identity: &SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, MlsError> {
        let key_id = ResumptionPsk {
            psk_epoch,
            usage: ResumptionPSKUsage::Application,
            psk_group_id: PskGroupId(self.group_id().to_vec()),
        };

        let proposal = self.psk_proposal(JustPreSharedKeyID::Resumption(key_id))?;
        self.propose(proposal, signing_identity, authenticated_data)
            .await
    }

    fn psk_proposal(&self, key_id: JustPreSharedKeyID) -> Result<Proposal, MlsError> {
        Ok(Proposal::Psk(PreSharedKeyProposal {
            psk: PreSharedKeyID {
                key_id,
                psk_nonce: PskNonce::random(&self.cipher_suite_provider)
                    .map_err(|e| MlsError::CryptoProviderError(e.into()))?,
            },
        }))
    }

    /// Create an external proposal to request that a group sets extensions stored in the group
    /// state.
    ///
    /// # Warning
    ///
    /// In order for the proposal generated by this function to be successfully
    /// committed, the group needs to have `signing_identity` as an entry
    /// within an [ExternalSendersExt](crate::extension::built_in::ExternalSendersExt)
    /// as part of its group context extensions.
    pub async fn propose_group_context_extensions(
        &mut self,
        extensions: ExtensionList,
        signing_identity: &SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, MlsError> {
        let proposal = Proposal::GroupContextExtensions(extensions);
        self.propose(proposal, signing_identity, authenticated_data)
            .await
    }

    /// Create an external proposal to request that a group is reinitialized.
    ///
    /// # Warning
    ///
    /// In order for the proposal generated by this function to be successfully
    /// committed, the group needs to have `signing_identity` as an entry
    /// within an [ExternalSendersExt](crate::extension::built_in::ExternalSendersExt)
    /// as part of its group context extensions.
    pub async fn propose_reinit(
        &mut self,
        group_id: Option<Vec<u8>>,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        extensions: ExtensionList,
        signing_identity: &SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, MlsError> {
        let group_id = group_id.map(Ok).unwrap_or_else(|| {
            self.cipher_suite_provider
                .random_bytes_vec(self.cipher_suite_provider.kdf_extract_size())
                .map_err(|e| MlsError::CryptoProviderError(e.into()))
        })?;

        let proposal = Proposal::ReInit(ReInitProposal {
            group_id,
            version,
            cipher_suite,
            extensions,
        });

        self.propose(proposal, signing_identity, authenticated_data)
            .await
    }

    /// Create a custom proposal message.
    ///
    /// # Warning
    ///
    /// In order for the proposal generated by this function to be successfully
    /// committed, the group needs to have `signing_identity` as an entry
    /// within an [ExternalSendersExt](crate::extension::built_in::ExternalSendersExt)
    /// as part of its group context extensions.
    pub async fn propose_custom(
        &mut self,
        proposal: CustomProposal,
        signing_identity: &SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, MlsError> {
        self.propose(
            Proposal::Custom(proposal),
            signing_identity,
            authenticated_data,
        )
        .await
    }

    async fn propose(
        &mut self,
        proposal: Proposal,
        signing_identity: &SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, MlsError> {
        let external_senders_ext = self
            .state
            .context
            .extensions
            .get_as::<ExternalSendersExt>()?
            .ok_or(MlsError::ExternalProposalsDisabled)?;

        let signer = self
            .config
            .keychain()
            .signer(signing_identity)
            .await
            .map_err(|e| MlsError::KeychainError(e.into()))?
            .ok_or(MlsError::SignerNotFound)?;

        let sender_index = external_senders_ext
            .allowed_senders
            .iter()
            .position(|allowed_signer| signing_identity == allowed_signer)
            .ok_or(MlsError::InvalidExternalSigningIdentity)?;

        let sender = Sender::External(sender_index as u32);

        let auth_content = AuthenticatedContent::new_signed(
            &self.cipher_suite_provider,
            &self.state.context,
            sender,
            Content::Proposal(proposal.clone()),
            &signer,
            WireFormat::PublicMessage,
            authenticated_data,
        )?;

        self.state.proposals.insert(
            ProposalRef::from_content(&self.cipher_suite_provider, &auth_content)?,
            proposal,
            sender,
        );

        let plaintext = PublicMessage {
            content: auth_content.content,
            auth: auth_content.auth,
            membership_tag: None,
        };

        Ok(MLSMessage::new(
            self.protocol_version(),
            MLSMessagePayload::Plain(plaintext),
        ))
    }

    #[inline(always)]
    pub(crate) fn group_state(&self) -> &GroupState {
        &self.state
    }

    /// Get the unique identifier of this group.
    #[inline(always)]
    pub fn group_id(&self) -> &[u8] {
        &self.group_state().context.group_id
    }

    /// Get the current epoch number of the group's state.
    #[inline(always)]
    pub fn current_epoch(&self) -> u64 {
        self.group_state().context.epoch
    }

    /// Get the current protocol version in use by the group.
    #[inline(always)]
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.group_state().context.protocol_version
    }

    /// Get the current ciphersuite in use by the group.
    #[inline(always)]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.group_state().context.cipher_suite
    }

    /// Export the current ratchet tree used within the group.
    pub fn export_tree(&self) -> Result<Vec<u8>, MlsError> {
        self.group_state()
            .public_tree
            .export_node_data()
            .mls_encode_to_vec()
            .map_err(Into::into)
    }

    /// Get the current roster of the group.
    #[inline(always)]
    pub fn roster(&self) -> Vec<Member> {
        self.group_state().roster()
    }

    /// Get the
    /// [transcript hash](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-transcript-hashes)
    /// for the current epoch that the group is in.
    #[inline(always)]
    pub fn transcript_hash(&self) -> &Vec<u8> {
        &self.group_state().context.confirmed_transcript_hash
    }

    /// Find a member based on their identity.
    ///
    /// Identities are matched based on the
    /// [IdentityProvider](crate::IdentityProvider)
    /// that this group was configured with.
    pub async fn get_member_with_identity(
        &self,
        identity_id: &SigningIdentity,
    ) -> Result<Member, MlsError> {
        let identity = self
            .identity_provider()
            .identity(identity_id)
            .await
            .map_err(|error| MlsError::IdentityProviderError(error.into()))?;

        let index = self
            .group_state()
            .public_tree
            .get_leaf_node_with_identity(&identity)
            .ok_or(MlsError::MemberNotFound)?;

        let node = self.group_state().public_tree.get_leaf_node(index)?;

        Ok(member_from_leaf_node(node, index))
    }
}

#[async_trait]
impl<C> MessageProcessor for ExternalGroup<C>
where
    C: ExternalClientConfig + Clone,
{
    type ProposalRules = C::ProposalRules;
    type IdentityProvider = C::IdentityProvider;
    type ExternalPskIdValidator = PassThroughPskIdValidator;
    type OutputType = ExternalReceivedMessage;
    type CipherSuiteProvider = <C::CryptoProvider as CryptoProvider>::CipherSuiteProvider;

    fn self_index(&self) -> Option<LeafIndex> {
        None
    }

    fn proposal_rules(&self) -> Self::ProposalRules {
        self.config.proposal_rules()
    }

    fn verify_plaintext_authentication(
        &self,
        message: PublicMessage,
    ) -> Result<EventOrContent<Self::OutputType>, MlsError> {
        let auth_content = crate::group::message_verifier::verify_plaintext_authentication(
            &self.cipher_suite_provider,
            message,
            None,
            None,
            &self.state,
        )?;

        Ok(EventOrContent::Content(auth_content))
    }

    async fn process_ciphertext(
        &mut self,
        _cipher_text: PrivateMessage,
    ) -> Result<EventOrContent<Self::OutputType>, MlsError> {
        Ok(EventOrContent::Event(ExternalReceivedMessage::Ciphertext))
    }

    async fn update_key_schedule(
        &mut self,
        _secrets: Option<(TreeKemPrivate, PathSecret)>,
        interim_transcript_hash: InterimTranscriptHash,
        confirmation_tag: ConfirmationTag,
        provisional_public_state: ProvisionalState,
    ) -> Result<(), MlsError> {
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

    fn cipher_suite_provider(&self) -> &Self::CipherSuiteProvider {
        &self.cipher_suite_provider
    }
}

/// Serializable snapshot of an [ExternalGroup](ExternalGroup) state.
#[serde_as]
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Clone)]
pub struct ExternalSnapshot {
    version: u16,
    state: RawGroupState,
}

impl<C> ExternalGroup<C>
where
    C: ExternalClientConfig + Clone,
{
    /// Create a snapshot of this group's current internal state.
    pub fn snapshot(&self, export_internals: bool) -> ExternalSnapshot {
        ExternalSnapshot {
            state: RawGroupState::export(self.group_state(), export_internals),
            version: 1,
        }
    }

    pub(crate) async fn from_snapshot(
        config: C,
        snapshot: ExternalSnapshot,
    ) -> Result<Self, MlsError> {
        let identity_provider = config.identity_provider();

        let cipher_suite_provider = cipher_suite_provider(
            config.crypto_provider(),
            snapshot.state.context.cipher_suite,
        )?;

        Ok(ExternalGroup {
            config,
            state: snapshot.state.import(&identity_provider).await?,
            cipher_suite_provider,
        })
    }
}

impl From<CommitMessageDescription> for ExternalReceivedMessage {
    fn from(value: CommitMessageDescription) -> Self {
        ExternalReceivedMessage::Commit(value)
    }
}

impl TryFrom<ApplicationMessageDescription> for ExternalReceivedMessage {
    type Error = MlsError;

    fn try_from(_: ApplicationMessageDescription) -> Result<Self, Self::Error> {
        Err(MlsError::UnencryptedApplicationMessage)
    }
}

impl From<ProposalMessageDescription> for ExternalReceivedMessage {
    fn from(value: ProposalMessageDescription) -> Self {
        ExternalReceivedMessage::Proposal(value)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::{
        external_client::tests_utils::{TestExternalClientBuilder, TestExternalClientConfig},
        group::test_utils::TestGroup,
    };

    use super::ExternalGroup;

    pub(crate) async fn make_external_group(
        group: &TestGroup,
    ) -> ExternalGroup<TestExternalClientConfig> {
        make_external_group_with_config(
            group,
            TestExternalClientBuilder::new_for_test().build_config(),
        )
        .await
    }

    pub(crate) async fn make_external_group_with_config(
        group: &TestGroup,
        config: TestExternalClientConfig,
    ) -> ExternalGroup<TestExternalClientConfig> {
        let public_tree = group.group.export_tree().unwrap();

        ExternalGroup::join(
            config,
            group.group.group_info_message(true).await.unwrap(),
            Some(&public_tree),
        )
        .await
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::make_external_group;
    use crate::{
        cipher_suite::CipherSuite,
        client::{
            test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
            MlsError,
        },
        crypto::{test_utils::TestCryptoProvider, SignatureSecretKey},
        extension::ExternalSendersExt,
        external_client::{
            group::test_utils::make_external_group_with_config,
            tests_utils::{TestExternalClientBuilder, TestExternalClientConfig},
            ExternalGroup, ExternalReceivedMessage,
        },
        group::{
            framing::{Content, MLSMessagePayload},
            proposal::{AddProposal, Proposal, ProposalOrRef},
            proposal_ref::ProposalRef,
            test_utils::{test_group, TestGroup},
            ProposalMessageDescription,
        },
        identity::{test_utils::get_test_signing_identity, SigningIdentity},
        key_package::test_utils::{test_key_package, test_key_package_message},
        protocol_version::ProtocolVersion,
        ExtensionList, MLSMessage,
    };
    use assert_matches::assert_matches;
    use futures::{future::BoxFuture, FutureExt};

    async fn test_group_with_one_commit(v: ProtocolVersion, cs: CipherSuite) -> TestGroup {
        let mut group = test_group(v, cs).await;
        group.group.commit(Vec::new()).await.unwrap();
        group.process_pending_commit().await.unwrap();
        group
    }

    async fn test_group_two_members(
        v: ProtocolVersion,
        cs: CipherSuite,
        ext_identity: Option<SigningIdentity>,
    ) -> TestGroup {
        let mut group = test_group_with_one_commit(v, cs).await;

        let bob_key_package = test_key_package_message(v, cs, "bob").await;

        let mut commit_builder = group
            .group
            .commit_builder()
            .add_member(bob_key_package)
            .unwrap();

        if let Some(ext_signer) = ext_identity {
            let mut ext_list = ExtensionList::new();

            ext_list
                .set_from(ExternalSendersExt {
                    allowed_senders: vec![ext_signer],
                })
                .unwrap();

            commit_builder = commit_builder.set_group_context_ext(ext_list).unwrap();
        }

        commit_builder.build().await.unwrap();

        group.process_pending_commit().await.unwrap();
        group
    }

    #[futures_test::test]
    async fn external_group_can_be_created() {
        for (v, cs) in ProtocolVersion::all().flat_map(|v| {
            TestCryptoProvider::all_supported_cipher_suites()
                .into_iter()
                .map(move |cs| (v, cs))
        }) {
            make_external_group(&test_group_with_one_commit(v, cs).await).await;
        }
    }

    #[futures_test::test]
    async fn external_group_can_process_commit() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let mut server = make_external_group(&alice).await;
        let commit_output = alice.group.commit(Vec::new()).await.unwrap();
        alice.group.apply_pending_commit().await.unwrap();

        server
            .process_incoming_message(commit_output.commit_message)
            .await
            .unwrap();

        assert_eq!(alice.group.state, server.state);
    }

    #[futures_test::test]
    async fn external_group_can_process_proposals_by_reference() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let mut server = make_external_group(&alice).await;

        let bob_key_package =
            test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;

        let add_proposal = Proposal::Add(AddProposal {
            key_package: bob_key_package,
        });

        let packet = alice.propose(add_proposal.clone()).await;

        let proposal_process = server.process_incoming_message(packet).await.unwrap();

        assert_matches!(
            proposal_process,
            ExternalReceivedMessage::Proposal(ProposalMessageDescription { ref proposal, ..}) if proposal == &add_proposal
        );

        let commit_output = alice.group.commit(vec![]).await.unwrap();
        alice.group.apply_pending_commit().await.unwrap();

        let commit_result = server
            .process_incoming_message(commit_output.commit_message)
            .await
            .unwrap();

        assert_matches!(
            commit_result,
            ExternalReceivedMessage::Commit(commit_description)
                if commit_description.state_update.roster_update.added().iter().any(|added| added.index() == 1)
        );

        assert_eq!(alice.group.state, server.state);
    }

    #[futures_test::test]
    async fn external_group_can_process_commit_adding_member() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let mut server = make_external_group(&alice).await;
        let (_, commit) = alice.join("bob").await;

        let update = match server.process_incoming_message(commit).await.unwrap() {
            ExternalReceivedMessage::Commit(update) => update.state_update,
            _ => panic!("Expected processed commit"),
        };

        assert_eq!(update.roster_update.added().len(), 1);
        assert_eq!(server.state.public_tree.get_leaf_nodes().len(), 2);

        assert_eq!(alice.group.state, server.state);
    }

    #[futures_test::test]
    async fn external_group_rejects_commit_not_for_current_epoch() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let mut server = make_external_group(&alice).await;

        let mut commit_output = alice.group.commit(vec![]).await.unwrap();

        match commit_output.commit_message.payload {
            MLSMessagePayload::Plain(ref mut plain) => plain.content.epoch = 0,
            _ => panic!("Unexpected non-plaintext data"),
        };

        assert_matches!(
            server
                .process_incoming_message(commit_output.commit_message)
                .await,
            Err(MlsError::InvalidEpoch(0))
        );
    }

    #[futures_test::test]
    async fn external_group_can_reject_message_with_invalid_signature() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let mut server = make_external_group_with_config(
            &alice,
            TestExternalClientBuilder::new_for_test().build_config(),
        )
        .await;

        let mut commit_output = alice.group.commit(Vec::new()).await.unwrap();

        match commit_output.commit_message.payload {
            MLSMessagePayload::Plain(ref mut plain) => plain.auth.signature = Vec::new().into(),
            _ => panic!("Unexpected non-plaintext data"),
        };

        assert_matches!(
            server
                .process_incoming_message(commit_output.commit_message)
                .await,
            Err(MlsError::InvalidSignature)
        );
    }

    #[futures_test::test]
    async fn external_group_rejects_unencrypted_application_message() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let mut server = make_external_group(&alice).await;

        let plaintext = alice
            .make_plaintext(Content::Application(b"hello".to_vec().into()))
            .await;

        assert_matches!(
            server.process_incoming_message(plaintext).await,
            Err(MlsError::UnencryptedApplicationMessage)
        );
    }

    #[futures_test::test]
    async fn external_group_will_reject_unsupported_cipher_suites() {
        let alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let config =
            TestExternalClientBuilder::new_for_test_disabling_cipher_suite(TEST_CIPHER_SUITE)
                .build_config();

        let res = ExternalGroup::join(
            config,
            alice.group.group_info_message(true).await.unwrap(),
            None,
        )
        .await
        .map(|_| ());

        assert_matches!(
            res,
            Err(MlsError::UnsupportedCipherSuite(TEST_CIPHER_SUITE))
        );
    }

    #[futures_test::test]
    async fn external_group_will_reject_unsupported_protocol_versions() {
        let alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let config = TestExternalClientBuilder::new_for_test().build_config();

        let mut group_info = alice.group.group_info_message(true).await.unwrap();
        group_info.version = ProtocolVersion::from(64);

        let res = ExternalGroup::join(config, group_info, None)
            .await
            .map(|_| ());

        assert_matches!(
            res,
            Err(MlsError::UnsupportedProtocolVersion(v)) if v ==
                ProtocolVersion::from(64)
        );
    }

    async fn setup_extern_proposal_test(
        extern_proposals_allowed: bool,
    ) -> (SigningIdentity, SignatureSecretKey, TestGroup) {
        let (server_identity, server_key) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"server".to_vec());

        let alice = test_group_two_members(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            extern_proposals_allowed.then(|| server_identity.clone()),
        )
        .await;

        (server_identity, server_key, alice)
    }

    async fn test_external_proposal<F>(proposal_creation: F)
    where
        F: for<'a> Fn(
            &'a mut ExternalGroup<TestExternalClientConfig>,
            &'a SigningIdentity,
        ) -> BoxFuture<'a, MLSMessage>,
    {
        let (server_identity, server_key, mut alice) = setup_extern_proposal_test(true).await;
        let mut server = make_external_group(&alice).await;

        server
            .config
            .0
            .keychain
            .insert(server_identity.clone(), server_key, TEST_CIPHER_SUITE);

        // Create an external proposal
        let external_proposal = proposal_creation(&mut server, &server_identity).await;
        let auth_content = external_proposal.clone().into_plaintext().unwrap().into();

        let proposal_ref =
            ProposalRef::from_content(&server.cipher_suite_provider, &auth_content).unwrap();

        // Alice receives the proposal
        alice.process_message(external_proposal).await.unwrap();

        // Alice commits the proposal
        let commit_output = alice.group.commit(vec![]).await.unwrap();

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

        alice.process_pending_commit().await.unwrap();

        server
            .process_incoming_message(commit_output.commit_message)
            .await
            .unwrap();

        assert_eq!(alice.group.state, server.state);
    }

    #[futures_test::test]
    async fn external_group_can_propose_add() {
        test_external_proposal(|ext_group, ext_identity| {
            async move {
                let charlie_key_package =
                    test_key_package_message(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "charlie")
                        .await;

                ext_group
                    .propose_add(charlie_key_package, ext_identity, vec![])
                    .await
                    .unwrap()
            }
            .boxed()
        })
        .await
    }

    #[futures_test::test]
    async fn external_group_can_propose_remove() {
        test_external_proposal(|ext_group, ext_identity| {
            async move {
                ext_group
                    .propose_remove(1, ext_identity, vec![])
                    .await
                    .unwrap()
            }
            .boxed()
        })
        .await
    }

    #[futures_test::test]
    async fn external_group_external_proposal_not_allowed() {
        let (signing_id, secret_key, alice) = setup_extern_proposal_test(false).await;
        let mut server = make_external_group(&alice).await;

        server
            .config
            .0
            .keychain
            .insert(signing_id.clone(), secret_key, TEST_CIPHER_SUITE);

        let charlie_key_package =
            test_key_package_message(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "charlie").await;

        let res = server
            .propose_add(charlie_key_package, &signing_id, vec![])
            .await;

        assert_matches!(res, Err(MlsError::ExternalProposalsDisabled));
    }

    #[futures_test::test]
    async fn external_group_external_signing_identity_invalid() {
        let (server_identity, server_key) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"server".to_vec());

        let alice = test_group_two_members(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            Some(get_test_signing_identity(TEST_CIPHER_SUITE, b"not server".to_vec()).0),
        )
        .await;

        let mut server = make_external_group(&alice).await;

        server
            .config
            .0
            .keychain
            .insert(server_identity.clone(), server_key, TEST_CIPHER_SUITE);

        let res = server.propose_remove(1, &server_identity, vec![]).await;

        assert_matches!(res, Err(MlsError::InvalidExternalSigningIdentity));
    }

    #[futures_test::test]
    async fn external_group_errors_on_old_epoch() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let mut server = make_external_group_with_config(
            &alice,
            TestExternalClientBuilder::new_for_test()
                .max_epoch_jitter(0)
                .build_config(),
        )
        .await;

        let old_application_msg = alice
            .group
            .encrypt_application_message(&[], vec![])
            .await
            .unwrap();

        let commit_output = alice.group.commit(vec![]).await.unwrap();

        server
            .process_incoming_message(commit_output.commit_message)
            .await
            .unwrap();

        let res = server.process_incoming_message(old_application_msg).await;

        assert_matches!(res, Err(MlsError::InvalidEpoch(1)));
    }

    #[futures_test::test]
    async fn proposals_can_be_cached_externally() {
        let mut alice = test_group_with_one_commit(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let mut server = make_external_group_with_config(
            &alice,
            TestExternalClientBuilder::new_for_test()
                .cache_proposals(false)
                .build_config(),
        )
        .await;

        let proposal = alice.group.propose_update(vec![]).await.unwrap();

        let commit_output = alice.group.commit(vec![]).await.unwrap();

        server
            .process_incoming_message(proposal.clone())
            .await
            .unwrap();
        server.insert_proposal_from_message(proposal).unwrap();
        server
            .process_incoming_message(commit_output.commit_message)
            .await
            .unwrap();
    }

    #[futures_test::test]
    async fn external_group_can_observe_since_creation() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let info = alice.group.group_info_message(true).await.unwrap();

        let config = TestExternalClientBuilder::new_for_test().build_config();
        let mut server = ExternalGroup::join(config, info, None).await.unwrap();

        for _ in 0..2 {
            let commit = alice.group.commit(vec![]).await.unwrap().commit_message;
            alice.process_pending_commit().await.unwrap();
            server.process_incoming_message(commit).await.unwrap();
        }
    }

    #[futures_test::test]
    async fn external_group_can_be_serialized_to_json() {
        let server =
            make_external_group(&test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await).await;

        let snapshot = serde_json::to_vec(&server.snapshot(false)).unwrap();
        let snapshot_restored = serde_json::from_slice(&snapshot).unwrap();

        let server_restored =
            ExternalGroup::from_snapshot(server.config.clone(), snapshot_restored)
                .await
                .unwrap();

        assert_eq!(server.group_state(), server_restored.group_state());
    }
}
