use alloc::vec;
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};

use crate::{
    cipher_suite::CipherSuite,
    client::MlsError,
    client_builder::Preferences,
    client_config::ClientConfig,
    extension::RatchetTreeExt,
    identity::SigningIdentity,
    protocol_version::ProtocolVersion,
    psk::ExternalPskId,
    signer::Signable,
    storage_provider::psk::PskStoreIdValidator,
    tree_kem::{
        kem::TreeKem, node::LeafIndex, path_secret::PathSecret, TreeKemPrivate, UpdatePath,
    },
    ExtensionList,
};

#[cfg(feature = "external_commit")]
use crate::tree_kem::leaf_node::LeafNode;

use super::{
    confirmation_tag::ConfirmationTag,
    framing::{Content, MLSMessage, Sender},
    internal::{JustPreSharedKeyID, PskGroupId, ResumptionPSKUsage, ResumptionPsk},
    key_schedule::{CommitSecret, KeySchedule},
    message_processor::MessageProcessor,
    message_signature::AuthenticatedContent,
    proposal::{CustomProposal, Proposal, ProposalOrRef},
    ConfirmedTranscriptHash, ControlEncryptionMode, Group, GroupInfo,
};

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(aws_mls_core::arbitrary::Arbitrary))]
pub(crate) struct Commit {
    pub proposals: Vec<ProposalOrRef>,
    pub path: Option<UpdatePath>,
}

#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct CommitGeneration {
    pub content: AuthenticatedContent,
    pub pending_secrets: Option<(TreeKemPrivate, PathSecret)>,
}

#[derive(Clone, Debug)]
struct CommitOptions {
    pub prefer_path_update: bool,
    pub encryption_mode: ControlEncryptionMode,
    pub ratchet_tree_extension: bool,
}

#[derive(Clone, Debug)]
#[non_exhaustive]
/// Result of MLS commit operation using
/// [`Group::commit`](crate::group::Group::commit) or
/// [`CommitBuilder::build`](CommitBuilder::build).
pub struct CommitOutput {
    /// Commit message to send to other group members.
    pub commit_message: MLSMessage,
    /// Welcome message to send to new group members.
    pub welcome_message: Option<MLSMessage>,
    /// Ratchet tree to send out of band if
    /// [`Preferences::ratchet_tree_extension`] is not in use
    pub ratchet_tree: Option<Vec<u8>>,
}

impl CommitOutput {
    /// Commit message to send to other group members.
    pub fn commit_message(&self) -> &MLSMessage {
        &self.commit_message
    }

    /// Welcome message to send to new group members.
    pub fn welcome_message(&self) -> Option<&MLSMessage> {
        self.welcome_message.as_ref()
    }

    /// Ratchet tree to send out of band if
    /// [`Preferences::ratchet_tree_extension`] is not in use
    pub fn ratchet_tree(&self) -> Option<&[u8]> {
        self.ratchet_tree.as_deref()
    }
}

/// Build a commit with multiple proposals by-value.
///
/// Proposals within a commit can be by-value or by-reference.
/// Proposals received during the current epoch will be added to the resulting
/// commit by-reference automatically so long as they pass the rules defined
/// in the current
/// [proposal rules](crate::client_builder::ClientBuilder::proposal_rules).
pub struct CommitBuilder<'a, C>
where
    C: ClientConfig + Clone,
{
    group: &'a mut Group<C>,
    pub(super) proposals: Vec<Proposal>,
    authenticated_data: Vec<u8>,
    group_info_extensions: ExtensionList,
    signing_identity: Option<SigningIdentity>,
    preferences: Option<Preferences>,
}

impl<'a, C> CommitBuilder<'a, C>
where
    C: ClientConfig + Clone,
{
    /// Insert an [`AddProposal`](crate::group::proposal::AddProposal) into
    /// the current commit that is being built.
    pub fn add_member(mut self, key_package: MLSMessage) -> Result<CommitBuilder<'a, C>, MlsError> {
        let proposal = self.group.add_proposal(key_package)?;
        self.proposals.push(proposal);
        Ok(self)
    }

    /// Set group info extensions that will be inserted into the resulting
    /// [welcome message](CommitOutput::welcome_message) for new members.
    ///
    /// Group info extensions that are transmitted as part of a welcome message
    /// are encrypted along with other private values.
    ///
    /// These extensions can be retrieved as part of
    /// [`NewMemberInfo`](crate::group::NewMemberInfo) that is returned
    /// by joining the group via
    /// [`Client::join_group`](crate::Client::join_group).
    pub fn set_group_info_ext(self, extensions: ExtensionList) -> Self {
        Self {
            group_info_extensions: extensions,
            ..self
        }
    }

    /// Insert a [`RemoveProposal`](crate::group::proposal::RemoveProposal) into
    /// the current commit that is being built.
    pub fn remove_member(mut self, index: u32) -> Result<Self, MlsError> {
        let proposal = self.group.remove_proposal(index)?;
        self.proposals.push(proposal);
        Ok(self)
    }

    /// Insert a
    /// [`GroupContextExtensions`](crate::group::proposal::Proposal::GroupContextExtensions)
    /// into the current commit that is being built.
    pub fn set_group_context_ext(mut self, extensions: ExtensionList) -> Result<Self, MlsError> {
        let proposal = self.group.group_context_extensions_proposal(extensions);
        self.proposals.push(proposal);
        Ok(self)
    }

    /// Insert a
    /// [`PreSharedKeyProposal`](crate::group::proposal::PreSharedKeyProposal) with
    /// an external PSK into the current commit that is being built.
    pub fn add_external_psk(mut self, psk_id: ExternalPskId) -> Result<Self, MlsError> {
        let key_id = JustPreSharedKeyID::External(psk_id);
        let proposal = self.group.psk_proposal(key_id)?;
        self.proposals.push(proposal);
        Ok(self)
    }

    /// Insert a
    /// [`PreSharedKeyProposal`](crate::group::proposal::PreSharedKeyProposal) with
    /// a resumption PSK into the current commit that is being built.
    pub fn add_resumption_psk(mut self, psk_epoch: u64) -> Result<Self, MlsError> {
        let psk_id = ResumptionPsk {
            psk_epoch,
            usage: ResumptionPSKUsage::Application,
            psk_group_id: PskGroupId(self.group.group_id().to_vec()),
        };

        let key_id = JustPreSharedKeyID::Resumption(psk_id);
        let proposal = self.group.psk_proposal(key_id)?;
        self.proposals.push(proposal);
        Ok(self)
    }

    /// Insert a [`ReInitProposal`](crate::group::proposal::ReInitProposal) into
    /// the current commit that is being built.
    pub fn reinit(
        mut self,
        group_id: Option<Vec<u8>>,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        extensions: ExtensionList,
    ) -> Result<Self, MlsError> {
        let proposal = self
            .group
            .reinit_proposal(group_id, version, cipher_suite, extensions)?;

        self.proposals.push(proposal);
        Ok(self)
    }

    /// Insert a [`CustomProposal`](crate::group::proposal::CustomProposal) into
    /// the current commit that is being built.
    pub fn custom_proposal(mut self, proposal: CustomProposal) -> Self {
        self.proposals.push(Proposal::Custom(proposal));
        self
    }

    /// Insert a proposal that was previously constructed such as when a
    /// proposal is returned from
    /// [`StateUpdate::unused_proposals`](super::StateUpdate::unused_proposals).
    pub fn raw_proposal(mut self, proposal: Proposal) -> Self {
        self.proposals.push(proposal);
        self
    }

    /// Insert proposals that were previously constructed such as when a
    /// proposal is returned from
    /// [`StateUpdate::unused_proposals`](super::StateUpdate::unused_proposals).
    pub fn raw_proposals(mut self, mut proposals: Vec<Proposal>) -> Self {
        self.proposals.append(&mut proposals);
        self
    }

    /// Add additional authenticated data to the commit.
    ///
    /// # Warning
    ///
    /// The data provided here is always sent unencrypted.
    pub fn authenticated_data(self, authenticated_data: Vec<u8>) -> Self {
        Self {
            authenticated_data,
            ..self
        }
    }

    /// Change the committer's signing identity as part of making this commit.
    /// This will only succeed if the [`IdentityProvider`](crate::IdentityProvider)
    /// in use by the group considers the credential inside this signing_identity
    /// [valid](crate::IdentityProvider::validate)
    /// and results in the same
    /// [identity](crate::IdentityProvider::identity)
    /// being used.
    pub fn set_new_signing_identity(self, signing_identity: SigningIdentity) -> Self {
        Self {
            signing_identity: Some(signing_identity),
            ..self
        }
    }

    /// Set [`Preferences`](crate::client_builder::Preferences) used to make
    /// this commit. By default, preferences from the group's
    /// [`ClientConfig`](crate::client_config::ClientConfig) are used.
    pub fn set_commit_preferences(self, preferences: Preferences) -> Self {
        Self {
            preferences: Some(preferences),
            ..self
        }
    }

    /// Finalize the commit to send.
    ///
    /// # Errors
    ///
    /// This function will return an error if any of the proposals provided
    /// are not contextually valid according to the rules defined by the
    /// MLS RFC, or if they do not pass the custom rules defined by the current
    /// [proposal rules](crate::client_builder::ClientBuilder::proposal_rules).
    pub async fn build(self) -> Result<CommitOutput, MlsError> {
        self.group
            .commit_internal(
                self.proposals,
                #[cfg(feature = "external_commit")]
                None,
                self.authenticated_data,
                self.group_info_extensions,
                self.signing_identity,
                self.preferences,
            )
            .await
    }
}

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    /// Perform a commit of received proposals.
    ///
    /// This function is the equivalent of [`Group::commit_builder`] immediately
    /// followed by [`CommitBuilder::build`]. Any received proposals since the
    /// last commit will be included in the resulting message by-reference.
    ///
    /// Data provided in the `authenticated_data` field will be placed into
    /// the resulting commit message unencrypted.
    ///
    /// # Pending Commits
    ///
    /// When a commit is created, it is not applied immediately in order to
    /// allow for the resolution of conflicts when multiple members of a group
    /// attempt to make commits at the same time. For example, a central relay
    /// can be used to decide which commit should be accepted by the group by
    /// determining a consistent view of commit packet order for all clients.
    ///
    /// Pending commits are stored internally as part of the group's state
    /// so they do not need to be tracked outside of this library. Any commit
    /// message that is processed before calling [Group::apply_pending_commit]
    /// will clear the currently pending commit.
    ///
    /// # Empty Commits
    ///
    /// Sending a commit that contains no proposals is a valid operation
    /// within the MLS protocol. It is useful for providing stronger forward
    /// secrecy and post-compromise security, especially for long running
    /// groups when group membership does not change often.
    ///
    /// # Path Updates
    ///
    /// Path updates provide forward secrecy and post-compromise security
    /// within the MLS protocol.
    /// The [force_commit_path_update](crate::client_builder::Preferences)
    /// controls the ability of a group to send a commit without a path update.
    /// An update path will automatically be sent if there are no proposals
    /// in the commit, or if any proposal other than
    /// [`Add`](crate::group::proposal::Proposal::Add),
    /// [`Psk`](crate::group::proposal::Proposal::Psk),
    /// or [`ReInit`](crate::group::proposal::Proposal::ReInit) are part of the commit.
    pub async fn commit(&mut self, authenticated_data: Vec<u8>) -> Result<CommitOutput, MlsError> {
        self.commit_internal(
            vec![],
            #[cfg(feature = "external_commit")]
            None,
            authenticated_data,
            Default::default(),
            None,
            None,
        )
        .await
    }

    /// Create a new commit builder that can include proposals
    /// by-value.
    pub fn commit_builder(&mut self) -> CommitBuilder<C> {
        CommitBuilder {
            group: self,
            proposals: Default::default(),
            authenticated_data: Default::default(),
            group_info_extensions: Default::default(),
            signing_identity: Default::default(),
            preferences: Default::default(),
        }
    }

    /// Returns commit and optional [`MLSMessage`] containing a welcome message
    /// for newly added members.
    pub(super) async fn commit_internal(
        &mut self,
        proposals: Vec<Proposal>,
        #[cfg(feature = "external_commit")] external_leaf: Option<&LeafNode>,
        authenticated_data: Vec<u8>,
        group_info_extensions: ExtensionList,
        signing_identity: Option<SigningIdentity>,
        preferences: Option<Preferences>,
    ) -> Result<CommitOutput, MlsError> {
        if self.pending_commit.is_some() {
            return Err(MlsError::ExistingPendingCommit);
        }

        let preferences = preferences.unwrap_or(self.config.preferences());

        let options = CommitOptions {
            prefer_path_update: preferences.force_commit_path_update,
            encryption_mode: preferences.encryption_mode(),
            ratchet_tree_extension: preferences.ratchet_tree_extension,
        };

        #[cfg(feature = "external_commit")]
        let is_external = external_leaf.is_some();

        // Construct an initial Commit object with the proposals field populated from Proposals
        // received during the current epoch, and an empty path field. Add passed in proposals
        // by value
        #[cfg(feature = "external_commit")]
        let sender = if is_external {
            Sender::NewMemberCommit
        } else {
            Sender::Member(*self.private_tree.self_index)
        };

        #[cfg(not(feature = "external_commit"))]
        let sender = Sender::Member(*self.private_tree.self_index);

        #[cfg(feature = "external_commit")]
        let new_signer = match external_leaf {
            Some(leaf_node) => {
                self.signer_for_identity(Some(&leaf_node.signing_identity))
                    .await
            }
            None => self.signer_for_identity(signing_identity.as_ref()).await,
        }?;

        #[cfg(not(feature = "external_commit"))]
        let new_signer = self.signer_for_identity(signing_identity.as_ref()).await?;

        #[cfg(feature = "external_commit")]
        let old_signer = match external_leaf {
            Some(leaf_node) => {
                self.signer_for_identity(Some(&leaf_node.signing_identity))
                    .await
            }
            None => self.signer().await,
        }?;

        #[cfg(not(feature = "external_commit"))]
        let old_signer = self.signer().await?;

        let (commit_proposals, proposal_effects) = self
            .state
            .proposals
            .prepare_commit(
                sender,
                proposals,
                &self.context().extensions,
                &self.config.identity_provider(),
                &self.cipher_suite_provider,
                &self.state.public_tree,
                #[cfg(feature = "external_commit")]
                external_leaf,
                PskStoreIdValidator::from(self.config.secret_store()),
                self.config.proposal_rules(),
                &self.state.roster(),
            )
            .await?;

        let mut provisional_state = self.calculate_provisional_state(proposal_effects)?;
        let mut provisional_private_tree = self.provisional_private_tree(&provisional_state)?;

        #[cfg(feature = "external_commit")]
        if is_external {
            provisional_private_tree.self_index = provisional_state
                .external_init
                .ok_or(MlsError::ExternalCommitMissingExternalInit)?
                .0;

            self.private_tree.self_index = provisional_private_tree.self_index;
        }

        let mut provisional_group_context = provisional_state.group_context;
        provisional_group_context.epoch += 1;

        // Decide whether to populate the path field: If the path field is required based on the
        // proposals that are in the commit (see above), then it MUST be populated. Otherwise, the
        // sender MAY omit the path field at its discretion.
        let perform_path_update =
            options.prefer_path_update || provisional_state.path_update_required;

        let added_leaves = provisional_state.added_leaves;

        let (update_path, path_secrets, root_secret) = if perform_path_update {
            // If populating the path field: Create an UpdatePath using the new tree. Any new
            // member (from an add proposal) MUST be excluded from the resolution during the
            // computation of the UpdatePath. The GroupContext for this operation uses the
            // group_id, epoch, tree_hash, and confirmed_transcript_hash values in the initial
            // GroupContext object. The leaf_key_package for this UpdatePath must have a
            // parent_hash extension.
            let encap_gen = TreeKem::new(
                &mut provisional_state.public_tree,
                &mut provisional_private_tree,
            )
            .encap(
                &mut provisional_group_context,
                &added_leaves
                    .iter()
                    .map(|(_, leaf_index)| *leaf_index)
                    .collect::<Vec<LeafIndex>>(),
                &new_signer,
                self.config.leaf_properties(),
                signing_identity,
                self.config.identity_provider(),
                &self.cipher_suite_provider,
                #[cfg(test)]
                &self.commit_modifiers,
            )
            .await?;

            (
                Some(encap_gen.update_path),
                Some(encap_gen.path_secrets),
                Some(encap_gen.root_secret),
            )
        } else {
            // Update the tree hash, since it was not updated by encap.
            provisional_state.public_tree.update_hashes(
                &mut vec![provisional_private_tree.self_index],
                &[],
                &self.cipher_suite_provider,
            )?;

            provisional_group_context.tree_hash = provisional_state
                .public_tree
                .tree_hash(&self.cipher_suite_provider)?;

            (None, None, None)
        };

        let commit_secret =
            CommitSecret::from_root_secret(&self.cipher_suite_provider, root_secret.as_ref())?;

        let psks = if let Some(psk) = &self.previous_psk {
            vec![psk.id.clone()]
        } else {
            provisional_state.psks.clone()
        };

        let psk_secret = self.get_psk(&provisional_state.psks).await?;

        let commit = Commit {
            proposals: commit_proposals,
            path: update_path,
        };

        let mut auth_content = AuthenticatedContent::new_signed(
            &self.cipher_suite_provider,
            self.context(),
            sender,
            Content::Commit(commit),
            &old_signer,
            options.encryption_mode.into(),
            authenticated_data,
        )?;

        // Use the signature, the commit_secret and the psk_secret to advance the key schedule and
        // compute the confirmation_tag value in the MLSPlaintext.
        let confirmed_transcript_hash = ConfirmedTranscriptHash::create(
            self.cipher_suite_provider(),
            &self.state.interim_transcript_hash,
            &auth_content,
        )?;

        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash;

        // Add the ratchet tree extension if necessary
        let mut extensions = ExtensionList::new();

        if options.ratchet_tree_extension {
            let ratchet_tree_ext = RatchetTreeExt {
                tree_data: provisional_state.public_tree.export_node_data(),
            };

            extensions.set_from(ratchet_tree_ext)?;
        }

        // Add in any user provided extensions
        extensions.append(group_info_extensions);

        let key_schedule_result = KeySchedule::from_key_schedule(
            &self.key_schedule,
            &commit_secret,
            &provisional_group_context,
            self.state.public_tree.total_leaf_count(),
            &psk_secret,
            &self.cipher_suite_provider,
        )?;

        let confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &provisional_group_context.confirmed_transcript_hash,
            &self.cipher_suite_provider,
        )?;

        auth_content.auth.confirmation_tag = Some(confirmation_tag.clone());

        // Construct a GroupInfo reflecting the new state
        // Group ID, epoch, tree, and confirmed transcript hash from the new state
        let mut group_info = GroupInfo {
            group_context: provisional_group_context,
            extensions,
            confirmation_tag, // The confirmation_tag from the MLSPlaintext object
            signer: provisional_private_tree.self_index,
            signature: vec![],
        };

        group_info.grease(self.cipher_suite_provider())?;

        // Sign the GroupInfo using the member's private signing key
        group_info.sign(&self.cipher_suite_provider, &new_signer, &())?;

        let welcome_message = self.make_welcome_message(
            added_leaves,
            &key_schedule_result.joiner_secret,
            &psk_secret,
            path_secrets.as_ref(),
            psks,
            &group_info,
        )?;

        let commit_message = self.format_for_wire(auth_content.clone())?;

        let pending_commit = CommitGeneration {
            content: auth_content,
            pending_secrets: root_secret.map(|rs| (provisional_private_tree, rs)),
        };

        self.pending_commit = Some(pending_commit);

        let ratchet_tree = (!options.ratchet_tree_extension)
            .then(|| {
                provisional_state
                    .public_tree
                    .export_node_data()
                    .mls_encode_to_vec()
            })
            .transpose()?;

        Ok(CommitOutput {
            commit_message,
            welcome_message,
            ratchet_tree,
        })
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use alloc::vec::Vec;

    use crate::{
        crypto::SignatureSecretKey,
        tree_kem::{leaf_node::LeafNode, TreeKemPublic, UpdatePathNode},
    };
    use core::fmt;

    pub struct CommitModifiers<CP> {
        pub modify_leaf: fn(&mut LeafNode, &SignatureSecretKey, &CP),
        pub modify_tree: fn(&mut TreeKemPublic),
        pub modify_path: fn(Vec<UpdatePathNode>) -> Vec<UpdatePathNode>,
    }

    impl<CP> fmt::Debug for CommitModifiers<CP> {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            write!(fmt, "CommitModifiers")
        }
    }

    impl<CP> Copy for CommitModifiers<CP> {}

    impl<CP> Clone for CommitModifiers<CP> {
        fn clone(&self) -> Self {
            *self
        }
    }

    impl<CP> Default for CommitModifiers<CP> {
        fn default() -> Self {
            Self {
                modify_leaf: |_, _, _| (),
                modify_tree: |_| (),
                modify_path: |a| a,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use thiserror::Error;

    use alloc::boxed::Box;

    use aws_mls_core::{
        group::RosterUpdate,
        identity::{CredentialType, IdentityProvider, IdentityWarning},
        time::MlsTime,
    };

    use crate::{crypto::test_utils::TestCryptoProvider, extension::ExternalSendersExt, Client};

    use crate::{
        client::test_utils::{test_client_with_key_pkg, TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        client_builder::{
            test_utils::TestClientConfig, BaseConfig, ClientBuilder, WithCryptoProvider,
            WithIdentityProvider, WithKeychain,
        },
        client_config::ClientConfig,
        extension::{
            test_utils::{TestExtension, TEST_EXTENSION_TYPE},
            RequiredCapabilitiesExt,
        },
        group::{
            proposal::{PreSharedKeyProposal, ProposalType},
            test_utils::{test_group_custom_config, test_n_member_group},
        },
        identity::test_utils::get_test_signing_identity,
        identity::{basic::BasicIdentityProvider, test_utils::get_test_basic_credential},
        key_package::test_utils::test_key_package_message,
        psk::{JustPreSharedKeyID, PreSharedKey, PreSharedKeyID},
        storage_provider::in_memory::InMemoryKeychainStorage,
    };

    use super::*;

    async fn test_commit_builder_group() -> Group<TestClientConfig> {
        test_group_custom_config(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, |b| {
            b.custom_proposal_type(ProposalType::from(42))
        })
        .await
        .group
    }

    fn assert_commit_builder_output<C: ClientConfig>(
        group: Group<C>,
        commit_output: CommitOutput,
        expected: Vec<Proposal>,
        welcome_count: usize,
    ) {
        let plaintext = commit_output.commit_message.into_plaintext().unwrap();

        let commit_data = match plaintext.content.content {
            Content::Commit(commit) => commit,
            _ => panic!("Found non-commit data"),
        };

        assert_eq!(commit_data.proposals.len(), expected.len());

        commit_data.proposals.into_iter().for_each(|proposal| {
            let proposal = match proposal {
                ProposalOrRef::Proposal(p) => p,
                ProposalOrRef::Reference(_) => panic!("found proposal reference"),
            };

            if let Some(psk_id) = match &proposal {
                Proposal::Psk(PreSharedKeyProposal { psk: PreSharedKeyID { key_id: JustPreSharedKeyID::External(psk_id), .. },}) => Some(psk_id),
                _ => None,
            } {
                let found = expected.iter().any(|item| matches!(item, Proposal::Psk(PreSharedKeyProposal { psk: PreSharedKeyID { key_id: JustPreSharedKeyID::External(id), .. }}) if id == psk_id));

                assert!(found)
            } else {
                assert!(expected.contains(&proposal));
            }
        });

        if welcome_count > 0 {
            let welcome_msg = commit_output.welcome_message.unwrap();

            assert_eq!(welcome_msg.version, group.state.context.protocol_version);

            let welcome_msg = welcome_msg.into_welcome().unwrap();

            assert_eq!(welcome_msg.cipher_suite, group.state.context.cipher_suite);
            assert_eq!(welcome_msg.secrets.len(), welcome_count);
        } else {
            assert!(commit_output.welcome_message.is_none());
        }
    }

    #[futures_test::test]
    async fn test_commit_builder_add() {
        let mut group = test_commit_builder_group().await;

        let test_key_package =
            test_key_package_message(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "alice").await;

        let commit_output = group
            .commit_builder()
            .add_member(test_key_package.clone())
            .unwrap()
            .build()
            .await
            .unwrap();

        let expected_add = group.add_proposal(test_key_package).unwrap();

        assert_commit_builder_output(group, commit_output, vec![expected_add], 1)
    }

    #[futures_test::test]
    async fn test_commit_builder_add_with_ext() {
        let mut group = test_commit_builder_group().await;

        let (bob_client, bob_key_package) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;

        let ext = TestExtension { foo: 42 };
        let mut extension_list = ExtensionList::default();
        extension_list.set_from(ext.clone()).unwrap();

        let welcome_message = group
            .commit_builder()
            .add_member(bob_key_package)
            .unwrap()
            .set_group_info_ext(extension_list)
            .build()
            .await
            .unwrap()
            .welcome_message;

        let (_, context) = bob_client
            .join_group(None, welcome_message.unwrap())
            .await
            .unwrap();

        assert_eq!(
            context
                .group_info_extensions
                .get_as::<TestExtension>()
                .unwrap()
                .unwrap(),
            ext
        );
    }

    #[futures_test::test]
    async fn test_commit_builder_remove() {
        let mut group = test_commit_builder_group().await;
        let test_key_package =
            test_key_package_message(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "alice").await;

        group
            .commit_builder()
            .add_member(test_key_package)
            .unwrap()
            .build()
            .await
            .unwrap();

        group.apply_pending_commit().await.unwrap();

        let commit_output = group
            .commit_builder()
            .remove_member(1)
            .unwrap()
            .build()
            .await
            .unwrap();

        let expected_remove = group.remove_proposal(1).unwrap();

        assert_commit_builder_output(group, commit_output, vec![expected_remove], 0);
    }

    #[futures_test::test]
    async fn test_commit_builder_psk() {
        let mut group = test_commit_builder_group().await;
        let test_psk = ExternalPskId::new(vec![1]);

        group
            .config
            .secret_store()
            .insert(test_psk.clone(), PreSharedKey::from(vec![1]));

        let commit_output = group
            .commit_builder()
            .add_external_psk(test_psk.clone())
            .unwrap()
            .build()
            .await
            .unwrap();

        let key_id = JustPreSharedKeyID::External(test_psk);
        let expected_psk = group.psk_proposal(key_id).unwrap();

        assert_commit_builder_output(group, commit_output, vec![expected_psk], 0)
    }

    #[futures_test::test]
    async fn test_commit_builder_group_context_ext() {
        let mut group = test_commit_builder_group().await;
        let mut test_ext = ExtensionList::default();
        test_ext
            .set_from(RequiredCapabilitiesExt::default())
            .unwrap();

        let commit_output = group
            .commit_builder()
            .set_group_context_ext(test_ext.clone())
            .unwrap()
            .build()
            .await
            .unwrap();

        let expected_ext = group.group_context_extensions_proposal(test_ext);

        assert_commit_builder_output(group, commit_output, vec![expected_ext], 0);
    }

    #[futures_test::test]
    async fn test_commit_builder_reinit() {
        let mut group = test_commit_builder_group().await;
        let test_group_id = "foo".as_bytes().to_vec();
        let test_cipher_suite = CipherSuite::CURVE25519_CHACHA;
        let test_protocol_version = TEST_PROTOCOL_VERSION;
        let mut test_ext = ExtensionList::default();

        test_ext
            .set_from(RequiredCapabilitiesExt::default())
            .unwrap();

        let commit_output = group
            .commit_builder()
            .reinit(
                Some(test_group_id.clone()),
                test_protocol_version,
                test_cipher_suite,
                test_ext.clone(),
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        let expected_reinit = group
            .reinit_proposal(
                Some(test_group_id),
                test_protocol_version,
                test_cipher_suite,
                test_ext,
            )
            .unwrap();

        assert_commit_builder_output(group, commit_output, vec![expected_reinit], 0);
    }

    #[futures_test::test]
    async fn test_commit_builder_custom_proposal() {
        let mut group = test_commit_builder_group().await;

        let proposal = CustomProposal::new(42.into(), vec![0, 1]);

        let commit_output = group
            .commit_builder()
            .custom_proposal(proposal.clone())
            .build()
            .await
            .unwrap();

        assert_commit_builder_output(group, commit_output, vec![Proposal::Custom(proposal)], 0);
    }

    #[futures_test::test]
    async fn test_commit_builder_chaining() {
        let mut group = test_commit_builder_group().await;
        let kp1 = test_key_package_message(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "alice").await;
        let kp2 = test_key_package_message(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;

        let expected_adds = vec![
            group.add_proposal(kp1.clone()).unwrap(),
            group.add_proposal(kp2.clone()).unwrap(),
        ];

        let commit_output = group
            .commit_builder()
            .add_member(kp1)
            .unwrap()
            .add_member(kp2)
            .unwrap()
            .build()
            .await
            .unwrap();

        assert_commit_builder_output(group, commit_output, expected_adds, 2);
    }

    #[futures_test::test]
    async fn test_commit_builder_empty_commit() {
        let mut group = test_commit_builder_group().await;

        let commit_output = group.commit_builder().build().await.unwrap();

        assert_commit_builder_output(group, commit_output, vec![], 0);
    }

    #[futures_test::test]
    async fn test_commit_builder_authenticated_data() {
        let mut group = test_commit_builder_group().await;
        let test_data = "test".as_bytes().to_vec();

        let commit_output = group
            .commit_builder()
            .authenticated_data(test_data.clone())
            .build()
            .await
            .unwrap();

        assert_eq!(
            commit_output
                .commit_message
                .into_plaintext()
                .unwrap()
                .content
                .authenticated_data,
            test_data
        );
    }

    #[futures_test::test]
    async fn commit_can_change_credential() {
        let cs = TEST_CIPHER_SUITE;
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, cs, 3).await;
        let (identity, secret_key) = get_test_signing_identity(cs, b"member".to_vec());

        // Add new identity
        groups[0]
            .group
            .config
            .0
            .keychain
            .insert(identity.clone(), secret_key, cs);

        let commit_output = groups[0]
            .group
            .commit_builder()
            .set_new_signing_identity(identity.clone())
            .build()
            .await
            .unwrap();

        // Check that the credential was updated by in the committer's state.
        groups[0].process_pending_commit().await.unwrap();
        let new_member = groups[0].group.roster().first().cloned().unwrap();

        assert_eq!(
            new_member.signing_identity().credential,
            get_test_basic_credential(b"member".to_vec())
        );

        assert_eq!(
            new_member.signing_identity().signature_key,
            identity.signature_key
        );

        // Check that the credential was updated in another member's state.
        groups[1]
            .process_message(commit_output.commit_message)
            .await
            .unwrap();

        let new_member = groups[1].group.roster().first().cloned().unwrap();

        assert_eq!(
            new_member.signing_identity().credential,
            get_test_basic_credential(b"member".to_vec())
        );

        assert_eq!(
            new_member.signing_identity().signature_key,
            identity.signature_key
        );
    }

    #[futures_test::test]
    async fn commit_includes_tree_if_no_ratchet_tree_ext() {
        let mut group = test_group_custom_config(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, |b| {
            b.custom_proposal_type(ProposalType::from(42))
                .preferences(Preferences::default())
        })
        .await
        .group;

        let commit = group.commit(vec![]).await.unwrap();

        group.apply_pending_commit().await.unwrap();

        let new_tree = group.export_tree().unwrap();

        assert_eq!(new_tree, commit.ratchet_tree.unwrap())
    }

    #[futures_test::test]
    async fn commit_does_not_include_tree_if_ratchet_tree_ext() {
        let mut group = test_group_custom_config(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, |b| {
            b.custom_proposal_type(ProposalType::from(42))
                .preferences(Preferences::default().with_ratchet_tree_extension(true))
        })
        .await
        .group;

        let commit = group.commit(vec![]).await.unwrap();

        assert!(commit.ratchet_tree().is_none());
    }

    #[futures_test::test]
    async fn member_identity_is_validated_against_new_extensions() {
        let (alice, identity) = client_with_test_extension(b"alice");

        let mut alice = alice
            .create_group(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                identity,
                ExtensionList::new(),
            )
            .await
            .unwrap();

        let (bob, identity) = client_with_test_extension(b"bob");

        let bob_kp = bob
            .generate_key_package_message(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, identity)
            .await
            .unwrap();

        let mut extension_list = ExtensionList::new();
        let extension = TestExtension { foo: b'a' };
        extension_list.set_from(extension.clone()).unwrap();

        let res = alice
            .commit_builder()
            .add_member(bob_kp)
            .unwrap()
            .set_group_context_ext(extension_list.clone())
            .unwrap()
            .build()
            .await;

        assert!(res.is_err());

        let (alex, identity) = client_with_test_extension(b"alex");

        let alex_kp = alex
            .generate_key_package_message(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, identity)
            .await
            .unwrap();

        alice
            .commit_builder()
            .add_member(alex_kp)
            .unwrap()
            .set_group_context_ext(extension_list.clone())
            .unwrap()
            .build()
            .await
            .unwrap();
    }

    #[futures_test::test]
    async fn server_identity_is_validated_against_new_extensions() {
        let (alice, identity) = client_with_test_extension(b"alice");

        let mut alice = alice
            .create_group(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                identity,
                ExtensionList::new(),
            )
            .await
            .unwrap();

        let mut extension_list = ExtensionList::new();
        let extension = TestExtension { foo: b'a' };
        extension_list.set_from(extension.clone()).unwrap();

        let (alex_server, _) = get_test_signing_identity(TEST_CIPHER_SUITE, b"alex".to_vec());

        let mut alex_extensions = extension_list.clone();

        alex_extensions
            .set_from(ExternalSendersExt {
                allowed_senders: vec![alex_server],
            })
            .unwrap();

        let res = alice
            .commit_builder()
            .set_group_context_ext(alex_extensions)
            .unwrap()
            .build()
            .await;

        assert!(res.is_err());

        let (bob_server, _) = get_test_signing_identity(TEST_CIPHER_SUITE, b"bob".to_vec());

        let mut bob_extensions = extension_list;

        bob_extensions
            .set_from(ExternalSendersExt {
                allowed_senders: vec![bob_server],
            })
            .unwrap();

        alice
            .commit_builder()
            .set_group_context_ext(bob_extensions)
            .unwrap()
            .build()
            .await
            .unwrap();
    }

    #[derive(Debug, Clone)]
    struct IdentityProviderWithExtension(BasicIdentityProvider);

    #[derive(Debug, Clone, Error)]
    #[error("test error")]
    struct IdentityProviderWithExtensionError {}

    impl IdentityProviderWithExtension {
        // True if the identity starts with the character `foo` from `TestExtension` or if `TestExtension`
        // is not set.
        async fn starts_with_foo(
            &self,
            identity: &SigningIdentity,
            _timestamp: Option<MlsTime>,
            extensions: Option<&ExtensionList>,
        ) -> bool {
            if let Some(extensions) = extensions {
                if let Some(ext) = extensions.get_as::<TestExtension>().unwrap() {
                    self.identity(identity).await.unwrap()[0] == ext.foo
                } else {
                    true
                }
            } else {
                true
            }
        }
    }

    #[async_trait]
    impl IdentityProvider for IdentityProviderWithExtension {
        type Error = IdentityProviderWithExtensionError;

        async fn validate_member(
            &self,
            identity: &SigningIdentity,
            timestamp: Option<MlsTime>,
            extensions: Option<&ExtensionList>,
        ) -> Result<(), Self::Error> {
            self.starts_with_foo(identity, timestamp, extensions)
                .await
                .then_some(())
                .ok_or(IdentityProviderWithExtensionError {})
        }

        async fn validate_external_sender(
            &self,
            identity: &SigningIdentity,
            timestamp: Option<MlsTime>,
            extensions: Option<&ExtensionList>,
        ) -> Result<(), Self::Error> {
            (!self.starts_with_foo(identity, timestamp, extensions).await)
                .then_some(())
                .ok_or(IdentityProviderWithExtensionError {})
        }

        async fn identity(
            &self,
            signing_identity: &SigningIdentity,
        ) -> Result<Vec<u8>, Self::Error> {
            self.0
                .identity(signing_identity)
                .await
                .map_err(|_| IdentityProviderWithExtensionError {})
        }

        async fn valid_successor(
            &self,
            _predecessor: &SigningIdentity,
            _successor: &SigningIdentity,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        fn supported_types(&self) -> Vec<CredentialType> {
            self.0.supported_types()
        }

        async fn identity_warnings(
            &self,
            _update: &RosterUpdate,
        ) -> Result<Vec<IdentityWarning>, Self::Error> {
            Ok(vec![])
        }
    }

    type ExtensionClientConfig = WithIdentityProvider<
        IdentityProviderWithExtension,
        WithKeychain<InMemoryKeychainStorage, WithCryptoProvider<TestCryptoProvider, BaseConfig>>,
    >;

    fn client_with_test_extension(name: &[u8]) -> (Client<ExtensionClientConfig>, SigningIdentity) {
        let (identity, secret_key) = get_test_signing_identity(TEST_CIPHER_SUITE, name.to_vec());

        let client = ClientBuilder::new()
            .crypto_provider(TestCryptoProvider::new())
            .keychain(InMemoryKeychainStorage::new())
            .single_signing_identity(identity.clone(), secret_key, TEST_CIPHER_SUITE)
            .extension_types(vec![TEST_EXTENSION_TYPE.into()])
            .identity_provider(IdentityProviderWithExtension(BasicIdentityProvider::new()))
            .build();

        (client, identity)
    }
}
