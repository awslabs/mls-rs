use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    cipher_suite::CipherSuite,
    client_config::{ClientConfig, ProposalFilterInit, PskStore},
    extension::{ExtensionList, GroupContextExtension, RatchetTreeExt},
    key_package::KeyPackage,
    keychain::Keychain,
    protocol_version::ProtocolVersion,
    psk::{ExternalPskId, ResumptionPskSearch},
    signer::Signable,
    tree_kem::{
        kem::TreeKem, leaf_node::LeafNode, node::LeafIndex, path_secret::PathSecret,
        TreeKemPrivate, UpdatePath,
    },
};

use super::{
    confirmation_tag::ConfirmationTag,
    framing::{Content, MLSMessage, Sender},
    key_schedule::{CommitSecret, KeySchedule},
    message_processor::MessageProcessor,
    message_signature::MLSAuthenticatedContent,
    proposal::{Proposal, ProposalOrRef},
    ConfirmedTranscriptHash, ControlEncryptionMode, Group, GroupError, GroupInfo,
};

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) struct Commit {
    #[tls_codec(with = "crate::tls::DefVec")]
    pub proposals: Vec<ProposalOrRef>,
    pub path: Option<UpdatePath>,
}

#[derive(
    Clone,
    PartialEq,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
)]
pub(super) struct CommitGeneration {
    pub content: MLSAuthenticatedContent,
    pub pending_secrets: Option<(TreeKemPrivate, PathSecret)>,
}

#[derive(Clone, Debug)]
struct CommitOptions {
    pub prefer_path_update: bool,
    pub encryption_mode: ControlEncryptionMode,
    pub ratchet_tree_extension: bool,
}

pub struct CommitBuilder<'a, C>
where
    C: ClientConfig + Clone,
{
    group: &'a mut Group<C>,
    pub(super) proposals: Vec<Proposal>,
    authenticated_data: Vec<u8>,
}

impl<'a, C> CommitBuilder<'a, C>
where
    C: ClientConfig + Clone,
{
    pub fn add_member(mut self, key_package: KeyPackage) -> Result<Self, GroupError> {
        let proposal = self.group.add_proposal(key_package)?;
        self.proposals.push(proposal);
        Ok(self)
    }

    pub fn remove_member(mut self, index: u32) -> Result<Self, GroupError> {
        let proposal = self.group.remove_proposal(index)?;
        self.proposals.push(proposal);
        Ok(self)
    }

    pub fn set_group_context_ext(
        mut self,
        extensions: ExtensionList<GroupContextExtension>,
    ) -> Result<Self, GroupError> {
        let proposal = self.group.group_context_extensions_proposal(extensions);
        self.proposals.push(proposal);
        Ok(self)
    }

    pub fn add_psk(mut self, psk_id: ExternalPskId) -> Result<Self, GroupError> {
        let proposal = self.group.psk_proposal(psk_id)?;
        self.proposals.push(proposal);
        Ok(self)
    }

    pub fn reinit(
        mut self,
        group_id: Option<Vec<u8>>,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        extensions: ExtensionList<GroupContextExtension>,
    ) -> Result<Self, GroupError> {
        let proposal = self
            .group
            .reinit_proposal(group_id, version, cipher_suite, extensions)?;

        self.proposals.push(proposal);
        Ok(self)
    }

    pub fn authenticated_data(self, authenticated_data: Vec<u8>) -> Self {
        Self {
            authenticated_data,
            ..self
        }
    }

    pub fn build(self) -> Result<(MLSMessage, Option<MLSMessage>), GroupError> {
        self.group
            .commit_proposals(self.proposals, self.authenticated_data)
    }
}

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    fn commit_proposals(
        &mut self,
        proposals: Vec<Proposal>,
        authenticated_data: Vec<u8>,
    ) -> Result<(MLSMessage, Option<MLSMessage>), GroupError> {
        self.commit_internal(proposals, None, authenticated_data)
    }

    pub fn commit(
        &mut self,
        authenticated_data: Vec<u8>,
    ) -> Result<(MLSMessage, Option<MLSMessage>), GroupError> {
        self.commit_internal(vec![], None, authenticated_data)
    }

    pub fn commit_builder(&mut self) -> CommitBuilder<C> {
        CommitBuilder {
            group: self,
            proposals: Default::default(),
            authenticated_data: Default::default(),
        }
    }

    /// Returns commit and optional `MLSMessage` containing a `Welcome`
    pub(super) fn commit_internal(
        &mut self,
        proposals: Vec<Proposal>,
        external_leaf: Option<&LeafNode>,
        authenticated_data: Vec<u8>,
    ) -> Result<(MLSMessage, Option<MLSMessage>), GroupError> {
        if self.pending_commit.is_some() {
            return Err(GroupError::ExistingPendingCommit);
        }

        let preferences = self.config.preferences();

        let options = CommitOptions {
            prefer_path_update: preferences.force_commit_path_update,
            encryption_mode: preferences.encryption_mode(),
            ratchet_tree_extension: preferences.ratchet_tree_extension,
        };

        // Construct an initial Commit object with the proposals field populated from Proposals
        // received during the current epoch, and an empty path field. Add passed in proposals
        // by value
        let is_external = external_leaf.is_some();

        let sender = if is_external {
            Sender::NewMemberCommit
        } else {
            Sender::Member(self.private_tree.self_index)
        };

        let signer = match external_leaf {
            Some(leaf_node) => self
                .config
                .keychain()
                .signer(&leaf_node.signing_identity)
                .ok_or(GroupError::NoCredentialFound),
            None => self.signer(),
        }?;

        let (commit_proposals, proposal_effects) = self.state.proposals.prepare_commit(
            sender.clone(),
            proposals,
            &self.context().extensions,
            self.config.credential_validator(),
            &self.state.public_tree,
            external_leaf,
            self.config.secret_store().into_external_id_validator(),
            self.config
                .proposal_filter(ProposalFilterInit::new(sender.clone())),
        )?;

        let mut provisional_state = self.calculate_provisional_state(proposal_effects)?;
        let mut provisional_private_tree = self.provisional_private_tree(&provisional_state)?;

        if is_external {
            provisional_private_tree.self_index = provisional_state
                .external_init
                .ok_or(GroupError::ExternalCommitMissingExternalInit)?
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
            let (update_leaf_properties, signer) = self.current_leaf_properties()?;

            let encap_gen = TreeKem::new(
                &mut provisional_state.public_tree,
                &mut provisional_private_tree,
            )
            .encap(
                &self.context().group_id,
                &mut provisional_group_context,
                &added_leaves
                    .iter()
                    .map(|(_, leaf_index)| *leaf_index)
                    .collect::<Vec<LeafIndex>>(),
                &signer,
                update_leaf_properties,
                self.config.credential_validator(),
                #[cfg(test)]
                &self.commit_modifiers,
            )?;

            (
                Some(encap_gen.update_path),
                Some(encap_gen.path_secrets),
                Some(encap_gen.root_secret),
            )
        } else {
            // Update the tree hash, since it was not updated by encap.
            provisional_state
                .public_tree
                .update_hashes(&mut vec![provisional_private_tree.self_index], &[])?;

            provisional_group_context.tree_hash = provisional_state.public_tree.tree_hash()?;
            (None, None, None)
        };

        let commit_secret =
            CommitSecret::from_root_secret(self.state.cipher_suite(), root_secret.as_ref())?;

        let psk_store = self.config.secret_store();

        let resumption_psk_search = ResumptionPskSearch {
            group_context: self.context(),
            current_epoch: &self.epoch_secrets,
            prior_epochs: &self.state_repo,
        };

        let psk_secret = crate::psk::psk_secret::<C>(
            self.state.cipher_suite(),
            Some(&psk_store),
            Some(resumption_psk_search),
            &provisional_state.psks,
        )?;

        let commit = Commit {
            proposals: commit_proposals,
            path: update_path,
        };

        let mut auth_content = MLSAuthenticatedContent::new_signed(
            self.context(),
            sender,
            Content::Commit(commit),
            &signer,
            options.encryption_mode.into(),
            authenticated_data,
        )?;

        // Use the signature, the commit_secret and the psk_secret to advance the key schedule and
        // compute the confirmation_tag value in the MLSPlaintext.
        let confirmed_transcript_hash = ConfirmedTranscriptHash::create(
            self.state.cipher_suite(),
            &self.state.interim_transcript_hash,
            &auth_content,
        )?;

        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash;

        let mut extensions = ExtensionList::new();

        if options.ratchet_tree_extension {
            let ratchet_tree_ext = RatchetTreeExt {
                tree_data: provisional_state.public_tree.export_node_data(),
            };

            extensions.set_extension(ratchet_tree_ext)?;
        }

        let key_schedule_result = KeySchedule::derive(
            &self.key_schedule,
            &commit_secret,
            &provisional_group_context,
            &self.state.public_tree,
            &psk_secret,
        )?;

        let confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &provisional_group_context.confirmed_transcript_hash,
            &self.state.cipher_suite(),
        )?;

        auth_content.auth.confirmation_tag = Some(confirmation_tag.clone());

        // Construct a GroupInfo reflecting the new state
        // Group ID, epoch, tree, and confirmed transcript hash from the new state
        let mut group_info = GroupInfo {
            group_context: provisional_group_context.clone().into(),
            extensions,
            confirmation_tag, // The confirmation_tag from the MLSPlaintext object
            signer: provisional_private_tree.self_index,
            signature: vec![],
        };

        // Sign the GroupInfo using the member's private signing key
        group_info.sign(&signer, &())?;

        let welcome = self.make_welcome_message(
            added_leaves,
            &key_schedule_result.joiner_secret,
            &psk_secret,
            path_secrets.as_ref(),
            provisional_state.psks,
            &group_info,
        )?;

        let commit_message = self.format_for_wire(auth_content.clone())?;

        let pending_commit = CommitGeneration {
            content: auth_content,
            pending_secrets: root_secret.map(|rs| (provisional_private_tree, rs)),
        };

        self.pending_commit = Some(pending_commit);

        Ok((commit_message, welcome))
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::tree_kem::{leaf_node::LeafNode, TreeKemPublic, UpdatePathNode};
    use core::fmt;

    pub struct CommitModifiers<S> {
        pub modify_leaf: fn(&mut LeafNode, &S),
        pub modify_tree: fn(&mut TreeKemPublic),
        pub modify_path: fn(Vec<UpdatePathNode>) -> Vec<UpdatePathNode>,
    }

    impl<S> fmt::Debug for CommitModifiers<S> {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            write!(fmt, "CommitModifiers")
        }
    }

    impl<S> Copy for CommitModifiers<S> {}

    impl<S> Clone for CommitModifiers<S> {
        fn clone(&self) -> Self {
            *self
        }
    }

    impl<S> Default for CommitModifiers<S> {
        fn default() -> Self {
            Self {
                modify_leaf: |_, _| (),
                modify_tree: |_| (),
                modify_path: |a| a,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        client_config::InMemoryClientConfig,
        credential::test_utils::get_test_basic_credential,
        extension::RequiredCapabilitiesExt,
        group::{
            proposal::PreSharedKey,
            test_utils::{test_group, test_n_member_group},
        },
        key_package::test_utils::test_key_package,
        psk::{JustPreSharedKeyID, PreSharedKeyID, Psk},
        signing_identity::test_utils::get_test_signing_identity,
    };

    use super::*;

    fn test_commit_builder_group() -> Group<InMemoryClientConfig> {
        test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).group
    }

    fn assert_commit_builder_output(
        group: Group<InMemoryClientConfig>,
        commit_message: MLSMessage,
        expected: Vec<Proposal>,
        welcome_message: Option<MLSMessage>,
        welcome_count: usize,
    ) {
        let plaintext = commit_message.into_plaintext().unwrap();

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
                Proposal::Psk(PreSharedKey { psk: PreSharedKeyID { key_id: JustPreSharedKeyID::External(psk_id), .. },}) => Some(psk_id),
                _ => None,
            } {
                let found = expected.iter().any(|item| matches!(item, Proposal::Psk(PreSharedKey { psk: PreSharedKeyID { key_id: JustPreSharedKeyID::External(id), .. }}) if id == psk_id));

                assert!(found)
            } else {
                assert!(expected.contains(&proposal));
            }
        });

        if welcome_count > 0 {
            let welcome_msg = welcome_message.unwrap();

            assert_eq!(
                welcome_msg.version,
                group.state.context.protocol_version.into()
            );

            let welcome_msg = welcome_msg.into_welcome().unwrap();

            assert_eq!(welcome_msg.cipher_suite, group.state.context.cipher_suite);
            assert_eq!(welcome_msg.secrets.len(), welcome_count);
        } else {
            assert!(welcome_message.is_none());
        }
    }

    #[test]
    fn test_commit_builder_add() {
        let mut group = test_commit_builder_group();
        let test_key_package = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "alice");

        let (commit_message, welcome_message) = group
            .commit_builder()
            .add_member(test_key_package.clone())
            .unwrap()
            .build()
            .unwrap();

        let expected_add = group.add_proposal(test_key_package).unwrap();

        assert_commit_builder_output(
            group,
            commit_message,
            vec![expected_add],
            welcome_message,
            1,
        )
    }

    #[test]
    fn test_commit_builder_remove() {
        let mut group = test_commit_builder_group();
        let test_key_package = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "alice");

        group
            .commit_builder()
            .add_member(test_key_package)
            .unwrap()
            .build()
            .unwrap();

        group.apply_pending_commit().unwrap();

        let (commit_message, welcome_message) = group
            .commit_builder()
            .remove_member(1)
            .unwrap()
            .build()
            .unwrap();

        let expected_remove = group.remove_proposal(1).unwrap();

        assert_commit_builder_output(
            group,
            commit_message,
            vec![expected_remove],
            welcome_message,
            0,
        );
    }

    #[test]
    fn test_commit_builder_psk() {
        let mut group = test_commit_builder_group();
        let test_psk = ExternalPskId(vec![1]);

        group
            .config
            .secret_store()
            .insert(test_psk.clone(), Psk::from(vec![]));

        let (commit_message, welcome_message) = group
            .commit_builder()
            .add_psk(test_psk.clone())
            .unwrap()
            .build()
            .unwrap();

        let expected_psk = group.psk_proposal(test_psk).unwrap();

        assert_commit_builder_output(
            group,
            commit_message,
            vec![expected_psk],
            welcome_message,
            0,
        )
    }

    #[test]
    fn test_commit_builder_group_context_ext() {
        let mut group = test_commit_builder_group();
        let mut test_ext = ExtensionList::default();
        test_ext
            .set_extension(RequiredCapabilitiesExt::default())
            .unwrap();

        let (commit_message, welcome_message) = group
            .commit_builder()
            .set_group_context_ext(test_ext.clone())
            .unwrap()
            .build()
            .unwrap();

        let expected_ext = group.group_context_extensions_proposal(test_ext);

        assert_commit_builder_output(
            group,
            commit_message,
            vec![expected_ext],
            welcome_message,
            0,
        );
    }

    #[test]
    fn test_commit_builder_reinit() {
        let mut group = test_commit_builder_group();
        let test_group_id = "foo".as_bytes().to_vec();
        let test_cipher_suite = CipherSuite::Curve25519ChaCha20;
        let test_protocol_version = ProtocolVersion::Mls10;
        let mut test_ext = ExtensionList::default();

        test_ext
            .set_extension(RequiredCapabilitiesExt::default())
            .unwrap();

        let (commit_message, welcome_message) = group
            .commit_builder()
            .reinit(
                Some(test_group_id.clone()),
                test_protocol_version,
                test_cipher_suite,
                test_ext.clone(),
            )
            .unwrap()
            .build()
            .unwrap();

        let expected_reinit = group
            .reinit_proposal(
                Some(test_group_id),
                test_protocol_version,
                test_cipher_suite,
                test_ext,
            )
            .unwrap();

        assert_commit_builder_output(
            group,
            commit_message,
            vec![expected_reinit],
            welcome_message,
            0,
        );
    }

    #[test]
    fn test_commit_builder_chaining() {
        let mut group = test_commit_builder_group();
        let kp1 = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "alice");
        let kp2 = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let expected_adds = vec![
            group.add_proposal(kp1.clone()).unwrap(),
            group.add_proposal(kp2.clone()).unwrap(),
        ];

        let (commit_message, welcome_message) = group
            .commit_builder()
            .add_member(kp1)
            .unwrap()
            .add_member(kp2)
            .unwrap()
            .build()
            .unwrap();

        assert_commit_builder_output(group, commit_message, expected_adds, welcome_message, 2);
    }

    #[test]
    fn test_commit_builder_empty_commit() {
        let mut group = test_commit_builder_group();

        let (commit_message, welcome_message) = group.commit_builder().build().unwrap();

        assert_commit_builder_output(group, commit_message, vec![], welcome_message, 0);
    }

    #[test]
    fn test_commit_builder_authenticated_data() {
        let mut group = test_commit_builder_group();
        let test_data = "test".as_bytes().to_vec();

        let (commit_message, _) = group
            .commit_builder()
            .authenticated_data(test_data.clone())
            .build()
            .unwrap();

        assert_eq!(
            commit_message
                .into_plaintext()
                .unwrap()
                .content
                .authenticated_data,
            test_data
        );
    }

    #[test]
    fn commit_can_change_credential() {
        let cs = CipherSuite::Curve25519Aes128;
        let mut groups = test_n_member_group(ProtocolVersion::Mls10, cs, 3);
        let (identity, secret_key) = get_test_signing_identity(cs, b"member".to_vec());

        groups[0]
            .group
            .config
            .keychain
            .insert(identity.clone(), secret_key);

        groups[0].group.config.keychain.default_identity = Some(identity.clone());
        let (commit, _) = groups[0].group.commit(vec![]).unwrap();

        // Check that the credential was updated by in the committer's state.
        groups[0].process_pending_commit().unwrap();
        let new_member = groups[0].group.roster().next().unwrap();

        assert_eq!(
            new_member.signing_identity().credential,
            get_test_basic_credential(b"member".to_vec())
        );

        assert_eq!(
            new_member.signing_identity().signature_key,
            identity.signature_key
        );

        // Check that the credential was updated in another member's state.
        groups[1].process_message(commit).unwrap();
        let new_member = groups[1].group.roster().next().unwrap();

        assert_eq!(
            new_member.signing_identity().credential,
            get_test_basic_credential(b"member".to_vec())
        );

        assert_eq!(
            new_member.signing_identity().signature_key,
            identity.signature_key
        );
    }
}
