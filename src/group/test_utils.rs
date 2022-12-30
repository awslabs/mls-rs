use rand::RngCore;

use super::*;
use crate::{
    client::test_utils::TEST_CIPHER_SUITE,
    client_builder::{
        test_utils::{TestClientBuilder, TestClientConfig},
        Preferences,
    },
    client_config::ClientConfig,
    extension::RequiredCapabilitiesExt,
    identity::test_utils::get_test_signing_identity,
    key_package::{KeyPackageGeneration, KeyPackageGenerator},
    provider::{crypto::test_utils::test_cipher_suite_provider, identity::BasicIdentityProvider},
    tree_kem::{leaf_node::test_utils::get_test_capabilities, Lifetime},
};

pub const TEST_GROUP: &[u8] = b"group";

pub(crate) struct TestGroup {
    pub group: Group<TestClientConfig>,
}

impl TestGroup {
    pub(crate) fn propose(&mut self, proposal: Proposal) -> MLSMessage {
        self.group.proposal_message(proposal, vec![]).unwrap()
    }

    pub(crate) fn update_proposal(&mut self) -> Proposal {
        self.group.update_proposal(None).unwrap()
    }

    pub(crate) fn join_with_preferences(
        &mut self,
        name: &str,
        preferences: Preferences,
    ) -> (TestGroup, MLSMessage) {
        self.join_with_custom_config(name, |mut config| {
            config.0.settings.preferences = preferences;
            config
        })
        .unwrap()
    }

    pub(crate) fn join_with_custom_config<F>(
        &mut self,
        name: &str,
        config: F,
    ) -> Result<(TestGroup, MLSMessage), GroupError>
    where
        F: FnOnce(TestClientConfig) -> TestClientConfig,
    {
        let (new_key_package, secret_key) = test_member(
            self.group.state.protocol_version(),
            self.group.state.cipher_suite(),
            name.as_bytes(),
        );

        // Add new member to the group
        let commit_output = self
            .group
            .commit_builder()
            .add_member(new_key_package.key_package.clone())
            .unwrap()
            .build()
            .unwrap();

        // Apply the commit to the original group
        self.group.apply_pending_commit().unwrap();

        let client_config = config(
            TestClientBuilder::new_for_test_custom(
                secret_key,
                new_key_package,
                Preferences::default(),
            )
            .build_config(),
        );

        let tree = (!client_config.0.settings.preferences.ratchet_tree_extension)
            .then(|| self.group.export_tree().unwrap());

        // Group from new member's perspective
        let (new_group, _) = Group::join(
            commit_output.welcome_message.unwrap(),
            tree.as_ref().map(Vec::as_ref),
            client_config,
        )?;

        let new_test_group = TestGroup { group: new_group };

        Ok((new_test_group, commit_output.commit_message))
    }

    pub(crate) fn join(&mut self, name: &str) -> (TestGroup, MLSMessage) {
        self.join_with_preferences(name, self.group.config.preferences())
    }

    pub(crate) fn process_pending_commit(&mut self) -> Result<StateUpdate<()>, GroupError> {
        self.group.apply_pending_commit()
    }

    pub(crate) fn process_message(&mut self, message: MLSMessage) -> Result<Event<()>, GroupError> {
        self.group
            .process_incoming_message(message)
            .map(|r| r.event)
    }

    pub(crate) fn make_plaintext(&mut self, content: Content) -> MLSMessage {
        let auth_content = MLSAuthenticatedContent::new_signed(
            &self.group.cipher_suite_provider,
            &self.group.state.context,
            Sender::Member(*self.group.private_tree.self_index),
            content,
            &self.group.signer().unwrap(),
            WireFormat::Plain,
            Vec::new(),
        )
        .unwrap();

        self.group.format_for_wire(auth_content).unwrap()
    }
}

pub(crate) fn get_test_group_context(epoch: u64, cipher_suite: CipherSuite) -> GroupContext {
    GroupContext {
        protocol_version: ProtocolVersion::Mls10,
        cipher_suite,
        group_id: Vec::new(),
        epoch,
        tree_hash: vec![],
        confirmed_transcript_hash: ConfirmedTranscriptHash::from(vec![]),
        extensions: ExtensionList::from(vec![]),
    }
}

pub(crate) fn get_test_group_context_with_id(
    group_id: Vec<u8>,
    epoch: u64,
    cipher_suite: CipherSuite,
) -> GroupContext {
    GroupContext {
        protocol_version: ProtocolVersion::Mls10,
        cipher_suite,
        group_id,
        epoch,
        tree_hash: vec![],
        confirmed_transcript_hash: ConfirmedTranscriptHash::from(vec![]),
        extensions: ExtensionList::from(vec![]),
    }
}

pub(crate) fn group_extensions() -> ExtensionList<GroupContextExtension> {
    let required_capabilities = RequiredCapabilitiesExt::default();

    let mut extensions = ExtensionList::new();
    extensions.set_extension(required_capabilities).unwrap();
    extensions
}

pub(crate) fn lifetime() -> Lifetime {
    Lifetime::years(1).unwrap()
}

pub(crate) fn test_member(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    identifier: &[u8],
) -> (KeyPackageGeneration, SignatureSecretKey) {
    let (signing_identity, signing_key) =
        get_test_signing_identity(cipher_suite, identifier.to_vec());

    let key_package_generator = KeyPackageGenerator {
        protocol_version,
        cipher_suite_provider: &test_cipher_suite_provider(cipher_suite),
        signing_identity: &signing_identity,
        signing_key: &signing_key,
        identity_provider: &BasicIdentityProvider::new(),
    };

    let key_package = key_package_generator
        .generate(
            lifetime(),
            get_test_capabilities(),
            ExtensionList::default(),
            ExtensionList::default(),
        )
        .unwrap();

    (key_package, signing_key)
}

pub(crate) fn test_group_custom(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    capabilities: Option<Capabilities>,
    leaf_extensions: Option<ExtensionList<LeafNodeExtension>>,
    preferences: Option<Preferences>,
) -> TestGroup {
    let capabilities = capabilities.unwrap_or_default();
    let leaf_extensions = leaf_extensions.unwrap_or_default();
    let preferences = preferences.unwrap_or_default();

    let (signing_identity, secret_key) =
        get_test_signing_identity(cipher_suite, b"member".to_vec());

    let group = TestClientBuilder::new_for_test()
        .test_single_signing_identity(signing_identity.clone(), secret_key, cipher_suite)
        .leaf_node_extensions(leaf_extensions)
        .preferences(preferences)
        .extension_types(capabilities.extensions)
        .protocol_versions(
            capabilities
                .protocol_versions
                .into_iter()
                .map(|p| p.into_enum().unwrap()),
        )
        .build()
        .create_group_with_id(
            protocol_version,
            cipher_suite,
            TEST_GROUP.to_vec(),
            signing_identity,
            group_extensions(),
        )
        .unwrap();

    TestGroup { group }
}

pub(crate) fn test_group(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
) -> TestGroup {
    test_group_custom(
        protocol_version,
        cipher_suite,
        None,
        None,
        Some(Preferences::default().with_ratchet_tree_extension(true)),
    )
}

pub(crate) fn test_group_custom_config<F>(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    custom: F,
) -> TestGroup
where
    F: FnOnce(TestClientBuilder) -> TestClientBuilder,
{
    let (signing_identity, secret_key) =
        get_test_signing_identity(cipher_suite, b"member".to_vec());

    let client_builder = TestClientBuilder::new_for_test()
        .signing_identity(signing_identity.clone(), secret_key, cipher_suite)
        .preferences(Preferences::default().with_ratchet_tree_extension(true));

    let group = custom(client_builder)
        .build()
        .create_group_with_id(
            protocol_version,
            cipher_suite,
            TEST_GROUP.to_vec(),
            signing_identity,
            group_extensions(),
        )
        .unwrap();

    TestGroup { group }
}

pub(crate) fn test_n_member_group(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    num_members: usize,
) -> Vec<TestGroup> {
    let group = test_group(protocol_version, cipher_suite);

    let mut groups = vec![group];

    for i in 1..num_members {
        let (new_group, commit) = groups.get_mut(0).unwrap().join(&format!("name {}", i));
        process_commit(&mut groups, commit, 0);
        groups.push(new_group);
    }

    groups
}

pub(crate) fn process_commit(groups: &mut [TestGroup], commit: MLSMessage, excluded: u32) {
    groups
        .iter_mut()
        .filter(|g| g.group.current_member_index() != excluded)
        .for_each(|g| {
            g.process_message(commit.clone()).unwrap();
        });
}

pub(crate) fn get_test_25519_key(key_byte: u8) -> HpkePublicKey {
    vec![key_byte; 32].into()
}

pub(crate) fn get_test_groups_with_features(
    n: usize,
    extensions: ExtensionList<GroupContextExtension>,
    leaf_extensions: ExtensionList<LeafNodeExtension>,
) -> Vec<Group<TestClientConfig>> {
    let clients = (0..n)
        .map(|i| {
            let (identity, secret_key) =
                get_test_signing_identity(TEST_CIPHER_SUITE, format!("member{i}").into_bytes());

            let client = TestClientBuilder::new_for_test()
                .extension_type(999)
                .preferences(Preferences::default().with_ratchet_tree_extension(true))
                .test_single_signing_identity(identity.clone(), secret_key, TEST_CIPHER_SUITE)
                .leaf_node_extensions(leaf_extensions.clone())
                .build();

            (client, identity)
        })
        .collect::<Vec<_>>();

    let group = clients[0]
        .0
        .create_group_with_id(
            ProtocolVersion::Mls10,
            CipherSuite::Curve25519Aes128,
            b"TEST GROUP".to_vec(),
            clients[0].1.clone(),
            extensions,
        )
        .unwrap();

    let mut groups = vec![group];

    clients.iter().skip(1).for_each(|(client, identity)| {
        let key_package = client
            .generate_key_package(
                ProtocolVersion::Mls10,
                CipherSuite::Curve25519Aes128,
                identity.clone(),
            )
            .unwrap();

        let commit_output = groups[0]
            .commit_builder()
            .add_member(key_package)
            .unwrap()
            .build()
            .unwrap();

        groups[0].apply_pending_commit().unwrap();

        for group in groups.iter_mut().skip(1) {
            group
                .process_incoming_message(commit_output.commit_message.clone())
                .unwrap();
        }

        groups.push(
            client
                .join_group(None, commit_output.welcome_message.unwrap())
                .unwrap()
                .0,
        );
    });

    groups
}

pub fn random_bytes(count: usize) -> Vec<u8> {
    let mut buf = vec![0; count];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}
