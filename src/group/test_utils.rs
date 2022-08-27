use ferriscrypt::asym::ec_key::{self, SecretKey};

use super::*;
use crate::{
    client_config::{test_utils::test_config, InMemoryClientConfig, Preferences},
    credential::{CredentialType, PassthroughCredentialValidator},
    extension::RequiredCapabilitiesExt,
    key_package::{KeyPackageGeneration, KeyPackageGenerator},
    signing_identity::test_utils::get_test_signing_identity,
    tree_kem::Lifetime,
};

pub const TEST_GROUP: &[u8] = b"group";

#[derive(Debug)]
pub(crate) struct TestGroup {
    pub group: Group<InMemoryClientConfig>,
}

impl TestGroup {
    pub(crate) fn propose(&mut self, proposal: Proposal) -> MLSMessage {
        self.group.proposal_message(proposal, vec![]).unwrap()
    }

    pub(crate) fn join_with_preferences(
        &mut self,
        name: &str,
        preferences: Preferences,
    ) -> (TestGroup, MLSMessage) {
        self.join_with_custom_config(name, |config| config.with_preferences(preferences))
            .unwrap()
    }

    pub(crate) fn join_with_custom_config<F>(
        &mut self,
        name: &str,
        config: F,
    ) -> Result<(TestGroup, MLSMessage), GroupError>
    where
        F: FnOnce(InMemoryClientConfig) -> InMemoryClientConfig,
    {
        let (new_key_package, secret_key) = test_member(
            self.group.state.protocol_version(),
            self.group.state.cipher_suite(),
            name.as_bytes(),
        );

        // Add new member to the group
        let (commit, welcome) = self
            .group
            .commit_builder()
            .add_member(new_key_package.key_package.clone())
            .unwrap()
            .build()
            .unwrap();

        // Apply the commit to the original group
        self.group.apply_pending_commit().unwrap();

        let config = config(test_config(
            secret_key,
            new_key_package,
            Preferences::default(),
        ));

        let tree = (!config.preferences().ratchet_tree_extension)
            .then(|| self.group.export_tree().unwrap());

        // Group from new member's perspective
        let new_group = Group::join(welcome.unwrap(), tree.as_ref().map(Vec::as_ref), config)?;

        let new_test_group = TestGroup { group: new_group };

        Ok((new_test_group, commit))
    }

    pub(crate) fn join(&mut self, name: &str) -> (TestGroup, MLSMessage) {
        self.join_with_preferences(name, self.group.config.preferences())
    }

    pub(crate) fn process_pending_commit(&mut self) -> Result<StateUpdate, GroupError> {
        self.group.apply_pending_commit()
    }

    pub(crate) fn process_message(&mut self, message: MLSMessage) -> Result<Event, GroupError> {
        self.group
            .process_incoming_message(message)
            .map(|r| r.event)
    }

    pub(crate) fn make_plaintext(&mut self, content: Content) -> MLSMessage {
        let auth_content = MLSAuthenticatedContent::new_signed(
            &self.group.state.context,
            Sender::Member(self.group.private_tree.self_index),
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
        group_id: vec![],
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
) -> (KeyPackageGeneration, SecretKey) {
    let (signing_identity, signing_key) =
        get_test_signing_identity(cipher_suite, identifier.to_vec());

    let key_package_generator = KeyPackageGenerator {
        protocol_version,
        cipher_suite,
        signing_identity: &signing_identity,
        signing_key: &signing_key,
        credential_validator: &PassthroughCredentialValidator::new(),
    };

    let key_package = key_package_generator
        .generate(
            lifetime(),
            Capabilities::default(),
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

    let mut config = InMemoryClientConfig::default()
        .with_signing_identity(signing_identity, secret_key)
        .with_leaf_node_extensions(leaf_extensions)
        .with_credential_types(capabilities.credentials)
        .with_preferences(preferences);

    config.cipher_suites = capabilities
        .cipher_suites
        .into_iter()
        .map(|cs| cs.into_enum().unwrap())
        .collect();

    config.supported_extensions = capabilities.extensions;

    config.protocol_versions = capabilities
        .protocol_versions
        .into_iter()
        .map(|p| p.into_enum().unwrap())
        .collect();

    let group = Group::new(
        config,
        TEST_GROUP.to_vec(),
        cipher_suite,
        protocol_version,
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
    F: FnOnce(InMemoryClientConfig) -> InMemoryClientConfig,
{
    let (signing_identity, secret_key) =
        get_test_signing_identity(cipher_suite, b"member".to_vec());

    let config = InMemoryClientConfig::default()
        .with_signing_identity(signing_identity, secret_key)
        .with_preferences(Preferences::default().with_ratchet_tree_extension(true));

    let config = custom(config);

    let group = Group::new(
        config,
        TEST_GROUP.to_vec(),
        cipher_suite,
        protocol_version,
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

    let mut groups: Vec<TestGroup> = vec![group];

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
    ec_key::PublicKey::from_uncompressed_bytes(&[key_byte; 32], ec_key::Curve::Ed25519)
        .unwrap()
        .try_into()
        .unwrap()
}

pub(crate) fn get_test_groups_with_features(
    n: usize,
    extensions: ExtensionList<GroupContextExtension>,
    leaf_extensions: ExtensionList<LeafNodeExtension>,
    credentials: Option<Vec<CredentialType>>,
) -> Vec<Group<InMemoryClientConfig>> {
    let clients = (0..n)
        .map(|i| {
            let (identity, secret_key) = get_test_signing_identity(
                CipherSuite::Curve25519Aes128,
                format!("member{i}").into_bytes(),
            );

            InMemoryClientConfig::default()
                .with_supported_extension(999)
                .with_preferences(Preferences::default().with_ratchet_tree_extension(true))
                .with_credential_types(credentials.clone().unwrap_or_else(|| vec![1, 2]))
                .with_signing_identity(identity, secret_key)
                .with_leaf_node_extensions(leaf_extensions.clone())
                .build_client()
        })
        .collect::<Vec<_>>();

    let group = clients[0]
        .create_group(
            ProtocolVersion::Mls10,
            CipherSuite::Curve25519Aes128,
            extensions,
        )
        .unwrap();

    let mut groups = vec![group];

    clients.iter().skip(1).for_each(|client| {
        let key_package = client
            .generate_key_package(ProtocolVersion::Mls10, CipherSuite::Curve25519Aes128)
            .unwrap();

        let (commit, welcome) = groups[0]
            .commit_builder()
            .add_member(key_package)
            .unwrap()
            .build()
            .unwrap();

        groups[0].apply_pending_commit().unwrap();

        for group in groups.iter_mut().skip(1) {
            group.process_incoming_message(commit.clone()).unwrap();
        }

        groups.push(client.join_group(None, welcome.unwrap()).unwrap());
    });

    groups
}
