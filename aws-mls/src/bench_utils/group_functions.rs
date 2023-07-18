use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use aws_mls_core::{
    crypto::{CipherSuiteProvider, CryptoProvider, SignatureSecretKey},
    group::GroupStateStorage,
    identity::BasicCredential,
    key_package::KeyPackageData,
    protocol_version::ProtocolVersion,
};

use crate::{
    cipher_suite::CipherSuite,
    client::MlsError,
    client_builder::{
        BaseConfig, Preferences, WithCryptoProvider, WithIdentityProvider, WithKeychain,
    },
    client_config::ClientConfig,
    group::{
        epoch::PriorEpoch,
        framing::{Content, MLSMessage, Sender, WireFormat},
        message_processor::MessageProcessor,
        message_signature::AuthenticatedContent,
        snapshot::Snapshot,
        Commit, Group,
    },
    identity::{basic::BasicIdentityProvider, SigningIdentity},
    storage_provider::in_memory::{
        InMemoryGroupStateStorage, InMemoryKeyPackageStorage, InMemoryKeychainStorage,
    },
    Client, ExtensionList,
};

#[cfg(awslc)]
pub use aws_mls_crypto_awslc::AwsLcCryptoProvider as MlsCryptoProvider;
#[cfg(not(any(awslc, rustcrypto)))]
pub use aws_mls_crypto_openssl::OpensslCryptoProvider as MlsCryptoProvider;
#[cfg(rustcrypto)]
pub use aws_mls_crypto_rustcrypto::RustCryptoProvider as MlsCryptoProvider;

pub type TestClientConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithKeychain<InMemoryKeychainStorage, WithCryptoProvider<MlsCryptoProvider, BaseConfig>>,
>;

pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::MLS_10;

#[derive(Debug, MlsEncode, MlsDecode, MlsSize)]
struct GroupInfo {
    session: Snapshot,
    epochs: Vec<u8>,
    key_packages: Vec<u8>,
    identities: Vec<u8>,
}

#[derive(Debug, MlsEncode, MlsDecode, MlsSize)]
pub struct TestCase {
    info: Vec<GroupInfo>,
}

#[maybe_async::maybe_async]
async fn generate_test_cases(cs: CipherSuite) -> Vec<TestCase> {
    let mut cases = Vec::new();

    for length in [16, 64, 128] {
        cases.push(get_group_states(cs, length).await)
    }

    cases
}

#[maybe_async::async_impl]
async fn load_or_generate(cs: CipherSuite) -> Vec<TestCase> {
    load_test_case_mls!(group_state, generate_test_cases(cs).await, to_vec)
}

#[maybe_async::sync_impl]
fn load_or_generate(cs: CipherSuite) -> Vec<TestCase> {
    load_test_case_mls!(group_state, generate_test_cases(cs), to_vec)
}

#[maybe_async::maybe_async]
pub async fn load_test_cases(cs: CipherSuite) -> Vec<Vec<Group<TestClientConfig>>> {
    let tests: Vec<TestCase> = load_or_generate(cs).await;

    let mut group_collection = Vec::new();

    for test in tests {
        let mut groups = Vec::new();

        for group_info in test.info {
            let key_packages = Vec::<(Vec<u8>, KeyPackageData)>::mls_decode(
                &mut group_info.key_packages.as_slice(),
            )
            .unwrap();

            let kpkg_storage = InMemoryKeyPackageStorage::default();

            for (id, pkg) in key_packages {
                kpkg_storage.insert(id, pkg);
            }

            let identities = Vec::<(SigningIdentity, SignatureSecretKey)>::mls_decode(
                &mut group_info.identities.as_slice(),
            )
            .unwrap();

            let epochs = Vec::<PriorEpoch>::mls_decode(&mut group_info.epochs.as_slice()).unwrap();

            let group_id = group_info.session.group_id().to_vec();

            let mut group_state_storage = InMemoryGroupStateStorage::default();

            group_state_storage
                .write(group_info.session, epochs, Vec::new(), None)
                .await
                .unwrap();

            let mut client = Client::builder()
                .preferences(make_preferences())
                .identity_provider(BasicIdentityProvider)
                .crypto_provider(MlsCryptoProvider::default())
                .group_state_storage(group_state_storage)
                .key_package_repo(kpkg_storage);

            for (identity, signer) in identities {
                client = client.signing_identity(identity, signer, cs);
            }

            let group = client.build().load_group(&group_id).await.unwrap();

            groups.push(group)
        }

        group_collection.push(groups);
    }

    group_collection
}

// creates group modifying code found in client.rs
#[maybe_async::maybe_async]
pub async fn create_group(cipher_suite: CipherSuite, size: usize) -> Vec<Group<TestClientConfig>> {
    let (alice_identity, alice_client) = make_client(cipher_suite, "alice");

    let alice_group = alice_client
        .create_group(
            PROTOCOL_VERSION,
            cipher_suite,
            alice_identity,
            ExtensionList::new(),
        )
        .await
        .unwrap();

    let mut groups = vec![alice_group];

    for n in 0..size - 1 {
        let (committer_group, other_groups) = groups.split_last_mut().unwrap();

        let (new_identity, new_client) = make_client(cipher_suite, &format!("bob{n}"));

        let new_kpkg = new_client
            .generate_key_package_message(PROTOCOL_VERSION, cipher_suite, new_identity)
            .await
            .unwrap();

        let commit_output = committer_group
            .commit_builder()
            .add_member(new_kpkg)
            .unwrap()
            .build()
            .await
            .unwrap();

        committer_group.apply_pending_commit().await.unwrap();

        for group in other_groups {
            group
                .process_incoming_message(commit_output.commit_message.clone())
                .await
                .unwrap();
        }

        let (new_group, _) = new_client
            .join_group(None, commit_output.welcome_message.unwrap())
            .await
            .unwrap();

        groups.push(new_group);
    }

    groups
}

pub fn get_snapshot<C>(group: &Group<C>) -> Result<Vec<u8>, aws_mls_codec::Error>
where
    C: ClientConfig + Clone,
{
    group.snapshot().mls_encode_to_vec()
}

#[maybe_async::maybe_async]
async fn get_group_states(cipher_suite: CipherSuite, size: usize) -> TestCase {
    let groups = create_group(cipher_suite, size).await;

    let mut group_info = Vec::new();

    for mut group in groups {
        group.write_to_storage().await.unwrap();

        let config = &group.config;

        let epoch_repo = config.group_state_storage();
        let mut epoch_id = group.current_epoch();
        let mut exported_epochs = Vec::<PriorEpoch>::new();

        while let Some(epoch) = epoch_repo.epoch(group.group_id(), epoch_id).await.unwrap() {
            exported_epochs.push(epoch);
            epoch_id -= 1;
        }

        let group_state = epoch_repo.state(group.group_id()).await.unwrap().unwrap();

        let epochs = exported_epochs.mls_encode_to_vec().unwrap();

        let key_repo = config.key_package_repo();
        let exported_key_packages = key_repo.key_packages();
        let key_packages = exported_key_packages.mls_encode_to_vec().unwrap();

        let key_chain = config.keychain();
        let exported_key_chain = key_chain.identities();
        let identities = exported_key_chain.mls_encode_to_vec().unwrap();

        let info = GroupInfo {
            session: group_state,
            epochs,
            key_packages,
            identities,
        };

        group_info.push(info)
    }

    TestCase { info: group_info }
}

#[maybe_async::maybe_async]
pub async fn create_fuzz_commit_message<C>(
    group_id: Vec<u8>,
    epoch: u64,
    authenticated_data: Vec<u8>,
    group: &mut Group<C>,
) -> Result<MLSMessage, MlsError>
where
    C: ClientConfig + Clone,
{
    let mut context = group.context().clone();
    context.group_id = group_id;
    context.epoch = epoch;

    #[cfg(feature = "private_message")]
    let wire_format = WireFormat::PrivateMessage;

    #[cfg(not(feature = "private_message"))]
    let wire_format = WireFormat::PublicMessage;

    let auth_content = AuthenticatedContent::new_signed(
        group.cipher_suite_provider(),
        &context,
        Sender::Member(0),
        Content::Commit(alloc::boxed::Box::new(Commit {
            proposals: Vec::new(),
            path: None,
        })),
        &group.signer().await?,
        wire_format,
        authenticated_data,
    )?;

    group.format_for_wire(auth_content)
}

fn make_client(
    cipher_suite: CipherSuite,
    name: &str,
) -> (SigningIdentity, Client<TestClientConfig>) {
    let (secret, signing_identity) = make_identity(cipher_suite, name);

    let client = Client::builder()
        .preferences(make_preferences())
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(MlsCryptoProvider::default())
        .single_signing_identity(signing_identity.clone(), secret, cipher_suite)
        .build();

    (signing_identity, client)
}

pub fn make_identity(
    cipher_suite: CipherSuite,
    name: &str,
) -> (SignatureSecretKey, SigningIdentity) {
    let cipher_suite = MlsCryptoProvider::new()
        .cipher_suite_provider(cipher_suite)
        .unwrap();

    let (secret, public) = cipher_suite.signature_key_generate().unwrap();
    let basic_identity = BasicCredential::new(name.as_bytes().to_vec());
    let signing_identity = SigningIdentity::new(basic_identity.into_credential(), public);

    (secret, signing_identity)
}

fn make_preferences() -> Preferences {
    let mut preferences = Preferences::default();
    preferences = preferences.with_ratchet_tree_extension(true);

    #[cfg(feature = "private_message")]
    {
        preferences = preferences.with_control_encryption(true);
    }

    preferences
}
