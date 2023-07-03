use aws_mls_core::{
    crypto::{CipherSuite, CipherSuiteProvider, CryptoProvider},
    identity::{BasicCredential, Credential, SigningIdentity},
    protocol_version::ProtocolVersion,
    psk::ExternalPskId,
};

use crate::{
    client_builder::{ClientBuilder, MlsConfig, Preferences},
    identity::basic::BasicIdentityProvider,
    Client, Group, MLSMessage,
};

use alloc::{vec, vec::Vec};

pub struct TestClient<C: MlsConfig> {
    pub client: Client<C>,
    pub identity: SigningIdentity,
}

pub fn get_test_basic_credential(identity: Vec<u8>) -> Credential {
    BasicCredential::new(identity).into_credential()
}

pub const TEST_EXT_PSK_ID: &[u8] = b"external psk";

pub fn make_test_ext_psk() -> Vec<u8> {
    b"secret psk key".to_vec()
}

pub fn generate_basic_client<C: CryptoProvider + Clone>(
    cipher_suite: CipherSuite,
    id: usize,
    preferences: &Preferences,
    crypto: &C,
) -> TestClient<impl MlsConfig> {
    let cs = crypto.cipher_suite_provider(cipher_suite).unwrap();

    let (secret_key, public_key) = cs.signature_key_generate().unwrap();
    let credential = get_test_basic_credential(alloc::format!("{id}").into_bytes());

    let identity = SigningIdentity::new(credential, public_key);

    let client = ClientBuilder::new()
        .crypto_provider(crypto.clone())
        .identity_provider(BasicIdentityProvider::new())
        .single_signing_identity(identity.clone(), secret_key, cipher_suite)
        .preferences(preferences.clone())
        .psk(
            ExternalPskId::new(TEST_EXT_PSK_ID.to_vec()),
            make_test_ext_psk().into(),
        )
        .build();

    TestClient { client, identity }
}

#[maybe_async::maybe_async]
pub async fn get_test_groups<C: CryptoProvider + Clone>(
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    num_participants: usize,
    preferences: &Preferences,
    crypto: &C,
) -> Vec<Group<impl MlsConfig>> {
    // Create the group with Alice as the group initiator
    let creator = generate_basic_client(cipher_suite, 0, preferences, crypto);

    let mut creator_group = creator
        .client
        .create_group(version, cipher_suite, creator.identity, Default::default())
        .await
        .unwrap();

    let mut receiver_clients = Vec::new();
    let mut commit_builder = creator_group.commit_builder();

    for i in 1..num_participants {
        let client = generate_basic_client(cipher_suite, i, preferences, crypto);

        let kp = client
            .client
            .generate_key_package_message(version, cipher_suite, client.identity.clone())
            .await
            .unwrap();

        receiver_clients.push(client);
        commit_builder = commit_builder.add_member(kp.clone()).unwrap();
    }

    let welcome = commit_builder.build().await.unwrap().welcome_message;

    creator_group.apply_pending_commit().await.unwrap();

    let tree_data = creator_group.export_tree().unwrap();

    let mut groups = vec![creator_group];

    for client in &receiver_clients {
        let (test_client, _info) = client
            .client
            .join_group(Some(&tree_data), welcome.clone().unwrap())
            .await
            .unwrap();

        groups.push(test_client);
    }

    groups
}

#[maybe_async::maybe_async]
pub async fn all_process_message<C: MlsConfig>(
    groups: &mut [Group<C>],
    message: &MLSMessage,
    sender: usize,
    is_commit: bool,
) {
    for group in groups {
        if sender != group.current_member_index() as usize {
            group
                .process_incoming_message(message.clone())
                .await
                .unwrap();
        } else if is_commit {
            group.apply_pending_commit().await.unwrap();
        }
    }
}
