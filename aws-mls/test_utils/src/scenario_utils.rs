use aws_mls::client_builder::Preferences;
use aws_mls::ExtensionList;
use aws_mls::MLSMessage;
use aws_mls::ProtocolVersion;
use aws_mls::{CipherSuite, Group};
use futures::StreamExt;

use crate::test_client::{generate_client, TestClientConfig};

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct TestCase {
    pub cipher_suite: u16,

    pub external_psks: Vec<TestExternalPsk>,
    #[serde(with = "hex::serde")]
    pub key_package: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub signature_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub encryption_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub init_priv: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub welcome: Vec<u8>,
    pub ratchet_tree: Option<TestRatchetTree>,
    #[serde(with = "hex::serde")]
    pub initial_epoch_authenticator: Vec<u8>,

    pub epochs: Vec<TestEpoch>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct TestExternalPsk {
    #[serde(with = "hex::serde")]
    pub psk_id: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub psk: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct TestEpoch {
    pub proposals: Vec<TestMLSMessage>,
    #[serde(with = "hex::serde")]
    pub commit: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub epoch_authenticator: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct TestMLSMessage(#[serde(with = "hex::serde")] pub Vec<u8>);

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct TestRatchetTree(#[serde(with = "hex::serde")] pub Vec<u8>);

impl TestEpoch {
    pub fn new(
        proposals: Vec<MLSMessage>,
        commit: &MLSMessage,
        epoch_authenticator: Vec<u8>,
    ) -> Self {
        let proposals = proposals
            .into_iter()
            .map(|p| TestMLSMessage(p.to_bytes().unwrap()))
            .collect();

        Self {
            proposals,
            commit: commit.to_bytes().unwrap(),
            epoch_authenticator,
        }
    }
}

pub async fn get_test_groups(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    num_participants: usize,
    preferences: Preferences,
) -> (Group<TestClientConfig>, Vec<Group<TestClientConfig>>) {
    // Create the group with Alice as the group initiator
    let creator = generate_client(cipher_suite, b"alice".to_vec(), preferences.clone());

    let mut creator_group = creator
        .client
        .create_group_with_id(
            protocol_version,
            cipher_suite,
            b"group".to_vec(),
            creator.identity,
            ExtensionList::default(),
        )
        .await
        .unwrap();

    // Generate random clients that will be members of the group
    let receiver_clients = (0..num_participants)
        .map(|i| {
            generate_client(
                cipher_suite,
                format!("bob{i}").into_bytes(),
                preferences.clone(),
            )
        })
        .collect::<Vec<_>>();

    let receiver_keys = futures::stream::iter(&receiver_clients)
        .then(|client| async {
            client
                .client
                .generate_key_package_message(
                    protocol_version,
                    cipher_suite,
                    client.identity.clone(),
                )
                .await
                .unwrap()
        })
        .collect::<Vec<MLSMessage>>()
        .await;

    // Add the generated clients to the group the creator made

    let welcome = futures::stream::iter(&receiver_keys)
        .fold(creator_group.commit_builder(), |builder, item| async move {
            builder.add_member(item.clone()).unwrap()
        })
        .await
        .build()
        .await
        .unwrap()
        .welcome_message;

    // Creator can confirm the commit was processed by the server
    let update = creator_group.apply_pending_commit().await.unwrap();

    assert!(update.is_active());
    assert_eq!(update.new_epoch(), 1);

    assert!(receiver_clients.iter().all(|client| creator_group
        .get_member_with_identity(client.identity.credential.as_basic().unwrap().identifier())
        .is_ok()));

    assert!(update.roster_update().removed().is_empty());

    // Export the tree for receivers
    let tree_data = creator_group.export_tree().unwrap();

    // All the receivers will be able to join the group
    let receiver_groups = futures::stream::iter(&receiver_clients)
        .then(|client| async {
            client
                .client
                .join_group(Some(&tree_data), welcome.clone().unwrap())
                .await
                .unwrap()
                .0
        })
        .collect::<Vec<_>>()
        .await;

    for one_receiver in &receiver_groups {
        assert!(Group::equal_group_state(&creator_group, one_receiver));
    }

    (creator_group, receiver_groups)
}

pub async fn all_process_message(
    groups: &mut [Group<TestClientConfig>],
    message: &MLSMessage,
    sender: usize,
    is_commit: bool,
) {
    futures::stream::iter(groups)
        .for_each(|g| async {
            if sender != g.current_member_index() as usize {
                g.process_incoming_message(message.clone()).await.unwrap();
            } else if is_commit {
                g.apply_pending_commit().await.unwrap();
            }
        })
        .await;
}
