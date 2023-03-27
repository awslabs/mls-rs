use aws_mls::client_builder::Preferences;
use aws_mls::group::{ReceivedMessage, StateUpdate};
use aws_mls::{CipherSuite, ExtensionList, Group, MLSMessage, ProtocolVersion};
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
) -> Vec<Group<TestClientConfig>> {
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
    let receiver_clients = (0..num_participants - 1)
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
    let commit_description = creator_group.apply_pending_commit().await.unwrap();

    assert!(commit_description.state_update.is_active());
    assert_eq!(commit_description.state_update.new_epoch(), 1);

    assert!(receiver_clients.iter().all(|client| creator_group
        .member_with_identity(client.identity.credential.as_basic().unwrap().identifier())
        .is_ok()));

    assert!(commit_description
        .state_update
        .roster_update()
        .removed()
        .is_empty());

    // Export the tree for receivers
    let tree_data = creator_group.export_tree().unwrap();

    // All the receivers will be able to join the group
    let mut receiver_groups = futures::stream::iter(&receiver_clients)
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

    receiver_groups.insert(0, creator_group);

    receiver_groups
}

pub async fn all_process_commit_with_update(
    groups: &mut [Group<TestClientConfig>],
    commit: &MLSMessage,
    sender: usize,
) -> Vec<StateUpdate> {
    let updates = groups.iter_mut().map(|g| async {
        if sender != g.current_member_index() as usize {
            let processed_msg = g.process_incoming_message(commit.clone()).await.unwrap();

            match processed_msg {
                ReceivedMessage::Commit(update) => update.state_update,
                _ => panic!("Expected commit, got {processed_msg:?}"),
            }
        } else {
            g.apply_pending_commit().await.unwrap().state_update
        }
    });

    futures::future::join_all(updates).await
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

pub async fn add_random_members(
    first_id: usize,
    num_added: usize,
    committer: usize,
    groups: &mut Vec<Group<TestClientConfig>>,
    test_case: Option<&mut TestCase>,
) {
    let cipher_suite = groups[committer].cipher_suite();
    let committer_index = groups[committer].current_member_index() as usize;

    let (key_packages, new_clients): (Vec<_>, Vec<_>) = futures::stream::iter(0..num_added)
        .then(|i| {
            let preferences = Preferences::default();
            async move {
                let id = first_id + i;
                let new_client =
                    generate_client(cipher_suite, format!("dave-{id}").into(), preferences);

                let key_package = new_client
                    .client
                    .generate_key_package_message(
                        ProtocolVersion::MLS_10,
                        cipher_suite,
                        new_client.identity.clone(),
                    )
                    .await
                    .unwrap();

                (key_package, new_client)
            }
        })
        .unzip()
        .await;

    let add_proposals: Vec<MLSMessage> = futures::stream::iter(key_packages)
        .fold(
            (&mut groups[committer], Vec::new()),
            |(group, mut acc), kp| async {
                acc.push(group.propose_add(kp, vec![]).await.unwrap());
                (group, acc)
            },
        )
        .await
        .1;

    for p in &add_proposals {
        all_process_message(groups, p, committer_index, false).await;
    }

    let commit_output = groups[committer].commit(vec![]).await.unwrap();

    all_process_message(groups, &commit_output.commit_message, committer_index, true).await;

    let auth = groups[committer].epoch_authenticator().unwrap().to_vec();
    let epoch = TestEpoch::new(add_proposals, &commit_output.commit_message, auth);

    if let Some(tc) = test_case {
        tc.epochs.push(epoch)
    };

    let tree_data = groups[committer].export_tree().unwrap();

    let mut new_groups: Vec<Group<TestClientConfig>> = futures::stream::iter(&new_clients)
        .then(|client| {
            let tree_data = tree_data.clone();
            let commit = commit_output.welcome_message.clone().unwrap();

            async move {
                client
                    .client
                    .join_group(Some(&tree_data.clone()), commit)
                    .await
                    .unwrap()
                    .0
            }
        })
        .collect()
        .await;

    groups.append(&mut new_groups);
}

pub async fn remove_members(
    removed_members: Vec<usize>,
    committer: usize,
    groups: &mut Vec<Group<TestClientConfig>>,
    test_case: Option<&mut TestCase>,
) {
    let remove_indexes = removed_members
        .iter()
        .map(|removed| groups[*removed].current_member_index())
        .collect::<Vec<u32>>();

    let commit_builder = futures::stream::iter(remove_indexes)
        .fold(
            groups[committer].commit_builder(),
            |builder, index| async move { builder.remove_member(index).unwrap() },
        )
        .await;

    let commit = commit_builder.build().await.unwrap().commit_message;
    let committer_index = groups[committer].current_member_index() as usize;
    all_process_message(groups, &commit, committer_index, true).await;

    let auth = groups[committer].epoch_authenticator().unwrap().to_vec();
    let epoch = TestEpoch::new(vec![], &commit, auth);

    if let Some(tc) = test_case {
        tc.epochs.push(epoch)
    };

    let mut index = 0;

    groups.retain(|_| {
        index += 1;
        !(removed_members.contains(&(index - 1)))
    });
}
