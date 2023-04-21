use assert_matches::assert_matches;
use aws_mls::client_builder::{ClientBuilder, Preferences};
use aws_mls::error::MlsError;
use aws_mls::group::proposal::Proposal;
use aws_mls::group::ReceivedMessage;
use aws_mls::identity::basic::BasicIdentityProvider;
use aws_mls::identity::SigningIdentity;
use aws_mls::storage_provider::in_memory::InMemoryKeychainStorage;
use aws_mls::ExtensionList;
use aws_mls::ProtocolVersion;
use aws_mls::{CipherSuite, Group};
use aws_mls::{Client, CryptoProvider};
use aws_mls_core::crypto::CipherSuiteProvider;
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        pub use aws_mls_crypto_rustcrypto::RustCryptoProvider as TestCryptoProvider;
    } else {
        pub use aws_mls_crypto_openssl::OpensslCryptoProvider as TestCryptoProvider;
    }
}

use futures::{Future, StreamExt};
use rand::RngCore;
use rand::{prelude::IteratorRandom, prelude::SliceRandom, Rng, SeedableRng};

use test_utils::scenario_utils::{
    add_random_members, all_process_commit_with_update, all_process_message, get_test_groups,
    remove_members,
};
use test_utils::test_client::{generate_client, get_test_basic_credential, TestClientConfig};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

#[cfg(not(target_arch = "wasm32"))]
use futures_test::test;

#[cfg(feature = "private_message")]
async fn test_on_all_params<F, Fut>(test: F)
where
    F: Fn(ProtocolVersion, CipherSuite, usize, Preferences) -> Fut,
    Fut: Future<Output = ()>,
{
    for version in ProtocolVersion::all() {
        for cs in TestCryptoProvider::all_supported_cipher_suites() {
            for encrypt_controls in [true, false] {
                let preferences = Preferences::default().with_control_encryption(encrypt_controls);

                test(version, cs, 10, preferences).await;
            }
        }
    }
}

#[cfg(not(feature = "private_message"))]
async fn test_on_all_params<F, Fut>(test: F)
where
    F: Fn(ProtocolVersion, CipherSuite, usize, Preferences) -> Fut,
    Fut: Future<Output = ()>,
{
    test_on_all_params_plaintext(test).await;
}

async fn test_on_all_params_plaintext<F, Fut>(test: F)
where
    F: Fn(ProtocolVersion, CipherSuite, usize, Preferences) -> Fut,
    Fut: Future<Output = ()>,
{
    for version in ProtocolVersion::all() {
        for cs in TestCryptoProvider::all_supported_cipher_suites() {
            test(version, cs, 10, Preferences::default()).await;
        }
    }
}

async fn test_create(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    _n_participants: usize,
    preferences: Preferences,
) {
    println!(
        "Testing group creation for cipher suite: {protocol_version:?} {cipher_suite:?}, participants: 1, {preferences:?}"
    );

    let alice = generate_client(cipher_suite, b"alice".to_vec(), preferences.clone());
    let bob = generate_client(cipher_suite, b"bob".to_vec(), preferences);

    let bob_key_pkg = bob
        .client
        .generate_key_package_message(protocol_version, cipher_suite, bob.identity)
        .await
        .unwrap();

    // Alice creates a group and adds bob
    let mut alice_group = alice
        .client
        .create_group_with_id(
            protocol_version,
            cipher_suite,
            b"group".to_vec(),
            alice.identity,
            ExtensionList::default(),
        )
        .await
        .unwrap();

    let welcome = alice_group
        .commit_builder()
        .add_member(bob_key_pkg)
        .unwrap()
        .build()
        .await
        .unwrap()
        .welcome_message;

    // Upon server confirmation, alice applies the commit to her own state
    alice_group.apply_pending_commit().await.unwrap();

    let tree = alice_group.export_tree().unwrap();

    // Bob receives the welcome message and joins the group
    let (bob_group, _) = bob
        .client
        .join_group(Some(&tree), welcome.unwrap())
        .await
        .unwrap();

    assert!(Group::equal_group_state(&alice_group, &bob_group));
}

#[test]
async fn test_create_group() {
    test_on_all_params(test_create).await;
}

#[test]
async fn test_many_commits() {
    let cipher_suite = CipherSuite::CURVE25519_AES128;
    let preferences = Preferences::default();

    let mut groups = get_test_groups(
        ProtocolVersion::MLS_10,
        cipher_suite,
        11,
        preferences.clone(),
    )
    .await;

    let seed: <rand::rngs::StdRng as SeedableRng>::Seed = rand::random();
    let mut rng = rand::rngs::StdRng::from_seed(seed);
    println!("testing random commits for seed {}", hex::encode(seed));

    let mut random_member_first_index = 0;
    for i in 0..100 {
        println!("running step {i}");
        let num_removed = rng.gen_range(0..groups.len());
        let mut members = (0..groups.len()).choose_multiple(&mut rng, num_removed + 1);
        let sender = members.pop().unwrap();
        remove_members(members, sender, &mut groups, None).await;

        let num_added = rng.gen_range(2..12);
        let sender = rng.gen_range(0..groups.len());

        add_random_members(
            random_member_first_index,
            num_added,
            sender,
            &mut groups,
            None,
        )
        .await;

        random_member_first_index += num_added;
    }
}

async fn test_empty_commits(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    preferences: Preferences,
) {
    println!(
        "Testing empty commits for cipher suite: {cipher_suite:?}, participants: {participants}, {preferences:?}",
    );

    let mut groups =
        get_test_groups(protocol_version, cipher_suite, participants, preferences).await;

    // Loop through each participant and send a path update

    for i in 0..groups.len() {
        // Create the commit
        let commit_output = groups[i].commit(vec![]).await.unwrap();

        assert!(commit_output.welcome_message.is_none());

        let index = groups[i].current_member_index() as usize;
        all_process_message(&mut groups, &commit_output.commit_message, index, true).await;

        for other_group in groups.iter() {
            assert!(Group::equal_group_state(other_group, &groups[i]));
        }
    }
}

#[test]
async fn test_group_path_updates() {
    test_on_all_params(test_empty_commits).await;
}

async fn test_update_proposals(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    preferences: Preferences,
) {
    println!(
        "Testing update proposals for cipher suite: {cipher_suite:?}, participants: {participants}, {preferences:?}",
    );

    let mut groups =
        get_test_groups(protocol_version, cipher_suite, participants, preferences).await;

    // Create an update from the ith member, have the ith + 1 member commit it
    for i in 0..groups.len() - 1 {
        let update_proposal_msg = groups[i].propose_update(vec![]).await.unwrap();

        let sender = groups[i].current_member_index() as usize;
        all_process_message(&mut groups, &update_proposal_msg, sender, false).await;

        // Everyone receives the commit
        let committer_index = i + 1;

        let commit_output = groups[committer_index].commit(vec![]).await.unwrap();

        assert!(commit_output.welcome_message.is_none());

        let commit = commit_output.commit_message();

        #[cfg(not(feature = "state_update"))]
        all_process_commit_with_update(&mut groups, commit, committer_index).await;

        #[cfg(feature = "state_update")]
        for update in all_process_commit_with_update(&mut groups, commit, committer_index).await {
            assert!(update.is_active());
            assert_eq!(update.new_epoch(), (i as u64) + 2);
            assert!(update.roster_update().added().is_empty());
            assert!(update.roster_update().removed().is_empty());
        }

        groups
            .iter()
            .for_each(|g| assert!(Group::equal_group_state(g, &groups[0])));
    }
}

#[test]
async fn test_group_update_proposals() {
    test_on_all_params(test_update_proposals).await;
}

async fn test_remove_proposals(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    preferences: Preferences,
) {
    println!(
        "Testing remove proposals for cipher suite: {cipher_suite:?}, participants: {participants}, {preferences:?}",
    );

    let mut groups =
        get_test_groups(protocol_version, cipher_suite, participants, preferences).await;

    // Remove people from the group one at a time
    while groups.len() > 1 {
        let removed_and_committer = (0..groups.len()).choose_multiple(&mut rand::thread_rng(), 2);

        let to_remove = removed_and_committer[0];
        let committer = removed_and_committer[1];
        let to_remove_index = groups[to_remove].current_member_index();

        let epoch_before_remove = groups[committer].current_epoch();

        let commit_output = groups[committer]
            .commit_builder()
            .remove_member(to_remove_index)
            .unwrap()
            .build()
            .await
            .unwrap();

        assert!(commit_output.welcome_message.is_none());

        let commit = commit_output.commit_message();
        let committer_index = groups[committer].current_member_index() as usize;
        all_process_message(&mut groups, commit, committer_index, true).await;

        // Check that remove was effective
        for (i, group) in groups.iter().enumerate() {
            if i == to_remove {
                assert_eq!(group.current_epoch(), epoch_before_remove);
            } else {
                assert_eq!(group.current_epoch(), epoch_before_remove + 1);

                assert!(group
                    .roster()
                    .iter()
                    .all(|member| member.index() != to_remove_index));
            }
        }

        groups.retain(|group| group.current_member_index() != to_remove_index);

        for one_group in groups.iter() {
            assert!(Group::equal_group_state(one_group, &groups[0]))
        }
    }
}

#[test]
async fn test_group_remove_proposals() {
    test_on_all_params(test_remove_proposals).await;
}

#[cfg(feature = "private_message")]
async fn test_application_messages(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    preferences: Preferences,
) {
    let message_count = 20;

    let mut groups =
        get_test_groups(protocol_version, cipher_suite, participants, preferences).await;

    // Loop through each participant and send application messages
    for i in 0..groups.len() {
        let mut test_message = vec![0; 1024];
        rand::thread_rng().fill_bytes(&mut test_message);

        for _ in 0..message_count {
            // Encrypt the application message
            let ciphertext = groups[i]
                .encrypt_application_message(&test_message, vec![])
                .await
                .unwrap();

            let sender_index = groups[i].current_member_index();

            for g in groups.iter_mut() {
                if g.current_member_index() != sender_index {
                    let decrypted = g
                        .process_incoming_message(ciphertext.clone())
                        .await
                        .unwrap();

                    assert_matches!(decrypted, ReceivedMessage::ApplicationMessage(m) if m.data() == test_message);
                }
            }
        }
    }
}

#[cfg(feature = "private_message")]
#[test]
async fn test_out_of_order_application_messages() {
    let mut groups = get_test_groups(
        ProtocolVersion::MLS_10,
        CipherSuite::CURVE25519_AES128,
        2,
        Preferences::default(),
    )
    .await;

    let mut alice_group = groups[0].clone();
    let bob_group = &mut groups[1];

    let mut ciphertexts = vec![alice_group
        .encrypt_application_message(&[0], vec![])
        .await
        .unwrap()];

    ciphertexts.push(
        alice_group
            .encrypt_application_message(&[1], vec![])
            .await
            .unwrap(),
    );

    let commit = alice_group.commit(vec![]).await.unwrap().commit_message;

    alice_group.apply_pending_commit().await.unwrap();

    bob_group.process_incoming_message(commit).await.unwrap();

    ciphertexts.push(
        alice_group
            .encrypt_application_message(&[2], vec![])
            .await
            .unwrap(),
    );

    ciphertexts.push(
        alice_group
            .encrypt_application_message(&[3], vec![])
            .await
            .unwrap(),
    );

    for i in [3, 2, 1, 0] {
        assert_matches!(
            bob_group.process_incoming_message(ciphertexts[i].clone()).await.unwrap(),
            ReceivedMessage::ApplicationMessage(m) if m.data() == [i as u8]
        );
    }
}

#[cfg(feature = "private_message")]
#[test]
async fn test_group_application_messages() {
    test_on_all_params(test_application_messages).await
}

async fn processing_message_from_self_returns_error(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    _n_participants: usize,
    preferences: Preferences,
) {
    println!(
        "Verifying that processing one's own message returns an error for cipher suite: {cipher_suite:?}, {preferences:?}",
    );

    let mut creator_group = get_test_groups(protocol_version, cipher_suite, 1, preferences).await;
    let creator_group = &mut creator_group[0];

    let commit = creator_group
        .commit(Vec::new())
        .await
        .unwrap()
        .commit_message;

    let error = creator_group
        .process_incoming_message(commit)
        .await
        .unwrap_err();

    assert_matches!(error, MlsError::CantProcessMessageFromSelf);
}

#[test]
async fn test_processing_message_from_self_returns_error() {
    test_on_all_params(processing_message_from_self_returns_error).await;
}

#[cfg(feature = "external_commit")]
async fn external_commits_work(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    _n_participants: usize,
    preferences: Preferences,
) {
    let creator = generate_client(cipher_suite, b"alice-0".to_vec(), preferences);

    let creator_group = creator
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

    const PARTICIPANT_COUNT: usize = 10;

    let others = (1..PARTICIPANT_COUNT)
        .map(|i| {
            generate_client(
                cipher_suite,
                format!("alice-{i}").into_bytes(),
                Default::default(),
            )
        })
        .collect::<Vec<_>>();

    let mut groups = futures::stream::iter(&others)
        .fold(vec![creator_group], |mut groups, client| async move {
            let existing_group = groups.choose_mut(&mut rand::thread_rng()).unwrap();

            let group_info = existing_group
                .group_info_message_allowing_ext_commit()
                .await
                .unwrap();

            let (new_group, commit) = client
                .client
                .external_commit_builder(client.identity.clone())
                .with_tree_data(existing_group.export_tree().unwrap())
                .build(group_info)
                .await
                .unwrap();

            for group in groups.iter_mut() {
                group
                    .process_incoming_message(commit.clone())
                    .await
                    .unwrap();
            }

            groups.push(new_group);
            groups
        })
        .await;

    assert!(groups
        .iter()
        .all(|group| group.roster().len() == PARTICIPANT_COUNT));

    for i in 0..groups.len() {
        let message = groups[i].propose_remove(0, Vec::new()).await.unwrap();

        for (_, group) in groups.iter_mut().enumerate().filter(|&(j, _)| i != j) {
            let processed = group
                .process_incoming_message(message.clone())
                .await
                .unwrap();

            if let ReceivedMessage::Proposal(p) = &processed {
                if let Proposal::Remove(r) = &p.proposal {
                    if r.to_remove() == 0 {
                        continue;
                    }
                }
            }

            panic!("expected a proposal, got {processed:?}");
        }
    }
}

#[cfg(feature = "external_commit")]
#[test]
async fn test_external_commits() {
    test_on_all_params_plaintext(external_commits_work).await
}

#[test]
async fn test_remove_nonexisting_leaf() {
    let mut groups = get_test_groups(
        ProtocolVersion::MLS_10,
        CipherSuite::CURVE25519_AES128,
        10,
        Preferences::default(),
    )
    .await;

    groups[0].propose_remove(5, vec![]).await.unwrap();

    // Leaf index out of bounds
    assert!(groups[0].propose_remove(13, vec![]).await.is_err());

    groups[0].commit(vec![]).await.unwrap();
    groups[0].apply_pending_commit().await.unwrap();

    // Removing blank leaf causes error
    assert!(groups[0].propose_remove(5, vec![]).await.is_err());
}

struct ReinitClientGeneration {
    client: Client<TestClientConfig>,
    id1: SigningIdentity,
    id2: SigningIdentity,
}

fn get_reinit_client(suite1: CipherSuite, suite2: CipherSuite, id: &str) -> ReinitClientGeneration {
    let credential = get_test_basic_credential(id.as_bytes().to_vec());

    let csp1 = TestCryptoProvider::new()
        .cipher_suite_provider(suite1)
        .unwrap();

    let csp2 = TestCryptoProvider::new()
        .cipher_suite_provider(suite2)
        .unwrap();

    let (sk1, pk1) = csp1.signature_key_generate().unwrap();
    let (sk2, pk2) = csp2.signature_key_generate().unwrap();

    let id1 = SigningIdentity::new(credential.clone(), pk1);
    let id2 = SigningIdentity::new(credential, pk2);

    let client = ClientBuilder::new()
        .crypto_provider(TestCryptoProvider::default())
        .identity_provider(BasicIdentityProvider::new())
        .keychain(InMemoryKeychainStorage::default())
        .signing_identity(id1.clone(), sk1, suite1)
        .signing_identity(id2.clone(), sk2, suite2)
        .build();

    ReinitClientGeneration { client, id1, id2 }
}

#[test]
async fn reinit_works() {
    let suite1 = CipherSuite::CURVE25519_AES128;
    let suite2 = CipherSuite::P256_AES128;
    let version = ProtocolVersion::MLS_10;

    // Create a group with 2 parties
    let alice = get_reinit_client(suite1, suite2, "alice");
    let bob = get_reinit_client(suite1, suite2, "bob");

    let mut alice_group = alice
        .client
        .create_group(version, suite1, alice.id1.clone(), ExtensionList::new())
        .await
        .unwrap();

    let kp = bob
        .client
        .generate_key_package_message(version, suite1, bob.id1)
        .await
        .unwrap();

    let welcome = alice_group
        .commit_builder()
        .add_member(kp)
        .unwrap()
        .build()
        .await
        .unwrap()
        .welcome_message;

    alice_group.apply_pending_commit().await.unwrap();
    let tree = alice_group.export_tree().unwrap();

    let (mut bob_group, _) = bob
        .client
        .join_group(Some(&tree), welcome.unwrap())
        .await
        .unwrap();

    // Alice proposes reinit
    let reinit_proposal_message = alice_group
        .propose_reinit(
            None,
            ProtocolVersion::MLS_10,
            suite2,
            ExtensionList::default(),
            vec![],
        )
        .await
        .unwrap();

    // Bob commits the reinit
    bob_group
        .process_incoming_message(reinit_proposal_message)
        .await
        .unwrap();

    let commit = bob_group.commit(vec![]).await.unwrap().commit_message;

    // Both process Bob's commit

    #[cfg(feature = "state_update")]
    {
        let state_update = bob_group.apply_pending_commit().await.unwrap().state_update;
        assert!(!state_update.is_active() && state_update.is_pending_reinit());
    }

    #[cfg(not(feature = "state_update"))]
    bob_group.apply_pending_commit().await.unwrap();

    let message = alice_group.process_incoming_message(commit).await.unwrap();

    #[cfg(feature = "state_update")]
    if let ReceivedMessage::Commit(commit_description) = message {
        assert!(
            !commit_description.state_update.is_active()
                && commit_description.state_update.is_pending_reinit()
        );
    }

    #[cfg(not(feature = "state_update"))]
    assert_matches!(message, ReceivedMessage::Commit(_));

    // They can't create new epochs anymore
    assert!(alice_group.commit(vec![]).await.is_err());

    assert!(bob_group.commit(vec![]).await.is_err());

    // Alice finishes the reinit by creating the new group
    let kp = bob
        .client
        .generate_key_package_message(version, suite2, bob.id2)
        .await
        .unwrap();

    let (mut alice_group, welcome) = alice_group
        .finish_reinit_commit(vec![kp], Some(alice.id2), None)
        .await
        .unwrap();

    // Alice invited Bob
    let welcome = welcome.unwrap();
    let tree = alice_group.export_tree().unwrap();

    let (mut bob_group, _) = bob_group
        .finish_reinit_join(welcome, Some(&tree))
        .await
        .unwrap();

    // They can talk
    let carol = get_reinit_client(suite1, suite2, "carol");

    let kp = carol
        .client
        .generate_key_package_message(version, suite2, carol.id2)
        .await
        .unwrap();

    let commit_output = alice_group
        .commit_builder()
        .add_member(kp)
        .unwrap()
        .build()
        .await
        .unwrap();

    alice_group.apply_pending_commit().await.unwrap();

    bob_group
        .process_incoming_message(commit_output.commit_message)
        .await
        .unwrap();

    let tree = alice_group.export_tree().unwrap();

    carol
        .client
        .join_group(Some(&tree), commit_output.welcome_message.unwrap())
        .await
        .unwrap();
}

#[cfg(feature = "external_commit")]
#[test]
async fn external_joiner_can_process_siblings_update() {
    let mut groups = get_test_groups(
        ProtocolVersion::MLS_10,
        CipherSuite::P256_AES128,
        3,
        Preferences::default().with_ratchet_tree_extension(true),
    )
    .await;

    // Remove leaf 1 s.t. the external joiner joins in its place
    let c = groups[0]
        .commit_builder()
        .remove_member(1)
        .unwrap()
        .build()
        .await
        .unwrap();

    all_process_message(&mut groups, &c.commit_message, 0, true).await;

    let info = groups[0]
        .group_info_message_allowing_ext_commit()
        .await
        .unwrap();

    // Create the external joiner and join
    let new_client = generate_client(
        CipherSuite::P256_AES128,
        b"new member".to_vec(),
        Preferences::default(),
    );

    let (group, commit) = new_client
        .client
        .commit_external(info, new_client.identity)
        .await
        .unwrap();

    all_process_message(&mut groups, &commit, 1, false).await;
    groups[1] = group;

    // New client's sibling proposes an update to blank their common parent
    let p = groups[0].propose_update(vec![]).await.unwrap();
    all_process_message(&mut groups, &p, 0, false).await;

    // Some other member commits
    let c = groups[2].commit(vec![]).await.unwrap();
    all_process_message(&mut groups, &c.commit_message, 2, true).await;
}
