// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use assert_matches::assert_matches;
use cfg_if::cfg_if;
use mls_rs::client_builder::MlsConfig;
use mls_rs::error::MlsError;
use mls_rs::extension::built_in::ExternalSendersExt;
use mls_rs::group::proposal::Proposal;
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rules::CommitOptions;
use mls_rs::ExtensionList;
use mls_rs::MlsMessage;
use mls_rs::ProtocolVersion;
#[cfg(feature = "application_data")]
use mls_rs::{
    client_builder::PaddingMode,
    group::{ApplicationDataDictionary, ComponentId, APPLICATION_DATA},
    identity::basic::BasicIdentityProvider,
    mls_rules::{DefaultMlsRules, EncryptionOptions},
    MlsRules,
};
use mls_rs::{CipherSuite, Group};
use mls_rs::{Client, CryptoProvider};
use mls_rs_core::crypto::CipherSuiteProvider;
#[cfg(feature = "application_data")]
use mls_rs_core::identity::BasicCredential;
use rand::prelude::SliceRandom;
use rand::RngCore;

use mls_rs::test_utils::{all_process_message, get_test_basic_credential};

#[cfg(mls_build_async)]
use futures::Future;

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        use mls_rs_crypto_webcrypto::WebCryptoProvider as TestCryptoProvider;
    } else {
        use mls_rs_crypto_openssl::OpensslCryptoProvider as TestCryptoProvider;
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn generate_client(
    cipher_suite: CipherSuite,
    protocol_version: ProtocolVersion,
    id: usize,
    encrypt_controls: bool,
) -> Client<impl MlsConfig> {
    mls_rs::test_utils::generate_basic_client(
        cipher_suite,
        protocol_version,
        id,
        None,
        encrypt_controls,
        &TestCryptoProvider::default(),
        None,
    )
    .await
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub async fn get_test_groups(
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    num_participants: usize,
    encrypt_controls: bool,
) -> Vec<Group<impl MlsConfig>> {
    mls_rs::test_utils::get_test_groups(
        version,
        cipher_suite,
        num_participants,
        None,
        encrypt_controls,
        &TestCryptoProvider::default(),
    )
    .await
}

use rand::seq::IteratorRandom;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as futures_test;

#[cfg(all(mls_build_async, not(target_arch = "wasm32")))]
use futures_test::test as futures_test;

#[cfg(feature = "private_message")]
#[cfg(mls_build_async)]
async fn test_on_all_params<F, Fut>(test: F)
where
    F: Fn(ProtocolVersion, CipherSuite, usize, bool) -> Fut,
    Fut: Future<Output = ()>,
{
    for version in ProtocolVersion::all() {
        for cs in TestCryptoProvider::all_supported_cipher_suites() {
            for encrypt_controls in [true, false] {
                test(version, cs, 10, encrypt_controls).await;
            }
        }
    }
}

#[cfg(feature = "private_message")]
#[cfg(not(mls_build_async))]
fn test_on_all_params<F>(test: F)
where
    F: Fn(ProtocolVersion, CipherSuite, usize, bool),
{
    for version in ProtocolVersion::all() {
        for cs in TestCryptoProvider::all_supported_cipher_suites() {
            for encrypt_controls in [true, false] {
                test(version, cs, 10, encrypt_controls);
            }
        }
    }
}

#[cfg(not(feature = "private_message"))]
#[cfg(mls_build_async)]
async fn test_on_all_params<F, Fut>(test: F)
where
    F: Fn(ProtocolVersion, CipherSuite, usize, bool) -> Fut,
    Fut: Future<Output = ()>,
{
    test_on_all_params_plaintext(test).await;
}

#[cfg(not(feature = "private_message"))]
#[cfg(not(mls_build_async))]
fn test_on_all_params<F>(test: F)
where
    F: Fn(ProtocolVersion, CipherSuite, usize, bool),
{
    test_on_all_params_plaintext(test);
}

#[cfg(mls_build_async)]
async fn test_on_all_params_plaintext<F, Fut>(test: F)
where
    F: Fn(ProtocolVersion, CipherSuite, usize, bool) -> Fut,
    Fut: Future<Output = ()>,
{
    for version in ProtocolVersion::all() {
        for cs in TestCryptoProvider::all_supported_cipher_suites() {
            test(version, cs, 10, false).await;
        }
    }
}

#[cfg(not(mls_build_async))]
fn test_on_all_params_plaintext<F>(test: F)
where
    F: Fn(ProtocolVersion, CipherSuite, usize, bool),
{
    for version in ProtocolVersion::all() {
        for cs in TestCryptoProvider::all_supported_cipher_suites() {
            test(version, cs, 10, false);
        }
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn test_create(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    _n_participants: usize,
    encrypt_controls: bool,
) {
    let alice = generate_client(cipher_suite, protocol_version, 0, encrypt_controls).await;
    let bob = generate_client(cipher_suite, protocol_version, 1, encrypt_controls).await;
    let bob_key_pkg = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .await
        .unwrap();

    // Alice creates a group and adds bob
    let mut alice_group = alice
        .create_group_with_id(
            b"group".to_vec(),
            Default::default(),
            Default::default(),
            None,
        )
        .await
        .unwrap();

    let welcome = &alice_group
        .commit_builder()
        .add_member(bob_key_pkg)
        .unwrap()
        .build()
        .await
        .unwrap()
        .welcome_messages[0];

    // Upon server confirmation, alice applies the commit to her own state
    alice_group.apply_pending_commit().await.unwrap();

    // Bob receives the welcome message and joins the group
    let (bob_group, _) = bob.join_group(None, welcome, None).await.unwrap();

    assert!(Group::equal_group_state(&alice_group, &bob_group));
}

#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_create_group() {
    test_on_all_params(test_create).await;
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn test_empty_commits(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    encrypt_controls: bool,
) {
    let mut groups = get_test_groups(
        protocol_version,
        cipher_suite,
        participants,
        encrypt_controls,
    )
    .await;

    // Loop through each participant and send a path update

    for i in 0..groups.len() {
        // Create the commit
        let commit_output = groups[i].commit(Vec::new()).await.unwrap();

        assert!(commit_output.welcome_messages.is_empty());

        let index = groups[i].current_member_index() as usize;
        all_process_message(&mut groups, &commit_output.commit_message, index, true).await;

        for other_group in groups.iter() {
            assert!(Group::equal_group_state(other_group, &groups[i]));
        }
    }
}

#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_group_path_updates() {
    test_on_all_params(test_empty_commits).await;
}

#[cfg(feature = "by_ref_proposal")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn test_update_proposals(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    encrypt_controls: bool,
) {
    let mut groups = get_test_groups(
        protocol_version,
        cipher_suite,
        participants,
        encrypt_controls,
    )
    .await;

    // Create an update from the ith member, have the ith + 1 member commit it
    for i in 0..groups.len() - 1 {
        let update_proposal_msg = groups[i].propose_update(Vec::new()).await.unwrap();

        let sender = groups[i].current_member_index() as usize;
        all_process_message(&mut groups, &update_proposal_msg, sender, false).await;

        // Everyone receives the commit
        let committer_index = i + 1;

        let commit_output = groups[committer_index].commit(Vec::new()).await.unwrap();

        assert!(commit_output.welcome_messages.is_empty());

        let commit = commit_output.commit_message;

        all_process_message(&mut groups, &commit, committer_index, true).await;

        groups
            .iter()
            .for_each(|g| assert!(Group::equal_group_state(g, &groups[0])));
    }
}

#[cfg(feature = "by_ref_proposal")]
#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_group_update_proposals() {
    test_on_all_params(test_update_proposals).await;
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn test_remove_proposals(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    encrypt_controls: bool,
) {
    let mut groups = get_test_groups(
        protocol_version,
        cipher_suite,
        participants,
        encrypt_controls,
    )
    .await;

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

        assert!(commit_output.welcome_messages.is_empty());

        let commit = commit_output.commit_message;
        let committer_index = groups[committer].current_member_index() as usize;
        all_process_message(&mut groups, &commit, committer_index, true).await;

        // Check that remove was effective
        for (i, group) in groups.iter().enumerate() {
            if i == to_remove {
                assert_eq!(group.current_epoch(), epoch_before_remove);
            } else {
                assert_eq!(group.current_epoch(), epoch_before_remove + 1);
                assert!(group.roster().member_with_index(to_remove_index).is_err());
            }
        }

        groups.retain(|group| group.current_member_index() != to_remove_index);

        for one_group in groups.iter() {
            assert!(Group::equal_group_state(one_group, &groups[0]))
        }
    }
}

#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_group_remove_proposals() {
    test_on_all_params(test_remove_proposals).await;
}

#[cfg(feature = "private_message")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn test_application_messages(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    encrypt_controls: bool,
) {
    let message_count = 20;

    let mut groups = get_test_groups(
        protocol_version,
        cipher_suite,
        participants,
        encrypt_controls,
    )
    .await;

    // Loop through each participant and send application messages
    for i in 0..groups.len() {
        let mut test_message = vec![0; 1024];
        rand::thread_rng().fill_bytes(&mut test_message);

        for _ in 0..message_count {
            // Encrypt the application message
            let ciphertext = groups[i]
                .encrypt_application_message(&test_message, Vec::new())
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

#[cfg(all(feature = "private_message", feature = "out_of_order"))]
#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_out_of_order_application_messages() {
    let mut groups =
        get_test_groups(ProtocolVersion::MLS_10, CipherSuite::P256_AES128, 2, false).await;

    let mut alice_group = groups[0].clone();
    let bob_group = &mut groups[1];

    let ciphertext = alice_group
        .encrypt_application_message(&[0], Vec::new())
        .await
        .unwrap();

    let mut ciphertexts = vec![ciphertext];

    ciphertexts.push(
        alice_group
            .encrypt_application_message(&[1], Vec::new())
            .await
            .unwrap(),
    );

    let commit = alice_group.commit(Vec::new()).await.unwrap().commit_message;

    alice_group.apply_pending_commit().await.unwrap();

    bob_group.process_incoming_message(commit).await.unwrap();

    ciphertexts.push(
        alice_group
            .encrypt_application_message(&[2], Vec::new())
            .await
            .unwrap(),
    );

    ciphertexts.push(
        alice_group
            .encrypt_application_message(&[3], Vec::new())
            .await
            .unwrap(),
    );

    for i in [3, 2, 1, 0] {
        let res = bob_group
            .process_incoming_message(ciphertexts[i].clone())
            .await
            .unwrap();

        assert_matches!(
            res,
            ReceivedMessage::ApplicationMessage(m) if m.data() == [i as u8]
        );
    }
}

#[cfg(feature = "private_message")]
#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_group_application_messages() {
    test_on_all_params(test_application_messages).await
}

#[cfg(feature = "private_message")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn processing_message_from_self_returns_error(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    _n_participants: usize,
    encrypt_controls: bool,
) {
    let mut creator_group =
        get_test_groups(protocol_version, cipher_suite, 1, encrypt_controls).await;
    let creator_group = &mut creator_group[0];

    let msg = creator_group
        .encrypt_application_message(b"hello self", vec![])
        .await
        .unwrap();

    let error = creator_group
        .process_incoming_message(msg)
        .await
        .unwrap_err();

    assert_matches!(error, MlsError::CantProcessMessageFromSelf);
}

#[cfg(feature = "private_message")]
#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_processing_message_from_self_returns_error() {
    test_on_all_params(processing_message_from_self_returns_error).await;
}

#[cfg(feature = "by_ref_proposal")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn external_commits_work(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    _n_participants: usize,
    _encrypt_controls: bool,
) {
    let creator = generate_client(cipher_suite, protocol_version, 0, false).await;

    let creator_group = creator
        .create_group_with_id(
            b"group".to_vec(),
            Default::default(),
            Default::default(),
            None,
        )
        .await
        .unwrap();

    const PARTICIPANT_COUNT: usize = 10;

    let mut others = Vec::new();

    for i in 1..PARTICIPANT_COUNT {
        others.push(generate_client(cipher_suite, protocol_version, i, Default::default()).await)
    }

    let mut groups = vec![creator_group];

    for client in &others {
        let existing_group = groups.choose_mut(&mut rand::thread_rng()).unwrap();

        let group_info = existing_group
            .group_info_message_allowing_ext_commit(true)
            .await
            .unwrap();

        let (new_group, commit) = client
            .external_commit_builder()
            .unwrap()
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
    }

    assert!(groups
        .iter()
        .all(|group| group.roster().members_iter().count() == PARTICIPANT_COUNT));

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

#[cfg(feature = "by_ref_proposal")]
#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_external_commits() {
    test_on_all_params_plaintext(external_commits_work).await
}

#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_remove_nonexisting_leaf() {
    let mut groups =
        get_test_groups(ProtocolVersion::MLS_10, CipherSuite::P256_AES128, 10, false).await;

    groups[0]
        .commit_builder()
        .remove_member(5)
        .unwrap()
        .build()
        .await
        .unwrap();
    groups[0].apply_pending_commit().await.unwrap();

    // Leaf index out of bounds
    assert!(groups[0].commit_builder().remove_member(13).is_err());

    // Removing blank leaf causes error
    assert!(groups[0].commit_builder().remove_member(5).is_err());
}

#[cfg(feature = "psk")]
#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn reinit_works() {
    use mls_rs::group::{CommitEffect, CommitMessageDescription};

    let suite1 = CipherSuite::P256_AES128;

    let Some(suite2) = CipherSuite::all()
        .find(|cs| cs != &suite1 && TestCryptoProvider::all_supported_cipher_suites().contains(cs))
    else {
        return;
    };

    let version = ProtocolVersion::MLS_10;

    let alice1 = generate_client(suite1, version, 1, Default::default()).await;
    let bob1 = generate_client(suite1, version, 2, Default::default()).await;

    // Create a group with 2 parties
    let mut alice_group = alice1
        .create_group(Default::default(), Default::default(), None)
        .await
        .unwrap();
    let kp = bob1
        .generate_key_package_message(Default::default(), Default::default(), None)
        .await
        .unwrap();

    let welcome = &alice_group
        .commit_builder()
        .add_member(kp)
        .unwrap()
        .build()
        .await
        .unwrap()
        .welcome_messages[0];

    alice_group.apply_pending_commit().await.unwrap();

    let (mut bob_group, _) = bob1.join_group(None, welcome, None).await.unwrap();

    // Alice proposes reinit
    let reinit_proposal_message = alice_group
        .propose_reinit(
            None,
            ProtocolVersion::MLS_10,
            suite2,
            ExtensionList::default(),
            Vec::new(),
        )
        .await
        .unwrap();

    // Bob commits the reinit
    bob_group
        .process_incoming_message(reinit_proposal_message)
        .await
        .unwrap();

    let commit = bob_group.commit(Vec::new()).await.unwrap().commit_message;

    // Both process Bob's commit

    let commit_effect = bob_group.apply_pending_commit().await.unwrap().effect;
    assert_matches!(commit_effect, CommitEffect::ReInit(_));

    let message = alice_group.process_incoming_message(commit).await.unwrap();

    assert_matches!(
        message,
        ReceivedMessage::Commit(CommitMessageDescription {
            effect: CommitEffect::ReInit(_),
            ..
        })
    );

    // They can't create new epochs anymore
    let res = alice_group.commit(Vec::new()).await;
    assert!(res.is_err());

    let res = bob_group.commit(Vec::new()).await;
    assert!(res.is_err());

    // Get reinit clients for alice and bob
    let (secret_key, public_key) = TestCryptoProvider::default()
        .cipher_suite_provider(suite2)
        .unwrap()
        .signature_key_generate()
        .await
        .unwrap();

    let identity = SigningIdentity::new(get_test_basic_credential(b"bob".to_vec()), public_key);

    let bob2 = bob_group
        .get_reinit_client(Some(secret_key), Some(identity))
        .unwrap();

    let (secret_key, public_key) = TestCryptoProvider::default()
        .cipher_suite_provider(suite2)
        .unwrap()
        .signature_key_generate()
        .await
        .unwrap();

    let identity = SigningIdentity::new(get_test_basic_credential(b"alice".to_vec()), public_key);

    let alice2 = alice_group
        .get_reinit_client(Some(secret_key), Some(identity))
        .unwrap();

    // Bob produces key package, alice commits, bob joins
    let kp = bob2.generate_key_package(None).await.unwrap();
    let (mut alice_group, welcome) = alice2
        .commit(vec![kp], Default::default(), None)
        .await
        .unwrap();
    let (mut bob_group, _) = bob2.join(&welcome[0], None, None).await.unwrap();

    assert!(bob_group.cipher_suite() == suite2);

    // They can talk
    let carol = generate_client(suite2, version, 3, Default::default()).await;

    let kp = carol
        .generate_key_package_message(Default::default(), Default::default(), None)
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

    carol
        .join_group(None, &commit_output.welcome_messages[0], None)
        .await
        .unwrap();
}

#[cfg(feature = "by_ref_proposal")]
#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn external_joiner_can_process_siblings_update() {
    let mut groups =
        get_test_groups(ProtocolVersion::MLS_10, CipherSuite::P256_AES128, 3, false).await;

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
        .group_info_message_allowing_ext_commit(true)
        .await
        .unwrap();

    // Create the external joiner and join
    let new_client = generate_client(
        CipherSuite::P256_AES128,
        ProtocolVersion::MLS_10,
        0xabba,
        false,
    )
    .await;

    let (mut group, commit) = new_client.commit_external(info).await.unwrap();

    all_process_message(&mut groups, &commit, 1, false).await;
    groups.remove(1);

    // New client's sibling proposes an update to blank their common parent
    let p = groups[0].propose_update(Vec::new()).await.unwrap();
    all_process_message(&mut groups, &p, 0, false).await;
    group.process_incoming_message(p).await.unwrap();

    // Some other member commits
    let c = groups[1].commit(Vec::new()).await.unwrap().commit_message;
    all_process_message(&mut groups, &c, 2, true).await;
    group.process_incoming_message(c).await.unwrap();
}

#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn weird_tree_scenario() {
    let mut groups =
        get_test_groups(ProtocolVersion::MLS_10, CipherSuite::P256_AES128, 17, false).await;

    let to_remove = [0u32, 2, 5, 7, 8, 9, 15];

    let mut builder = groups[14].commit_builder();

    for idx in to_remove.iter() {
        builder = builder.remove_member(*idx).unwrap();
    }

    let commit = builder.build().await.unwrap();

    for idx in to_remove.into_iter().rev() {
        groups.remove(idx as usize);
    }

    all_process_message(&mut groups, &commit.commit_message, 14, true).await;

    let mut builder = groups.last_mut().unwrap().commit_builder();

    for idx in 0..7 {
        builder = builder
            .add_member(fake_key_package(5555555 + idx).await)
            .unwrap()
    }

    let commit = builder.remove_member(1).unwrap().build().await.unwrap();

    let idx = groups.last().unwrap().current_member_index() as usize;

    all_process_message(&mut groups, &commit.commit_message, idx, true).await;
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn fake_key_package(id: usize) -> MlsMessage {
    generate_client(CipherSuite::P256_AES128, ProtocolVersion::MLS_10, id, false)
        .await
        .generate_key_package_message(Default::default(), Default::default(), None)
        .await
        .unwrap()
}

#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn external_info_from_commit_allows_to_join() {
    let cs = CipherSuite::P256_AES128;
    let version = ProtocolVersion::MLS_10;

    let mut alice = mls_rs::test_utils::get_test_groups(
        version,
        cs,
        1,
        Some(CommitOptions::new().with_allow_external_commit(true)),
        false,
        &TestCryptoProvider::default(),
    )
    .await
    .remove(0);

    let commit = alice.commit(vec![]).await.unwrap();
    alice.apply_pending_commit().await.unwrap();
    let bob = generate_client(cs, version, 0xdead, false).await;

    let (_bob, commit) = bob
        .commit_external(commit.external_commit_group_info.unwrap())
        .await
        .unwrap();

    alice.process_incoming_message(commit).await.unwrap();
}

#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn can_process_own_removal_if_pending_commit() {
    let mut groups =
        get_test_groups(ProtocolVersion::MLS_10, CipherSuite::P256_AES128, 2, false).await;

    let commit = groups[1]
        .commit_builder()
        .remove_member(0)
        .unwrap()
        .build()
        .await
        .unwrap();

    groups[0].commit(vec![]).await.unwrap();

    groups[0]
        .process_incoming_message(commit.commit_message)
        .await
        .unwrap();
}

#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn can_process_external_commit_if_pending_commit() {
    let alice = generate_client(CipherSuite::P256_AES128, ProtocolVersion::MLS_10, 0, false).await;
    let bob = generate_client(CipherSuite::P256_AES128, ProtocolVersion::MLS_10, 1, false).await;

    let mut alice_group = alice
        .create_group(Default::default(), Default::default(), None)
        .await
        .unwrap();

    alice_group
        .commit_builder()
        .add_member(
            bob.generate_key_package_message(Default::default(), Default::default(), None)
                .await
                .unwrap(),
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let (mut bob_group, external_commit) = bob
        .commit_external(
            alice_group
                .group_info_message_allowing_ext_commit(true)
                .await
                .unwrap(),
        )
        .await
        .unwrap();

    alice_group
        .process_incoming_message(external_commit)
        .await
        .unwrap();

    // Confirm that clients are in sync
    let commit = alice_group.commit(vec![]).await.unwrap();
    alice_group.apply_pending_commit().await.unwrap();

    bob_group
        .process_incoming_message(commit.commit_message)
        .await
        .unwrap();
}

#[cfg(feature = "application_data")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn test_application_data_proposals(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    encrypt_controls: bool,
) {
    let commit_options = CommitOptions::new()
        .with_ratchet_tree_extension(false)
        .with_single_welcome_message(true)
        .with_path_required(false)
        .with_allow_external_commit(true);
    let encryption_options = EncryptionOptions::new(encrypt_controls, PaddingMode::StepFunction);
    let rules = ApplicationDataRules(
        DefaultMlsRules::new()
            .with_commit_options(commit_options)
            .with_encryption_options(encryption_options),
    );

    let mut groups = get_test_group_with_rules(
        cipher_suite,
        participants,
        rules,
        #[cfg(feature = "by_ref_proposal")]
        None,
    );

    let committer = (0..groups.len()).choose_multiple(&mut rand::thread_rng(), 1)[0];

    let commit_output = groups[committer]
        .commit_builder()
        .application_data(10, b"hello".to_vec())
        .unwrap()
        .application_data(12, b"hi".to_vec())
        .unwrap()
        .application_data(10, b"world".to_vec())
        .unwrap()
        .build()
        .await
        .unwrap();

    let commit = commit_output.commit_message;
    let committer_index = groups[committer].current_member_index() as usize;

    let mut app_data = None;
    for group in &mut groups {
        let description = if committer_index != group.current_member_index() as usize {
            if let ReceivedMessage::Commit(description) = group
                .process_incoming_message(commit.clone())
                .await
                .unwrap()
            {
                description
            } else {
                unreachable!()
            }
        } else {
            group.apply_pending_commit().await.unwrap()
        };

        if app_data.is_none() {
            app_data = Some(description.application_data);
        } else {
            // the application data proposals must have been applied in the same order for all clients,
            // so if multiple proposals refer to the same component id and overwrite each other,
            // we should get a consistent result
            assert_eq!(app_data.as_ref().unwrap(), &description.application_data);
        }
    }

    for one_group in groups.iter() {
        assert!(Group::equal_group_state(one_group, &groups[0]))
    }
}

#[cfg(feature = "application_data")]
#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_group_application_data_proposals() {
    test_on_all_params(test_application_data_proposals).await;
}

#[cfg(feature = "application_data")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn test_application_data_update_proposals(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    encrypt_controls: bool,
) {
    use mls_rs::group::{proposal::AppDataUpdateOperation, ComponentData};

    let commit_options = CommitOptions::new()
        .with_ratchet_tree_extension(false)
        .with_single_welcome_message(true)
        .with_path_required(false)
        .with_allow_external_commit(true);
    let encryption_options = EncryptionOptions::new(encrypt_controls, PaddingMode::StepFunction);
    let rules = ApplicationDataRules(
        DefaultMlsRules::new()
            .with_commit_options(commit_options)
            .with_encryption_options(encryption_options),
    );

    let mut groups = get_test_group_with_rules(
        cipher_suite,
        participants,
        rules,
        #[cfg(feature = "by_ref_proposal")]
        None,
    );

    let committer = (0..groups.len()).choose_multiple(&mut rand::thread_rng(), 1)[0];
    let commit_output = groups[committer]
        .commit_builder()
        .application_data_update(
            10,
            ApplicationDataUpdateOperation::Update(b"hello".to_vec()),
        )
        .unwrap()
        .application_data_update(12, ApplicationDataUpdateOperation::Update(b"hi".to_vec()))
        .unwrap()
        .build()
        .await
        .unwrap();

    let sender = groups[committer].current_member_index() as usize;
    all_process_message(&mut groups, &commit_output.commit_message, sender, true).await;
    for one_group in groups.iter() {
        assert!(Group::equal_group_state(one_group, &groups[0]))
    }
    let app_data = check_application_data(&groups);

    assert_eq!(
        app_data,
        ApplicationDataDictionary {
            component_data: vec![
                ComponentData {
                    component_id: 10,
                    data: b"\x0A\x00hello".to_vec()
                },
                ComponentData {
                    component_id: 12,
                    data: b"\x0C\x00hi".to_vec()
                }
            ]
        }
    );

    let committer = (0..groups.len()).choose_multiple(&mut rand::thread_rng(), 1)[0];
    let commit_output = groups[committer]
        .commit_builder()
        .application_data_update(
            10,
            ApplicationDataUpdateOperation::Update(b"world".to_vec()),
        )
        .unwrap()
        .application_data_update(12, ApplicationDataUpdateOperation::Remove)
        .unwrap()
        .build()
        .await
        .unwrap();

    let sender = groups[committer].current_member_index() as usize;
    all_process_message(&mut groups, &commit_output.commit_message, sender, true).await;
    for one_group in groups.iter() {
        assert!(Group::equal_group_state(one_group, &groups[0]))
    }
    let app_data = check_application_data(&groups);
    assert_eq!(
        app_data,
        ApplicationDataDictionary {
            component_data: vec![ComponentData {
                component_id: 10,
                data: b"\x0A\x00hello\x00world".to_vec()
            }]
        }
    );
}

#[cfg(feature = "application_data")]
#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_group_application_data_update_proposals() {
    test_on_all_params(test_application_data_update_proposals).await;
}

#[cfg(feature = "application_data")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn test_application_data_update_invalid_proposals(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    encrypt_controls: bool,
) {
    use mls_rs::group::proposal::AppDataUpdateOperation;

    let commit_options = CommitOptions::new()
        .with_ratchet_tree_extension(false)
        .with_single_welcome_message(true)
        .with_path_required(false)
        .with_allow_external_commit(true);
    let encryption_options = EncryptionOptions::new(encrypt_controls, PaddingMode::StepFunction);
    let rules = ApplicationDataRules(
        DefaultMlsRules::new()
            .with_commit_options(commit_options)
            .with_encryption_options(encryption_options),
    );

    let mut groups = get_test_group_with_rules(
        cipher_suite,
        participants,
        rules,
        #[cfg(feature = "by_ref_proposal")]
        None,
    )
    .await;

    let committer = (0..groups.len()).choose_multiple(&mut rand::thread_rng(), 1)[0];
    // unknown component id
    assert_eq!(
        groups[committer]
            .commit_builder()
            .application_data_update(
                10,
                AppDataUpdateOperation::Update(b"hello".to_vec()),
            )
            .unwrap()
            .application_data_update(42, AppDataUpdateOperation::Update(b"hi".to_vec()))
            .unwrap()
            .build()
            .unwrap_err()
            .to_string(),
        "Invalid application data update proposal"
    );

    // multiple remove operations for the same component
    assert_eq!(
        groups[committer]
            .commit_builder()
            .application_data_update(10, AppDataUpdateOperation::Remove,)
            .unwrap()
            .application_data_update(12, AppDataUpdateOperation::Update(b"hi".to_vec()))
            .unwrap()
            .application_data_update(10, AppDataUpdateOperation::Remove,)
            .unwrap()
            .build()
            .unwrap_err()
            .to_string(),
        "Invalid application data update proposal"
    );

    // update and remove operations for the same component
    assert_eq!(
        groups[committer]
            .commit_builder()
            .application_data_update(
                10,
                AppDataUpdateOperation::Update(b"hello".to_vec()),
            )
            .unwrap()
            .application_data_update(12, AppDataUpdateOperation::Update(b"hi".to_vec()))
            .unwrap()
            .application_data_update(10, AppDataUpdateOperation::Remove,)
            .unwrap()
            .build()
            .unwrap_err()
            .to_string(),
        "Invalid application data update proposal"
    );
}

#[cfg(feature = "application_data")]
#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_group_application_data_update_invalid_proposals() {
    test_on_all_params(test_application_data_update_invalid_proposals).await;
}

#[cfg(all(feature = "by_ref_proposal", feature = "application_data"))]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn test_application_data_update_external_proposals(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    encrypt_controls: bool,
) {
    use mls_rs::group::{proposal::AppDataUpdateOperation, ComponentData};

    let commit_options = CommitOptions::new()
        .with_ratchet_tree_extension(false)
        .with_single_welcome_message(true)
        .with_path_required(false)
        .with_allow_external_commit(true);
    let encryption_options = EncryptionOptions::new(encrypt_controls, PaddingMode::StepFunction);
    let rules = ApplicationDataRules(
        DefaultMlsRules::new()
            .with_commit_options(commit_options)
            .with_encryption_options(encryption_options),
    );

    let crypto = TestCryptoProvider::new();
    let idp = BasicIdentityProvider::new();
    let credential =
        BasicCredential::new(format!("external").as_bytes().to_vec()).into_credential();
    let cs_crypto = crypto.cipher_suite_provider(cipher_suite).unwrap();
    let (secret, public) = cs_crypto.signature_key_generate().unwrap();
    let signing_identity = SigningIdentity::new(credential, public);

    let mut groups = get_test_group_with_rules(
        cipher_suite,
        participants,
        rules.clone(),
        Some(signing_identity.clone()),
    )
    .await;

    let client = mls_rs::external_client::ExternalClient::builder()
        .protocol_version(protocol_version)
        .identity_provider(idp.clone())
        .crypto_provider(crypto.clone())
        .mls_rules(rules.clone())
        .extension_types([APPLICATION_DATA])
        .signer(secret, signing_identity)
        .build();

    let group_info = groups[0].group_info_message(true).unwrap();
    let tree_data = groups[0].export_tree();

    // send the external proposal
    let mut external_group = client
        .observe_group(group_info, Some(tree_data))
        .await
        .unwrap();
    let message = external_group
        .propose_application_data_update(
            10,
            ApplicationDataUpdateOperation::Update(b"hello".to_vec()),
            vec![],
        )
        .unwrap();
    for group in &mut groups {
        group
            .process_incoming_message(message.clone())
            .await
            .unwrap();
    }

    // one of the members commits the proposal and sends to other members
    let committer = (0..groups.len()).choose_multiple(&mut rand::thread_rng(), 1)[0];
    let commit_output = groups[committer].commit_builder().build().await.unwrap();

    let sender = groups[committer].current_member_index() as usize;
    all_process_message(&mut groups, &commit_output.commit_message, sender, true).await;
    for one_group in groups.iter() {
        assert!(Group::equal_group_state(one_group, &groups[0]))
    }

    let app_data = check_application_data(&groups);
    assert_eq!(
        app_data,
        ApplicationDataDictionary {
            component_data: vec![ComponentData {
                component_id: 10,
                data: b"\x0A\x00hello".to_vec()
            }]
        }
    );

    // check if we can observe the group again
    let group_info = groups[0].group_info_message(true).unwrap();
    let tree_data = groups[0].export_tree();
    let _external_group = client
        .observe_group(group_info, Some(tree_data))
        .await
        .unwrap();

    // now, try with an invalid external sender
    let unauthorized_credential =
        BasicCredential::new(format!("unauthorized_external").as_bytes().to_vec())
            .into_credential();
    let (unauthorized_secret, unauthorized_public) = cs_crypto.signature_key_generate().unwrap();
    let unauthorized_signing_identity =
        SigningIdentity::new(unauthorized_credential, unauthorized_public);

    let unauthorized_client = mls_rs::external_client::ExternalClient::builder()
        .protocol_version(protocol_version)
        .identity_provider(idp)
        .crypto_provider(crypto)
        .mls_rules(rules)
        .extension_types([APPLICATION_DATA])
        .signer(unauthorized_secret, unauthorized_signing_identity)
        .build();

    let group_info = groups[0].group_info_message(true).unwrap();
    let tree_data = groups[0].export_tree();

    // send the external proposal
    let mut unauthorized_external_group = unauthorized_client
        .observe_group(group_info, Some(tree_data))
        .await
        .unwrap();
    assert_matches!(
        unauthorized_external_group
            .propose_application_data_update(
                10,
                AppDataUpdateOperation::Update(b"hi".to_vec()),
                vec![],
            )
            .unwrap_err(),
        MlsError::InvalidExternalSigningIdentity
    );
}

#[cfg(feature = "application_data")]
#[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test))]
async fn test_group_application_data_update_external_proposals() {
    test_on_all_params(test_application_data_update_external_proposals).await;
}

#[cfg(feature = "application_data")]
fn check_application_data<C: MlsConfig>(groups: &[Group<C>]) -> ApplicationDataDictionary {
    let mut app_data = None;
    for group in groups {
        let application_data =
            application_data_from_extensions(&group.context().extensions).unwrap();

        if app_data.is_none() {
            app_data = application_data;
        } else {
            assert_eq!(app_data, application_data);
        }
    }
    app_data.unwrap()
}

#[cfg(feature = "application_data")]
fn application_data_from_extensions(
    extensions: &ExtensionList,
) -> Result<Option<mls_rs::group::ApplicationDataDictionary>, mls_rs_codec::Error> {
    use mls_rs::mls_rs_codec::MlsDecode;

    for extension in extensions.iter() {
        if extension.extension_type == mls_rs::group::APPLICATION_DATA {
            return Ok(Some(mls_rs::group::ApplicationDataDictionary::mls_decode(
                &mut &*extension.extension_data,
            )?));
        }
    }
    Ok(None)
}

#[cfg(feature = "application_data")]
#[derive(Clone)]
struct ApplicationDataRules(DefaultMlsRules);

#[cfg(feature = "application_data")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl MlsRules for ApplicationDataRules {
    type Error = MlsError;

    async fn filter_proposals(
        &self,
        direction: mls_rs::mls_rules::CommitDirection,
        source: mls_rs::mls_rules::CommitSource,
        current_roster: &mls_rs::group::Roster<'_>,
        current_context: &mls_rs_core::group::GroupContext,
        proposals: mls_rs::mls_rules::ProposalBundle,
    ) -> Result<mls_rs::mls_rules::ProposalBundle, Self::Error> {
        self.0
            .filter_proposals(
                direction,
                source,
                current_roster,
                current_context,
                proposals,
            )
            .map_err(|_| unreachable!())
    }

    fn commit_options(
        &self,
        new_roster: &mls_rs::group::Roster,
        new_context: &mls_rs_core::group::GroupContext,
        proposals: &mls_rs::mls_rules::ProposalBundle,
    ) -> Result<CommitOptions, Self::Error> {
        self.0
            .commit_options(new_roster, new_context, proposals)
            .map_err(|_| unreachable!())
    }

    fn encryption_options(
        &self,
        current_roster: &mls_rs::group::Roster,
        current_context: &mls_rs_core::group::GroupContext,
    ) -> Result<mls_rs::mls_rules::EncryptionOptions, Self::Error> {
        self.0
            .encryption_options(current_roster, current_context)
            .map_err(|_| unreachable!())
    }

    #[cfg(feature = "application_data")]
    fn supported_components(&self) -> &[ComponentId] {
        &[10, 12]
    }

    #[cfg(feature = "application_data")]
    async fn update_components(
        &self,
        component_id: ComponentId,
        component_data: Option<&[u8]>,
        update: &[u8],
        _roster: &mls_rs::group::Roster,
    ) -> Result<Vec<u8>, MlsError> {
        let mut v = component_data
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| vec![component_id as u8]);
        v.push(0);
        v.extend(update);
        Ok(v)
    }
    #[cfg(feature = "application_data")]
    async fn validate_component_data(
        &self,
        _component_id: ComponentId,
        _component_data: &[u8],
    ) -> bool {
        true
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn get_test_group_with_rules<Rules: MlsRules + Clone>(
    cipher_suite: CipherSuite,
    num_participants: usize,
    rules: Rules,
    #[cfg(feature = "by_ref_proposal")] ext_identity: Option<SigningIdentity>,
) -> Vec<Group<impl MlsConfig>> {
    let creator = setup_mls_client(0, cipher_suite, rules.clone());

    #[cfg(not(feature = "by_ref_proposal"))]
    let group_context_extensions: ExtensionList = Default::default();
    #[cfg(feature = "by_ref_proposal")]
    let mut group_context_extensions: ExtensionList = Default::default();
    #[cfg(feature = "by_ref_proposal")]
    if let Some(ext_signer) = ext_identity {
        group_context_extensions
            .set_from(ExternalSendersExt::new(vec![ext_signer]))
            .unwrap();
    }

    let mut creator_group = creator
        .create_group(group_context_extensions, Default::default())
        .await
        .unwrap();

    let mut commit_builder = creator_group.commit_builder();
    let mut receiver_clients = vec![];

    for i in 1..num_participants {
        let client = setup_mls_client(i, cipher_suite, rules.clone());

        let kp = client
            .generate_key_package_message(Default::default(), Default::default())
            .await
            .unwrap();

        receiver_clients.push(client);
        commit_builder = commit_builder.add_member(kp.clone()).unwrap();
    }

    let welcome = commit_builder.build().await.unwrap().welcome_messages;

    creator_group.apply_pending_commit().await.unwrap();

    let tree_data = creator_group.export_tree().into_owned();

    let mut groups = vec![creator_group];

    for client in &receiver_clients {
        let (test_client, _info) = client
            .join_group(Some(tree_data.clone()), &welcome[0])
            .await
            .unwrap();

        groups.push(test_client);
    }
    groups
}

#[cfg(feature = "application_data")]
pub(crate) fn setup_mls_client<Rules: MlsRules + Clone>(
    id: usize,
    cipher_suite: CipherSuite,
    rules: Rules,
) -> Client<impl MlsConfig> {
    let credential =
        BasicCredential::new(format!("client-{id}").as_bytes().to_vec()).into_credential();
    let crypto = TestCryptoProvider::new();
    let idp = BasicIdentityProvider::new();

    let cs_crypto = crypto.cipher_suite_provider(cipher_suite).unwrap();
    let (secret, public) = cs_crypto.signature_key_generate().unwrap();
    let signing_identity = SigningIdentity::new(credential, public);

    let client = Client::builder()
        .ciphersuite(cipher_suite)
        .crypto_provider(crypto)
        .identity_provider(idp)
        .signing_identity(signing_identity, secret)
        .mls_rules(rules)
        .extension_type(APPLICATION_DATA)
        .build();

    client
}
