use aws_mls::{
    client_builder::{ClientBuilder, Preferences},
    group::CommitBuilder,
    identity::{basic::BasicIdentityProvider, SigningIdentity},
    storage_provider::{in_memory::InMemoryKeyPackageStorage, ExternalPskId},
    CipherSuite, CipherSuiteProvider, CryptoProvider, ExtensionList, Group, MLSMessage,
    ProtocolVersion,
};

use rand::{seq::IteratorRandom, Rng, SeedableRng};

use crate::scenario_utils::{add_random_members, remove_members};

use super::{
    scenario_utils::{
        all_process_message, get_test_groups, TestCase, TestEpoch, TestExternalPsk, TestRatchetTree,
    },
    test_client::{
        generate_client, get_test_basic_credential, make_test_ext_psk, TestClientConfig,
        TestCryptoProvider, TEST_EXT_PSK_ID,
    },
};
use itertools::Itertools;

fn write_test_cases(name: &str, serialized_tests: &str) {
    let path = format!("{}/../test_data/{}.json", env!("CARGO_MANIFEST_DIR"), name);

    if !std::path::Path::new(&path).exists() {
        std::fs::write(path, serialized_tests).unwrap();
    }
}

async fn invite_passive_client<P: CipherSuiteProvider>(
    groups: &mut [Group<TestClientConfig>],
    with_psk: bool,
    cs: &P,
) -> TestCase {
    let crypto_provider = TestCryptoProvider::new();

    let (secret_key, public_key) = cs.signature_key_generate().unwrap();
    let credential = get_test_basic_credential(b"Arnold".to_vec());
    let identity = SigningIdentity::new(credential, public_key);
    let key_package_repo = InMemoryKeyPackageStorage::new();

    let client = ClientBuilder::new()
        .crypto_provider(crypto_provider)
        .identity_provider(BasicIdentityProvider::new())
        .single_signing_identity(identity.clone(), secret_key.clone(), cs.cipher_suite())
        .key_package_repo(key_package_repo.clone())
        .build();

    let key_pckg = client
        .generate_key_package_message(ProtocolVersion::MLS_10, cs.cipher_suite(), identity.clone())
        .await
        .unwrap();

    let (_, key_pckg_secrets) = key_package_repo.key_packages()[0].clone();

    let mut commit_builder = groups[0]
        .commit_builder()
        .add_member(key_pckg.clone())
        .unwrap();

    if with_psk {
        commit_builder = commit_builder
            .add_external_psk(ExternalPskId::new(TEST_EXT_PSK_ID.to_vec()))
            .unwrap();
    }

    let commit = commit_builder.build().await.unwrap();

    all_process_message(groups, &commit.commit_message, 0, true).await;

    let external_psk = TestExternalPsk {
        psk_id: TEST_EXT_PSK_ID.to_vec(),
        psk: make_test_ext_psk(),
    };

    TestCase {
        cipher_suite: cs.cipher_suite().into(),
        key_package: key_pckg.to_bytes().unwrap(),
        encryption_priv: key_pckg_secrets.leaf_node_key.to_vec(),
        init_priv: key_pckg_secrets.init_key.to_vec(),
        welcome: commit.welcome_message.unwrap().to_bytes().unwrap(),
        initial_epoch_authenticator: groups[0].epoch_authenticator().unwrap(),
        epochs: vec![],
        signature_priv: secret_key.to_vec(),
        external_psks: if with_psk { vec![external_psk] } else { vec![] },
        ratchet_tree: None,
    }
}

pub async fn generate_passive_client_proposal_tests() {
    let mut test_cases: Vec<TestCase> = vec![];

    for cs in CipherSuite::all() {
        let crypto_provider = TestCryptoProvider::new();
        let Some(cs) = crypto_provider.cipher_suite_provider(cs) else { continue };

        let mut groups = get_test_groups(
            ProtocolVersion::MLS_10,
            cs.cipher_suite(),
            7,
            Preferences::default().with_ratchet_tree_extension(true),
        )
        .await;

        let mut partial_test_case = invite_passive_client(&mut groups, false, &cs).await;

        // Create a new epoch s.t. the passive member can process resumption PSK from the current one
        let commit = groups[0].commit(vec![]).await.unwrap();
        all_process_message(&mut groups, &commit.commit_message, 0, true).await;

        partial_test_case.epochs.push(TestEpoch::new(
            vec![],
            &commit.commit_message,
            groups[0].epoch_authenticator().unwrap(),
        ));

        let psk = ExternalPskId::new(TEST_EXT_PSK_ID.to_vec());
        let key_pckg = create_key_package(cs.cipher_suite()).await;

        // Create by value proposals
        let test_case = commit_by_value(
            &mut groups[3].clone(),
            |b| b.add_member(key_pckg.clone()).unwrap(),
            partial_test_case.clone(),
        )
        .await;

        test_cases.push(test_case);

        let test_case = commit_by_value(
            &mut groups[3].clone(),
            |b| b.remove_member(5).unwrap(),
            partial_test_case.clone(),
        )
        .await;

        test_cases.push(test_case);

        let test_case = commit_by_value(
            &mut groups[1].clone(),
            |b| b.add_external_psk(psk.clone()).unwrap(),
            partial_test_case.clone(),
        )
        .await;

        test_cases.push(test_case);

        let test_case = commit_by_value(
            &mut groups[5].clone(),
            |b| b.add_resumption_psk(groups[1].current_epoch() - 1).unwrap(),
            partial_test_case.clone(),
        )
        .await;

        test_cases.push(test_case);

        let test_case = commit_by_value(
            &mut groups[2].clone(),
            |b| b.set_group_context_ext(ExtensionList::new()).unwrap(),
            partial_test_case.clone(),
        )
        .await;

        test_cases.push(test_case);

        let test_case = commit_by_value(
            &mut groups[3].clone(),
            |b| {
                b.add_member(key_pckg)
                    .unwrap()
                    .remove_member(5)
                    .unwrap()
                    .add_external_psk(psk.clone())
                    .unwrap()
                    .add_resumption_psk(groups[4].current_epoch() - 1)
                    .unwrap()
                    .set_group_context_ext(ExtensionList::new())
                    .unwrap()
            },
            partial_test_case.clone(),
        )
        .await;

        test_cases.push(test_case);

        // Create by reference proposals
        let add = groups[0]
            .propose_add(create_key_package(cs.cipher_suite()).await, vec![])
            .await
            .unwrap();

        let add = (add, 0);

        let update = (groups[1].propose_update(vec![]).await.unwrap(), 1);
        let remove = (groups[2].propose_remove(2, vec![]).await.unwrap(), 2);

        let ext_psk = groups[3]
            .propose_external_psk(psk.clone(), vec![])
            .await
            .unwrap();

        let ext_psk = (ext_psk, 3);

        let last_ep = groups[3].current_epoch() - 1;

        let res_psk = groups[3]
            .propose_resumption_psk(last_ep, vec![])
            .await
            .unwrap();

        let res_psk = (res_psk, 3);

        let grp_ext = groups[4]
            .propose_group_context_extensions(ExtensionList::new(), vec![])
            .await
            .unwrap();

        let grp_ext = (grp_ext, 4);

        let proposals = [add, update, remove, ext_psk, res_psk, grp_ext];

        for (p, sender) in &proposals {
            let mut groups = groups.clone();

            all_process_message(&mut groups, p, *sender, false).await;

            let commit = groups[5].commit(vec![]).await.unwrap().commit_message;

            groups[5].apply_pending_commit().await.unwrap();
            let auth = groups[5].epoch_authenticator().unwrap();

            let mut test_case = partial_test_case.clone();
            let epoch = TestEpoch::new(vec![p.clone()], &commit, auth);
            test_case.epochs.push(epoch);

            test_cases.push(test_case);
        }

        let mut group = groups[4].clone();

        for (p, _) in proposals.iter().filter(|(_, i)| *i != 4) {
            group.process_incoming_message(p.clone()).await.unwrap();
        }

        let commit = group.commit(vec![]).await.unwrap().commit_message;
        group.apply_pending_commit().await.unwrap();
        let auth = group.epoch_authenticator().unwrap();
        let mut test_case = partial_test_case.clone();
        let proposals = proposals.into_iter().map(|(p, _)| p).collect();
        let epoch = TestEpoch::new(proposals, &commit, auth);
        test_case.epochs.push(epoch);
        test_cases.push(test_case);
    }

    let serialized_tests = serde_json::to_string_pretty(&test_cases).unwrap();
    write_test_cases("interop_passive_client_handle_commit", &serialized_tests);
}

async fn commit_by_value<F>(
    group: &mut Group<TestClientConfig>,
    proposal_adder: F,
    partial_test_case: TestCase,
) -> TestCase
where
    F: FnOnce(CommitBuilder<TestClientConfig>) -> CommitBuilder<TestClientConfig>,
{
    let builder = proposal_adder(group.commit_builder());
    let commit = builder.build().await.unwrap().commit_message;
    group.apply_pending_commit().await.unwrap();
    let auth = group.epoch_authenticator().unwrap();
    let epoch = TestEpoch::new(vec![], &commit, auth);
    let mut test_case = partial_test_case;
    test_case.epochs.push(epoch);
    test_case
}

async fn create_key_package(cs: CipherSuite) -> MLSMessage {
    let client = generate_client(cs, b"Roger".to_vec(), Preferences::default());

    client
        .client
        .generate_key_package_message(ProtocolVersion::MLS_10, cs, client.identity)
        .await
        .unwrap()
}

pub async fn generate_passive_client_welcome_tests() {
    let mut test_cases: Vec<TestCase> = vec![];

    for cs in CipherSuite::all() {
        let crypto_provider = TestCryptoProvider::new();
        let Some(cs) = crypto_provider.cipher_suite_provider(cs) else { continue };

        for with_tree_in_extension in [true, false] {
            for (with_psk, with_path) in [false, true].into_iter().cartesian_product([true, false])
            {
                let mut groups = get_test_groups(
                    ProtocolVersion::MLS_10,
                    cs.cipher_suite(),
                    16,
                    Preferences::default()
                        .with_ratchet_tree_extension(with_tree_in_extension)
                        .force_commit_path_update(with_path),
                )
                .await;

                // Remove a member s.t. the passive member joins in their place
                let proposal = groups[0].propose_remove(7, vec![]).await.unwrap();
                all_process_message(&mut groups, &proposal, 0, false).await;

                let mut test_case = invite_passive_client(&mut groups, with_psk, &cs).await;

                if !with_tree_in_extension {
                    let tree = groups[0].export_tree().unwrap();
                    test_case.ratchet_tree = Some(TestRatchetTree(tree));
                }

                test_cases.push(test_case);
            }
        }
    }

    let serialized_tests = serde_json::to_string_pretty(&test_cases).unwrap();
    write_test_cases("interop_passive_client_welcome", &serialized_tests);
}

pub async fn generate_passive_client_random_tests() {
    let mut test_cases: Vec<TestCase> = vec![];

    for cs in CipherSuite::all() {
        let crypto_provider = TestCryptoProvider::new();
        let Some(cs) = crypto_provider.cipher_suite_provider(cs) else { continue };

        let mut groups = get_test_groups(
            ProtocolVersion::MLS_10,
            cs.cipher_suite(),
            11,
            Preferences::default().with_ratchet_tree_extension(true),
        )
        .await;

        let mut test_case = invite_passive_client(&mut groups, false, &cs).await;

        let passive_client_index = 11;

        let seed: <rand::rngs::StdRng as SeedableRng>::Seed = rand::random();
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        println!("generating random commits for seed {}", hex::encode(seed));

        let mut random_member_first_index = 0;
        for i in 0..100 {
            println!("running step {i} members : {}", groups[0].roster().len());

            // We keep the passive client and another member to send
            let num_removed = rng.gen_range(0..groups.len() - 2);
            let num_added = rng.gen_range(1..30);

            let mut members = (0..groups.len())
                .filter(|i| groups[*i].current_member_index() != passive_client_index)
                .choose_multiple(&mut rng, num_removed + 1);

            let sender = members.pop().unwrap();

            remove_members(members, sender, &mut groups, Some(&mut test_case)).await;

            let sender = (0..groups.len())
                .filter(|i| groups[*i].current_member_index() != passive_client_index)
                .choose(&mut rng)
                .unwrap();

            add_random_members(
                random_member_first_index,
                num_added,
                sender,
                &mut groups,
                Some(&mut test_case),
            )
            .await;

            random_member_first_index += num_added;
        }

        test_cases.push(test_case);
    }

    let serialized_tests = serde_json::to_string_pretty(&test_cases).unwrap();
    write_test_cases("interop_passive_client_random", &serialized_tests);
}
