use alloc::vec;
use alloc::vec::Vec;

use aws_mls_core::{
    crypto::{CipherSuiteProvider, CryptoProvider},
    psk::ExternalPskId,
};
use test_utils::scenario_utils::TestCase;

use crate::{
    client_builder::ClientBuilder, crypto::test_utils::TestCryptoProvider,
    group::internal::ClientConfig, identity::basic::BasicIdentityProvider,
    key_package::KeyPackageGeneration, MLSMessage,
};

#[futures_test::test]
async fn interop_passive_client() {
    // Test vectors can be found here:
    // * https://github.com/mlswg/mls-implementations/blob/main/test-vectors/passive-client-welcome.json
    // * https://github.com/mlswg/mls-implementations/blob/main/test-vectors/passive-client-handle-commit.json
    // * https://github.com/mlswg/mls-implementations/blob/main/test-vectors/passive-client-random.json

    let test_cases_wel: Vec<TestCase> =
        load_test_cases!(interop_passive_client_welcome, Vec::<TestCase>::new());

    let test_cases_com: Vec<TestCase> =
        load_test_cases!(interop_passive_client_handle_commit, Vec::<TestCase>::new());

    let test_cases_rand: Vec<TestCase> =
        load_test_cases!(interop_passive_client_random, Vec::<TestCase>::new());

    for test_case in vec![]
        .into_iter()
        .chain(test_cases_com.into_iter())
        .chain(test_cases_wel.into_iter())
        .chain(test_cases_rand.into_iter())
    {
        let crypto_provider = TestCryptoProvider::new();
        let Some(cs) = crypto_provider.cipher_suite_provider(test_case.cipher_suite.into()) else { continue };

        let message = MLSMessage::from_bytes(&test_case.key_package).unwrap();
        let key_package = message.into_key_package().unwrap();
        let id = key_package.leaf_node.signing_identity.clone();
        let key = test_case.signature_priv.clone().into();

        let mut client_builder = ClientBuilder::new()
            .crypto_provider(crypto_provider)
            .identity_provider(BasicIdentityProvider::new())
            .single_signing_identity(id, key, cs.cipher_suite());

        for psk in test_case.external_psks {
            client_builder = client_builder.psk(ExternalPskId::new(psk.psk_id), psk.psk.into());
        }

        let client = client_builder.build();

        let key_pckg_gen = KeyPackageGeneration {
            reference: key_package.to_reference(&cs).unwrap(),
            key_package,
            init_secret_key: test_case.init_priv.into(),
            leaf_node_secret_key: test_case.encryption_priv.into(),
        };

        let (id, pkg) = key_pckg_gen.to_storage().unwrap();
        client.config.key_package_repo().insert(id, pkg);

        let welcome = MLSMessage::from_bytes(&test_case.welcome).unwrap();
        let tree = test_case.ratchet_tree.as_ref().map(|t| t.0.as_slice());

        let (mut group, _info) = client.join_group(tree, welcome).await.unwrap();

        assert_eq!(
            group.epoch_authenticator().unwrap().to_vec(),
            test_case.initial_epoch_authenticator
        );

        for epoch in test_case.epochs {
            for proposal in epoch.proposals.iter() {
                let message = MLSMessage::from_bytes(&proposal.0).unwrap();
                group.process_incoming_message(message).await.unwrap();
            }

            let message = MLSMessage::from_bytes(&epoch.commit).unwrap();
            group.process_incoming_message(message).await.unwrap();

            assert_eq!(
                epoch.epoch_authenticator,
                group.epoch_authenticator().unwrap().to_vec()
            );
        }
    }
}
