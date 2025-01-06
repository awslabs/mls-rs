// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::convert::Infallible;

use mls_rs::{
    client_builder::MlsConfig,
    error::MlsError,
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, KeyPackageStorage,
};
use mls_rs_core::key_package::KeyPackageData;

const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

fn main() -> Result<(), MlsError> {
    let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();

    // Create clients for Alice and Bob
    let alice = make_client(crypto_provider.clone(), "alice")?;
    let bob = make_client(crypto_provider.clone(), "bob")?;

    // Bob generates key package. We store secrets in memory, no need for any storage.
    let key_package_generation = bob
        .key_package_builder(CIPHERSUITE, None)?
        .valid_for_sec(123)
        .build()?;

    let stored_secrets = key_package_generation.key_package_data;

    // Alice creates a group with Bob.
    let mut alice_group = alice.create_group(ExtensionList::default(), Default::default())?;

    let welcomes = alice_group
        .commit_builder()
        .add_member(key_package_generation.key_package_message)?
        .build()?
        .welcome_messages;

    alice_group.apply_pending_commit()?;

    // Bob joins
    let mut bob_group = bob.group_joiner(&welcomes[0], stored_secrets)?.join()?.0;

    // Alice and bob can chat
    let msg = alice_group.encrypt_application_message(b"hello world", Default::default())?;
    let msg = bob_group.process_incoming_message(msg)?;

    println!("Received message: {:?}", msg);

    Ok(())
}

#[derive(Clone)]
struct NoOpKeyPackageStorage;

impl KeyPackageStorage for NoOpKeyPackageStorage {
    type Error = Infallible;

    fn delete(&mut self, _: &[u8]) -> Result<(), Infallible> {
        Ok(())
    }

    fn get(&self, _: &[u8]) -> Result<Option<KeyPackageData>, Infallible> {
        Ok(None)
    }

    fn insert(&mut self, _: Vec<u8>, _: KeyPackageData) -> Result<(), Infallible> {
        Ok(())
    }
}

fn make_client<P: CryptoProvider + Clone>(
    crypto_provider: P,
    name: &str,
) -> Result<Client<impl MlsConfig>, MlsError> {
    let cipher_suite = crypto_provider.cipher_suite_provider(CIPHERSUITE).unwrap();
    let (secret, public) = cipher_suite.signature_key_generate().unwrap();
    let basic_identity = BasicCredential::new(name.as_bytes().to_vec());
    let signing_identity = SigningIdentity::new(basic_identity.into_credential(), public);

    Ok(Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto_provider)
        .signing_identity(signing_identity, secret, CIPHERSUITE)
        .key_package_repo(NoOpKeyPackageStorage)
        .build())
}
