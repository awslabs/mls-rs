// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

//! 🔐 Cryptographic Security Showcase
//!
//! This example demonstrates advanced MLS cryptographic properties:
//! - Forward Secrecy & Post-Compromise Security
//! - Key Rotation and Epoch Evolution
//! - Compromise Recovery Scenarios

use assert_matches::assert_matches;
use mls_rs::{
    client_builder::{MlsConfig, PaddingMode},
    crypto::SignatureSecretKey,
    error::MlsError,
    group::ReceivedMessage,
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    mls_rules::{CommitOptions, DefaultMlsRules, EncryptionOptions},
    psk::{ExternalPskId, PreSharedKey},
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, PreSharedKeyStorage,
};

const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

fn create_identity(name: &str) -> (SigningIdentity, SignatureSecretKey) {
    let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();
    let cs_provider = crypto_provider.cipher_suite_provider(CIPHERSUITE).unwrap();
    let (secret, public) = cs_provider.signature_key_generate().unwrap();
    let credential = BasicCredential::new(name.as_bytes().to_vec());
    let signing_identity = SigningIdentity::new(credential.into_credential(), public);
    (signing_identity, secret)
}

fn create_client(name: &str) -> Client<impl MlsConfig> {
    let (signing_identity, secret_key) = create_identity(name);

    Client::builder()
        .crypto_provider(mls_rs_crypto_openssl::OpensslCryptoProvider::default())
        .identity_provider(BasicIdentityProvider)
        .mls_rules(
            DefaultMlsRules::new()
                .with_encryption_options(EncryptionOptions::new(true, PaddingMode::StepFunction))
                .with_commit_options(CommitOptions::new().with_path_required(true)),
        )
        .signing_identity(signing_identity, secret_key, CIPHERSUITE)
        .build()
}

fn main() -> Result<(), MlsError> {
    // 🔐 Create three MLS clients with unique identities
    let ann = create_client("📡");
    let carl = create_client("🚗");
    let lara = create_client("💻");

    let lara_kp =
        lara.generate_key_package_message(Default::default(), Default::default(), None)?;

    let ann_kp = ann.generate_key_package_message(Default::default(), Default::default(), None)?;

    // 🏗️ Carl 🚗 creates initial group (Epoch 0)
    let mut carl_group = carl.create_group(Default::default(), Default::default(), None)?;

    // ➕ Group evolution: Carl 🚗 adds Lara 💻 and Ann 📡 (Epoch 0 → 1)
    let commit_output = carl_group
        .commit_builder()
        .add_member(lara_kp)?
        .add_member(ann_kp)?
        .build()?;

    carl_group.apply_pending_commit()?;
    let welcome = &commit_output.welcome_messages[0];

    // 🤝 New members join using Welcome messages
    let (mut lara_group, _info) = lara.join_group(None, welcome, None)?;
    let (ann_group, _info) = ann.join_group(None, welcome, None)?;

    // 🔑 Demonstrate shared cryptographic state across all group members
    // All clients derive identical secrets from the same group key material
    let carl_secret = carl_group.export_secret(b"HKDF label", b"HKDF info", 32)?;
    let lara_secret = lara_group.export_secret(b"HKDF label", b"HKDF info", 32)?;
    let ann_secret = ann_group.export_secret(b"HKDF label", b"HKDF info", 32)?;
    assert_eq!(carl_secret, lara_secret);
    assert_eq!(carl_secret, ann_secret);

    // 💬 End-to-end encrypted messaging with authentication
    let msg =
        carl_group.encrypt_application_message(b"Hello, world!", b"authenticated data".into())?;

    // 🔓 Lara decrypts and verifies the message
    let lara_msg = lara_group.process_incoming_message(msg)?;

    match lara_msg {
        ReceivedMessage::ApplicationMessage(msg) => {
            assert_eq!(msg.data(), b"Hello, world!");
            assert_eq!(msg.authenticated_data, b"authenticated data");
            assert_eq!(msg.sender_index, 0); // Carl is sender (index 0)
        }
        _ => {
            panic!("Expected application message");
        }
    };

    // ➖ Group evolution: Carl removes Ann
    let commit_output = carl_group.commit_builder().remove_member(2)?.build()?;
    carl_group.apply_pending_commit()?;
    lara_group.process_incoming_message(commit_output.commit_message)?;
    assert_eq!(lara_group.roster().members().len(), 2); // Now only Carl + Lara

    // 🔄 Key rotation: Carl proposes key update for forward secrecy
    let proposal = carl_group.propose_update(vec![])?;
    lara_group.process_incoming_message(proposal)?;

    // Lara commits the key update proposal
    let commit_output = lara_group.commit(vec![])?;
    lara_group.apply_pending_commit()?;
    carl_group.process_incoming_message(commit_output.commit_message)?;

    // 🔐 Pre-Shared Key (PSK) injection for enhanced security
    let psk_id = ExternalPskId::new(b"PSK ID".to_vec());
    let psk = PreSharedKey::new(b"shared secret value".to_vec());

    // 💾 Both clients store the PSK in their secret stores
    lara.secret_store()
        .insert(psk_id.clone(), psk.clone())
        .unwrap();

    carl.secret_store()
        .insert(psk_id.clone(), psk.clone())
        .unwrap();

    // 🔄 Lara commits the PSK to the group
    let commit_output = lara_group
        .commit_builder()
        .add_external_psk(psk_id)?
        .build()?;

    // 📨 Carl processes the PSK commit message
    carl_group.process_incoming_message(commit_output.commit_message)?;

    // 🧟‍♀️ Zoe joins via external commit (no invitation needed!)
    let zoe = create_client("🧟‍♀️");
    let group_info = carl_group.group_info_message_allowing_ext_commit(true)?;
    let (mut zoe_group, external_commit) = zoe.commit_external(group_info)?;
    carl_group.process_incoming_message(external_commit)?;

    let msg = zoe_group.encrypt_application_message(b"hello", vec![])?;
    let carl_msg = carl_group.process_incoming_message(msg)?;
    assert_matches!(carl_msg, ReceivedMessage::ApplicationMessage(text) if text.data() == b"hello");

    Ok(())
}
