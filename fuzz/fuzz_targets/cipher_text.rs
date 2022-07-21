#![no_main]
use libfuzzer_sys::fuzz_target;

use once_cell::sync::Lazy;

use aws_mls::bench_utils::group_functions::{create_group, plaintext_sign};

use aws_mls::session::{MLSMessage, MLSMessagePayload, Session};

use aws_mls::client_config::{InMemoryClientConfig, PaddingMode};

use aws_mls::cipher_suite::CipherSuite;

use aws_mls::ProtocolVersion;

use std::sync::Mutex;

use aws_mls::group::framing::{Content, MLSPlaintext, Sender};

use aws_mls::group::{Commit, Group};

use aws_mls::tree_kem::node::LeafIndex;

pub const CIPHER_SUITE: aws_mls::cipher_suite::CipherSuite = CipherSuite::Curve25519Aes128;
pub const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;

static GROUP_DATA: Lazy<Mutex<Vec<Session<InMemoryClientConfig>>>> = Lazy::new(|| {
    let (_, container) = create_group(CIPHER_SUITE, 2);

    Mutex::new(container)
});

fuzz_target!(|data: (Vec<u8>, u64, Vec<u8>)| {
    let plain_text = &mut MLSPlaintext::new(
        data.0,
        data.1,
        Sender::Member(LeafIndex::new(0)),
        Content::Commit(Commit {
            proposals: Vec::new(),
            path: None,
        }),
        data.2,
    );

    let signer = Session::signer(&GROUP_DATA.lock().unwrap()[0]).unwrap();

    plaintext_sign(plain_text, &GROUP_DATA.lock().unwrap()[0].protocol, &signer).unwrap();

    let cipher_text = Group::encrypt_plaintext(
        &mut GROUP_DATA.lock().unwrap()[0].protocol,
        plain_text.clone(),
        PaddingMode::StepFunction,
    )
    .unwrap();

    let message = MLSMessage {
        version: TEST_PROTOCOL_VERSION,
        payload: MLSMessagePayload::Cipher(cipher_text),
    };

    let _ = GROUP_DATA.lock().unwrap()[1].process_incoming_message(message);
});
