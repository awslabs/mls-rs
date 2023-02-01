#![no_main]

use aws_mls::bench_utils::group_functions::{create_fuzz_commit_message, create_group};
use aws_mls::client::test_utils::TestClientConfig;
use aws_mls::group::Group;
use aws_mls::provider::crypto::CURVE25519_AES128;
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use std::sync::Mutex;

pub const CIPHER_SUITE: aws_mls::cipher_suite::CipherSuite = CURVE25519_AES128;

static GROUP_DATA: Lazy<Mutex<Vec<Group<TestClientConfig>>>> = Lazy::new(|| {
    let container = block_on(create_group(CIPHER_SUITE, 2));
    Mutex::new(container)
});

fuzz_target!(|data: (Vec<u8>, u64, Vec<u8>)| {
    let mut groups = GROUP_DATA.lock().unwrap();

    let message = block_on(create_fuzz_commit_message(
        data.0,
        data.1,
        data.2,
        &mut groups[0],
    ))
    .unwrap();

    let _ = block_on(groups[1].process_incoming_message(message));
});
