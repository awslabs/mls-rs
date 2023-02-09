#![no_main]
use aws_mls::bench_utils::group_functions::create_group;
use aws_mls::client_builder::test_utils::TestClientConfig;
use aws_mls::group::{Group, MLSMessage};
use aws_mls::CipherSuite;
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use std::sync::Mutex;

pub const CIPHER_SUITE: aws_mls::CipherSuite = CipherSuite::CURVE25519_AES128;

static GROUP_DATA: Lazy<Mutex<Vec<Group<TestClientConfig>>>> = Lazy::new(|| {
    let container = block_on(create_group(CIPHER_SUITE, 2));
    Mutex::new(container)
});

fuzz_target!(|data: MLSMessage| {
    let _ = block_on(GROUP_DATA.lock().unwrap()[1].process_incoming_message(data));
});
