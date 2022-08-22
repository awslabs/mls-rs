#![no_main]
use aws_mls::bench_utils::group_functions::create_group;
use aws_mls::cipher_suite::CipherSuite;
use aws_mls::client_config::InMemoryClientConfig;
use aws_mls::group::Group;
use aws_mls::group::MLSMessage;
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use std::sync::Mutex;

pub const CIPHER_SUITE: aws_mls::cipher_suite::CipherSuite = CipherSuite::Curve25519Aes128;

static GROUP_DATA: Lazy<Mutex<Vec<Group<InMemoryClientConfig>>>> = Lazy::new(|| {
    let container = create_group(CIPHER_SUITE, 2);

    Mutex::new(container)
});

fuzz_target!(|data: MLSMessage| {
    let _ = GROUP_DATA.lock().unwrap()[1].process_incoming_message(data);
});
