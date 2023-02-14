#![no_main]
use aws_mls::bench_utils::group_functions::{create_group, TestClientConfig};
use aws_mls::tls_codec::Deserialize;
use aws_mls::Group;
use aws_mls::{CipherSuite, MLSMessage};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use std::sync::Mutex;

static GROUP_DATA: Lazy<Mutex<Vec<Group<TestClientConfig>>>> = Lazy::new(|| {
    let cipher_suite = CipherSuite::CURVE25519_AES128;
    let container = block_on(create_group(cipher_suite, 2));
    Mutex::new(container)
});

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = MLSMessage::tls_deserialize(&mut &*data) {
        block_on(GROUP_DATA.lock().unwrap()[1].process_incoming_message(message)).ok();
    }
});
