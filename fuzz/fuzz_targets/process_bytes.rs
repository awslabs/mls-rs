#![no_main]
use aws_mls::bench_utils::group_functions::create_group;
use aws_mls::cipher_suite::CipherSuite;
use aws_mls::client_config::InMemoryClientConfig;
use aws_mls::group::framing::MLSMessage;
use aws_mls::group::{Group, GroupError};
use aws_mls::tls_codec::Deserialize;
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use std::sync::Mutex;

static GROUP_DATA: Lazy<Mutex<Vec<Group<InMemoryClientConfig>>>> = Lazy::new(|| {
    let cipher_suite = CipherSuite::Curve25519Aes128;
    let (_, container) = create_group(cipher_suite, 2, false);

    Mutex::new(container)
});

fuzz_target!(|data: &[u8]| {
    let _ = MLSMessage::tls_deserialize(&mut &*data)
        .map_err(GroupError::from)
        .and_then(|message| GROUP_DATA.lock().unwrap()[1].process_incoming_message(message));
});
