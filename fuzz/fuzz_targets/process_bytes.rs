#![no_main]
use libfuzzer_sys::fuzz_target;

use once_cell::sync::Lazy;

use aws_mls::bench_utils::group_functions::create_group;

use aws_mls::session::Session;

use aws_mls::client_config::InMemoryClientConfig;

use aws_mls::cipher_suite::CipherSuite;

use std::sync::Mutex;

static GROUP_DATA: Lazy<Mutex<Vec<Session<InMemoryClientConfig>>>> = Lazy::new(|| {
    let cipher_suite = CipherSuite::Curve25519Aes128;
    let (_, container) = create_group(cipher_suite, 2, false);

    Mutex::new(container)
});

fuzz_target!(|data: &[u8]| {
    let _ = GROUP_DATA.lock().unwrap()[1].process_incoming_bytes(data);
});
