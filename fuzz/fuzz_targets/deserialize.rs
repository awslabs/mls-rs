#![no_main]
use aws_mls::{group::framing::MLSMessage, tls_codec::Deserialize};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = MLSMessage::tls_deserialize(&mut &*data);
});
