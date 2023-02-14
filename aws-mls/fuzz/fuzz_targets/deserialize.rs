#![no_main]
use aws_mls::{tls_codec::Deserialize, MLSMessage};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = MLSMessage::tls_deserialize(&mut &*data);
});
