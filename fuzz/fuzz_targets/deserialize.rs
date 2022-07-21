#![no_main]
use libfuzzer_sys::fuzz_target;

use aws_mls::session::MLSMessage;

use aws_mls::tls_codec::Deserialize;

fuzz_target!(|data: &[u8]| {
    let _ = MLSMessage::tls_deserialize(&mut &*data);
});
