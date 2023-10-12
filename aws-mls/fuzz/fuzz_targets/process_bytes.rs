#![no_main]

#[cfg(sync)]
mod process_bytes {
    use aws_mls::aws_mls_codec::MlsDecode;
    use aws_mls::test_utils::fuzz_tests::GROUP;
    use aws_mls::MLSMessage;
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|data: &[u8]| {
        if let Ok(message) = MLSMessage::mls_decode(&mut &*data) {
            GROUP.lock().unwrap().process_incoming_message(message).ok();
        }
    });
}
