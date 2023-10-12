#![no_main]

#[cfg(sync)]
mod application_data {
    use aws_mls::test_utils::fuzz_tests::GROUP;

    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|data: (&[u8], Vec<u8>)| {
        let _ = GROUP
            .lock()
            .unwrap()
            .encrypt_application_message(data.0, data.1);
    });
}
