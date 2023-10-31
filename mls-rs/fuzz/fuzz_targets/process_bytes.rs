// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![no_main]

mod process_bytes {
    use libfuzzer_sys::fuzz_target;
    use mls_rs::mls_rs_codec::MlsDecode;
    use mls_rs::test_utils::fuzz_tests::GROUP;
    use mls_rs::MlsMessage;

    fuzz_target!(|data: &[u8]| {
        if let Ok(message) = MlsMessage::mls_decode(&mut &*data) {
            GROUP.lock().unwrap().process_incoming_message(message).ok();
        }
    });
}
