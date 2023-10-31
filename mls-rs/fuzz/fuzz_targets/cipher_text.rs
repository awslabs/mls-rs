// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![no_main]

mod ciphertext {
    use libfuzzer_sys::fuzz_target;
    use mls_rs::test_utils::fuzz_tests::{create_fuzz_commit_message, GROUP};

    fuzz_target!(|data: (Vec<u8>, u64, Vec<u8>)| {
        let message = create_fuzz_commit_message(data.0, data.1, data.2).unwrap();

        let _ = GROUP.lock().unwrap().process_incoming_message(message);
    });
}
