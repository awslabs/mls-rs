// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![no_main]

mod mls_message {
    use libfuzzer_sys::fuzz_target;
    use mls_rs::test_utils::fuzz_tests::GROUP;
    use mls_rs::MlsMessage;

    fuzz_target!(|data: MlsMessage| {
        let _ = GROUP.lock().unwrap().process_incoming_message(data);
    });
}
