// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![no_main]

mod mls_message {
    use aws_mls::test_utils::fuzz_tests::GROUP;
    use aws_mls::MLSMessage;
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|data: MLSMessage| {
        let _ = GROUP.lock().unwrap().process_incoming_message(data);
    });
}
