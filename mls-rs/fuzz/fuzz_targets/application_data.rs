// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![no_main]

mod application_data {
    use mls_rs::test_utils::fuzz_tests::GROUP;

    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|data: (&[u8], Vec<u8>)| {
        let _ = GROUP
            .lock()
            .unwrap()
            .encrypt_application_message(data.0, data.1);
    });
}
