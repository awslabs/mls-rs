// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![no_main]

mod deserialize {
    use libfuzzer_sys::fuzz_target;
    use mls_rs::{mls_rs_codec::MlsDecode, MlsMessage};

    fuzz_target!(|data: &[u8]| {
        let _ = MlsMessage::mls_decode(&mut &*data);
    });
}
