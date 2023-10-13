// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![no_main]

mod deserialize {
    use aws_mls::{aws_mls_codec::MlsDecode, MLSMessage};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|data: &[u8]| {
        let _ = MLSMessage::mls_decode(&mut &*data);
    });
}
