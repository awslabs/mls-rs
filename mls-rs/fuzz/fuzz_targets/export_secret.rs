// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![no_main]

mod export_secret {
    use libfuzzer_sys::{arbitrary, fuzz_target};
    use mls_rs::test_utils::fuzz_tests::GROUP;

    #[derive(Clone, Debug)]
    struct USize(usize);

    impl<'a> arbitrary::Arbitrary<'a> for USize {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            let x: usize = u.int_in_range(0..=4_000)?;

            Ok(Self(x))
        }
    }

    fuzz_target!(|data: (&str, &[u8], USize)| {
        let _ = GROUP
            .lock()
            .unwrap()
            .export_secret(data.0.as_bytes(), data.1, data.2 .0);
    });
}
