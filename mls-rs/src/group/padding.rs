// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

/// Padding used when sending an encrypted group message.
#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::ffi_type)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PaddingMode {
    /// Step function based on the size of the message being sent.
    /// The amount of padding used will increase with the size of the original
    /// message.
    #[default]
    StepFunction,
    /// Padme, which limits information leakage to O(log log M) bits while
    /// retaining an overhead of max 11.11%, defined as Algorithm 1 in
    /// https://www.petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf.
    Padme,
    /// No padding.
    None,
}

impl PaddingMode {
    pub(super) fn padded_size(&self, content_size: usize) -> usize {
        match self {
            PaddingMode::StepFunction => {
                // The padding hides all but 2 most significant bits of `length`. The hidden bits are replaced
                // by zeros and then the next number is taken to make sure the message fits.
                let blind = 1
                    << ((content_size + 1)
                        .next_power_of_two()
                        .max(256)
                        .trailing_zeros()
                        - 3);

                (content_size | (blind - 1)) + 1
            }
            PaddingMode::Padme => {
                // Prevents log2(0), which is undefined.
                if content_size < 2 {
                    return content_size;
                }

                // E <- floor(log2(L))
                // S <- floor(log2(E)) + 1
                // z <- E - S
                // m <- (1 << z) - 1
                // len' <- (L + m) & ~m

                let e: u32 = content_size.ilog2(); // l’s floating-point exponent
                let s: u32 = e.ilog2() + 1; // number of bits to represent e
                let num_zero_bits: u32 = e - s; // number of low bits to set to 0
                let bitmask: usize = (1 << num_zero_bits) - 1; // create a bitmask of 1s
                (content_size + bitmask) & !bitmask // len': round up to clear last num_zero_bits bits
            }
            PaddingMode::None => content_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PaddingMode;

    use alloc::vec;
    use alloc::vec::Vec;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestCase {
        input: usize,
        output: usize,
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn generate_message_padding_test_vector() -> Vec<TestCase> {
        let mut test_cases = vec![];
        for x in 1..1024 {
            test_cases.push(TestCase {
                input: x,
                output: PaddingMode::StepFunction.padded_size(x),
            });
        }
        test_cases
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_case_json!(
            message_padding_test_vector,
            generate_message_padding_test_vector()
        )
    }

    #[test]
    fn test_no_padding() {
        for i in [0, 100, 1000, 10000] {
            assert_eq!(PaddingMode::None.padded_size(i), i)
        }
    }

    #[test]
    fn test_step_function() {
        assert_eq!(PaddingMode::StepFunction.padded_size(0), 32);

        // Short
        assert_eq!(PaddingMode::StepFunction.padded_size(63), 64);
        assert_eq!(PaddingMode::StepFunction.padded_size(64), 96);
        assert_eq!(PaddingMode::StepFunction.padded_size(65), 96);

        // Almost long and almost short
        assert_eq!(PaddingMode::StepFunction.padded_size(127), 128);
        assert_eq!(PaddingMode::StepFunction.padded_size(128), 160);
        assert_eq!(PaddingMode::StepFunction.padded_size(129), 160);

        // One length from each of the 4 buckets between 256 and 512
        assert_eq!(PaddingMode::StepFunction.padded_size(260), 320);
        assert_eq!(PaddingMode::StepFunction.padded_size(330), 384);
        assert_eq!(PaddingMode::StepFunction.padded_size(390), 448);
        assert_eq!(PaddingMode::StepFunction.padded_size(490), 512);

        // All test cases
        let test_cases: Vec<TestCase> = load_test_cases();
        for test_case in test_cases {
            assert_eq!(
                test_case.output,
                PaddingMode::StepFunction.padded_size(test_case.input)
            );
        }
    }

    #[test]
    fn test_padme_exceptions() {
        assert_eq!(PaddingMode::Padme.padded_size(0), 0);
        assert_eq!(PaddingMode::Padme.padded_size(1), 1);
    }

    // All values are computed using reference implementation found at
    // https://lbarman.ch/blog/padme/#implementation.
    #[test]
    fn test_padme_powers_of_two() {
        for i in 0u32..32 {
            let val = 2usize.pow(i);
            assert_eq!(PaddingMode::Padme.padded_size(val), val);
        }
    }
    #[test]
    fn test_padme_powers_of_ten() {
        let res: [usize; 10] = [
            1, 10, 104, 1024, 10240, 100352, 1015808, 10223616, 100663296, 1006632960,
        ];
        for (i, result) in res.iter().enumerate() {
            assert_eq!(
                PaddingMode::Padme.padded_size(10usize.pow(i as u32)),
                *result
            );
        }
    }

    #[test]
    fn test_padme_rand() {
        let vec = [
            (441181141, 444596224),
            (942823001, 956301312),
            (1017891638, 1023410176),
            (1045008200, 1056964608),
            (2068479553, 2080374784),
            (2096246256, 2113929216),
            (2523113277, 2550136832),
            (3011885937, 3019898880),
            (3212797841, 3221225472),
            (3886482937, 3892314112),
        ];
        for (val, res) in vec.iter() {
            assert_eq!(PaddingMode::Padme.padded_size(*val), *res);
        }
    }
}
