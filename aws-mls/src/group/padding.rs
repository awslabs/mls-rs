use tls_codec::Size;

use super::framing::PrivateContentTBE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Padding used when sending an encrypted group message.
pub enum PaddingMode {
    /// Step function based on the size of the message being sent.
    /// The amount of padding used will increase with the size of the original
    /// message.
    StepFunction,
    /// No padding.
    None,
}

impl Default for PaddingMode {
    fn default() -> Self {
        PaddingMode::StepFunction
    }
}

impl PaddingMode {
    pub(super) fn apply_padding(&self, content: &mut PrivateContentTBE) {
        content.padding.clear();
        match self {
            PaddingMode::StepFunction => {
                let len = content.tls_serialized_len();
                content.padding.resize(step_padded_len(len) - len, 0);
            }
            PaddingMode::None => {}
        }
    }
}

// The padding hides all but 2 most significant bits of `length`. The hidden bits are replaced
// by zeros and then the next number is taken to make sure the message fits.
fn step_padded_len(length: usize) -> usize {
    let blind = 1 << ((length + 1).next_power_of_two().max(256).trailing_zeros() - 3);
    (length | (blind - 1)) + 1
}

#[cfg(test)]
mod tests {
    use crate::group::framing::test_utils::get_test_ciphertext_content;

    use super::{step_padded_len, PaddingMode};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestCase {
        input: usize,
        output: usize,
    }

    fn generate_message_padding_test_vector() -> Vec<TestCase> {
        let mut test_cases = vec![];
        for x in 1..1024 {
            test_cases.push(TestCase {
                input: x,
                output: step_padded_len(x),
            });
        }
        test_cases
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(
            message_padding_test_vector,
            generate_message_padding_test_vector()
        )
    }

    #[test]
    fn test_no_padding() {
        let mut ciphertext = get_test_ciphertext_content();
        let padding_mode = PaddingMode::None;
        padding_mode.apply_padding(&mut ciphertext);
        assert!(ciphertext.padding.is_empty())
    }

    #[test]
    fn test_padding_length() {
        assert_eq!(step_padded_len(0), 32);

        // Short
        assert_eq!(step_padded_len(63), 64);
        assert_eq!(step_padded_len(64), 96);
        assert_eq!(step_padded_len(65), 96);

        // Almost long and almost short
        assert_eq!(step_padded_len(127), 128);
        assert_eq!(step_padded_len(128), 160);
        assert_eq!(step_padded_len(129), 160);

        // One length from each of the 4 buckets between 256 and 512
        assert_eq!(step_padded_len(260), 320);
        assert_eq!(step_padded_len(330), 384);
        assert_eq!(step_padded_len(390), 448);
        assert_eq!(step_padded_len(490), 512);

        // All test cases
        let test_cases: Vec<TestCase> = load_test_cases();
        for test_case in test_cases {
            assert_eq!(test_case.output, step_padded_len(test_case.input));
        }
    }
}
