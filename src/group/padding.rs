use tls_codec::Size;

use super::framing::MLSCiphertextContent;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PaddingMode {
    StepFunction,
    None,
}

impl Default for PaddingMode {
    fn default() -> Self {
        PaddingMode::StepFunction
    }
}

impl PaddingMode {
    pub(super) fn apply_padding(&self, content: &mut MLSCiphertextContent) {
        content.padding.clear();
        match self {
            PaddingMode::StepFunction => {
                let original_length = content.tls_serialized_len();
                let padding = padding_length(original_length);
                content.padding.resize(padding, 0);
            }
            PaddingMode::None => {}
        }
    }
}

fn padding_length(length: usize) -> usize {
    if length < 8 {
        return 7 - length;
    }
    let bit_length: u32 = f32::log2(length as f32).ceil() as u32;
    let m = length % (1 << (bit_length - 3));
    (2_usize.pow(bit_length - 3) - 1) - m
}

#[cfg(test)]
mod tests {
    use ferriscrypt::rand::SecureRng;

    use crate::group::{
        framing::{Content, MLSCiphertextContent},
        message_signature::MLSMessageAuth,
    };

    use super::{padding_length, PaddingMode};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestCase {
        input: usize,
        output: usize,
    }

    fn test_ciphertext_content() -> MLSCiphertextContent {
        MLSCiphertextContent {
            content: Content::Application(SecureRng::gen(32).unwrap()),
            auth: MLSMessageAuth {
                signature: SecureRng::gen(64).unwrap().into(),
                confirmation_tag: None,
            },
            padding: vec![],
        }
    }

    fn generate_message_padding_test_vector() -> Vec<TestCase> {
        let mut test_cases = vec![];
        for x in 1..1024 {
            test_cases.push(TestCase {
                input: x,
                output: padding_length(x),
            });
        }
        test_cases
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(
            message_padding_test_vector,
            generate_message_padding_test_vector
        )
    }

    #[test]
    fn test_no_padding() {
        let mut ciphertext = test_ciphertext_content();
        let padding_mode = PaddingMode::None;
        padding_mode.apply_padding(&mut ciphertext);
        assert!(ciphertext.padding.is_empty())
    }

    #[test]
    fn test_padding_length() {
        let test_cases: Vec<TestCase> = load_test_cases();
        for test_case in test_cases {
            assert_eq!(test_case.output, padding_length(test_case.input));
        }
    }
}
