use tls_codec::Size;

use super::framing::MLSCiphertextContent;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PaddingMode {
    StepFunction(usize),
    None,
}

impl Default for PaddingMode {
    fn default() -> Self {
        PaddingMode::StepFunction(32)
    }
}

impl PaddingMode {
    pub(super) fn apply_padding(&self, content: &mut MLSCiphertextContent) {
        content.padding.clear();
        match self {
            PaddingMode::StepFunction(step_size) => {
                let original_length = content.tls_serialized_len();
                let padding = (step_size - original_length % step_size) % step_size;
                let padding = padding_length(padding, *step_size);
                content.padding.resize(padding, 0);
            }
            PaddingMode::None => {}
        }
    }
}

fn padding_length(target: usize, step: usize) -> usize {
    match target {
        0..=63 => target,
        65..=16384 => target - 1,
        64 | 16385 | 16386 => padding_length(target + step, step),
        _ => target - 3, // For `16387..` but rustc insists that the match is not exhaustive.
    }
}

#[cfg(test)]
mod tests {
    use ferriscrypt::rand::SecureRng;

    use crate::group::{
        framing::{Content, MLSCiphertextContent},
        message_signature::MLSMessageAuth,
    };

    use super::PaddingMode;
    use tls_codec::Size;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

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

    #[test]
    fn test_step_function_padding() {
        let mut ciphertext = test_ciphertext_content();
        let padding_mode = PaddingMode::StepFunction(42);
        padding_mode.apply_padding(&mut ciphertext);
        assert_eq!(ciphertext.tls_serialized_len() % 42, 0);
        assert!(ciphertext.padding.len() < 42);
    }

    #[test]
    fn test_no_padding() {
        let mut ciphertext = test_ciphertext_content();
        let padding_mode = PaddingMode::None;
        padding_mode.apply_padding(&mut ciphertext);
        assert!(ciphertext.padding.is_empty())
    }
}
