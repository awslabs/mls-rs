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
        match self {
            PaddingMode::StepFunction(step_size) => {
                let original_length = content.tls_serialized_len();
                let padding_length = original_length % step_size;
                content.padding = vec![0u8; padding_length];
            }
            PaddingMode::None => content.padding = vec![],
        }
    }
}

#[cfg(test)]
mod test {
    use ferriscrypt::rand::SecureRng;

    use crate::group::{
        framing::{Content, MLSCiphertextContent},
        message_signature::MLSMessageAuth,
    };

    use super::PaddingMode;

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
        assert_eq!(ciphertext.padding.len(), 21);
    }

    #[test]
    fn test_no_padding() {
        let mut ciphertext = test_ciphertext_content();
        let padding_mode = PaddingMode::None;
        padding_mode.apply_padding(&mut ciphertext);
        assert!(ciphertext.padding.is_empty())
    }
}
