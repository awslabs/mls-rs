use crate::{client::MlsError, group::ciphertext_processor::CiphertextProcessorError};

impl From<CiphertextProcessorError> for MlsError {
    fn from(e: CiphertextProcessorError) -> Self {
        if matches!(e, CiphertextProcessorError::CantProcessMessageFromSelf) {
            MlsError::CantProcessMessageFromSelf
        } else {
            MlsError::CiphertextProcessorError(e.into())
        }
    }
}
