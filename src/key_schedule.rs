use crate::kdf::{Kdf, KdfError};
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct Label<'a> {
    length: u16,
    label: String,
    context: &'a [u8],
}

impl<'a> Label<'a> {
    fn new(length: u16, label: &'a str, context: &'a [u8]) -> Self {
        Self {
            length,
            label: ["mls10 ", label].concat(),
            context,
        }
    }
}

#[derive(Serialize)]
struct TreeContext {
    node: u32,
    generation: u32,
}

pub trait KeyScheduleKdf: Kdf {
    fn expand_with_label(
        secret: &[u8],
        label: &str,
        context: &[u8],
        len: u16,
    ) -> Result<Vec<u8>, KdfError> {
        let label = Label::new(Self::EXTRACT_SIZE, label, context);
        let label_bytes = bincode::serialize(&label).map_err(|e| KdfError::Other(e.to_string()))?;
        Self::expand(secret, &label_bytes, len)
    }

    fn derive_secret(secret: &[u8], label: &str) -> Result<Vec<u8>, KdfError> {
        Self::expand_with_label(secret, &label, &[], Self::EXTRACT_SIZE)
    }

    fn derive_tree_secret(
        secret: &[u8],
        label: &str,
        node: u32,
        generation: u32,
        len: u16,
    ) -> Result<Vec<u8>, KdfError> {
        let tree_context = TreeContext { node, generation };

        let tree_context_bytes =
            bincode::serialize(&tree_context).map_err(|e| KdfError::Other(e.to_string()))?;

        Self::expand_with_label(secret, label, &tree_context_bytes, len)
    }
}

impl KeyScheduleKdf for crate::kdf::HkdfSha256 {}
impl KeyScheduleKdf for crate::kdf::HkdfSha512 {}

#[cfg(test)]
pub mod test_util {
    use super::{Kdf, KdfError, KeyScheduleKdf};
    use crate::kdf::KdfId;
    use mockall::mock;

    mock! {
        pub TestKeyScheduleKdf {}

        impl Kdf for TestKeyScheduleKdf {
            const KDF_ID: KdfId = KdfId::Test;
            const EXTRACT_SIZE: u16 = 42;

            // RFC 5869 Extract-and-Expand HKDF
            fn extract(salt: &[u8], key: &[u8]) -> Result<Vec<u8>, KdfError>;

            // RFC 5869 Extract-and-Expand HKDF
            fn expand(key: &[u8], info: &[u8], out_len: u16) -> Result<Vec<u8>, KdfError>;
        }

        impl KeyScheduleKdf for TestKeyScheduleKdf {
            fn derive_secret(secret: &[u8], label: &str) -> Result<Vec<u8>, KdfError>;
        }
    }
}
