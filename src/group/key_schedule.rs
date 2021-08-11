use ferriscrypt::digest::HashFunction;
use ferriscrypt::hpke::KdfId;
use ferriscrypt::kdf::hkdf::Hkdf;
use ferriscrypt::kdf::KdfError;
use serde::Serialize;
use std::ops::Deref;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyScheduleKdfError {
    #[error(transparent)]
    HkdfError(#[from] KdfError),
    #[error(transparent)]
    SerializationError(#[from] bincode::Error),
}

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

#[derive(Clone, Debug)]
pub struct KeyScheduleKdf(Hkdf);

impl Deref for KeyScheduleKdf {
    type Target = Hkdf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl KeyScheduleKdf {
    pub fn new(kdf_id: KdfId) -> KeyScheduleKdf {
        let hkdf = match kdf_id {
            KdfId::HkdfSha256 => Hkdf::new(HashFunction::Sha256),
            KdfId::HkdfSha384 => Hkdf::new(HashFunction::Sha384),
            KdfId::HkdfSha512 => Hkdf::new(HashFunction::Sha512),
        };

        KeyScheduleKdf(hkdf)
    }

    pub fn expand_with_label(
        &self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, KeyScheduleKdfError> {
        let label = Label::new(self.extract_size() as u16, label, context);
        let label_bytes = bincode::serialize(&label)?;
        let mut buf = vec![0u8; len];
        self.expand(secret, &label_bytes, &mut buf)?;
        Ok(buf)
    }

    pub fn derive_secret(
        &self,
        secret: &[u8],
        label: &str,
    ) -> Result<Vec<u8>, KeyScheduleKdfError> {
        self.expand_with_label(secret, label, &[], self.extract_size())
    }

    pub fn derive_tree_secret(
        &self,
        secret: &[u8],
        label: &str,
        node: u32,
        generation: u32,
        len: usize,
    ) -> Result<Vec<u8>, KeyScheduleKdfError> {
        let tree_context = TreeContext { node, generation };
        let tree_context_bytes = bincode::serialize(&tree_context)?;
        self.expand_with_label(secret, label, &tree_context_bytes, len)
    }
}
