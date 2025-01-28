use crate::client::MlsError;
use crate::tree_kem::hpke_encryption::HpkeEncryptable;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

pub type ComponentID = u32;

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
pub struct ComponentOperationLabel {
    component_id: ComponentID,
    context: Vec<u8>,
}

impl HpkeEncryptable for ComponentOperationLabel {
    const ENCRYPT_LABEL: &'static str = "MLS 1.0 Application";

    fn from_bytes(bytes: Vec<u8>) -> Result<Self, MlsError> {
        Self::mls_decode(&mut bytes.as_slice()).map_err(Into::into)
    }

    fn get_bytes(&self) -> Result<Vec<u8>, MlsError> {
        self.mls_encode_to_vec().map_err(Into::into)
    }
}

impl ComponentOperationLabel {
    pub fn new(component_id: u32, context: Vec<u8>) -> Self {
        Self {
            component_id,
            context,
        }
    }
}
