use crate::client::MlsError;
use alloc::vec::Vec;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

pub type ComponentID = u32;

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
pub struct ComponentOperationLabel {
    label: Vec<u8>,
    component_id: ComponentID,
    context: Vec<u8>,
}

impl ComponentOperationLabel {
    pub fn get_bytes(&self) -> Result<Vec<u8>, MlsError> {
        self.mls_encode_to_vec().map_err(Into::into)
    }
}

impl ComponentOperationLabel {
    pub fn new(component_id: u32, context: Vec<u8>) -> Self {
        Self {
            label: b"MLS 1.0 Application".to_vec(),
            component_id,
            context,
        }
    }
}
