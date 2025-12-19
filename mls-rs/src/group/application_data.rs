use std::fmt;

use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs_core::extension::{ExtensionList, ExtensionType};

/// app_data_dictionary
pub const APPLICATION_DATA: ExtensionType = ExtensionType::new(0x0006);

#[derive(Clone, Debug, Default, PartialEq, Eq, MlsEncode, MlsDecode, MlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Application specific data
///
/// Application data allows applications to manage their data without registering a custom extension, by
/// storing it in components.
///
/// It may appear in the following places:
/// * GC: GroupContext objects
/// * LN: LeafNode objects
/// * GI: GroupInfo objects
/// * AD: SafeAAD objects
/// * AE: AppEphemeral proposals

pub struct ApplicationDataDictionary {
    pub component_data: Vec<ComponentData>,
}

pub fn application_data_from_extensions(
    extensions: &ExtensionList,
) -> Result<Option<ApplicationDataDictionary>, crate::mls_rs_codec::Error> {
    for extension in extensions.iter() {
        if extension.extension_type == APPLICATION_DATA {
            return Ok(Some(ApplicationDataDictionary::mls_decode(
                &mut &*extension.extension_data,
            )?));
        }
    }
    Ok(None)
}

#[derive(Clone, PartialEq, Eq, MlsEncode, MlsDecode, MlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A component stored under application data
///
/// Components are indexed by their component id. Each component specifies an update structure
/// used in `ApplicationDataUpdateProposal`
pub struct ComponentData {
    pub component_id: ComponentId,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "mls_rs_core::vec_serde"))]
    pub data: Vec<u8>,
}

impl fmt::Debug for ComponentData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComponentData")
            .field("component_id", &self.component_id)
            .field("data", &mls_rs_core::debug::pretty_bytes(&self.data))
            .finish()
    }
}

pub type ComponentId = u16;
