use crate::credential::CredentialType;
use crate::group::proposal::ProposalType;
use crate::tls::ReadWithCount;
use crate::tree_kem::node::NodeVec;
use ferriscrypt::hpke::kem::HpkePublicKey;
use indexmap::IndexMap;
use std::io::{Read, Write};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum ExtensionError {
    #[error("Unexpected extension type: {0}, expected: {1}")]
    UnexpectedExtensionType(ExtensionType, ExtensionType),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
}

pub type ExtensionType = u16;

const APPLICATION_ID_EXT_ID: ExtensionType = 1;
const RATCHET_TREE_EXT_ID: ExtensionType = 2;
const REQUIRED_CAPABILITIES_EXT_ID: ExtensionType = 3;
const EXTERNAL_PUB_EXT_ID: ExtensionType = 4;

pub trait MlsExtension: Sized + Serialize + Deserialize {
    const IDENTIFIER: ExtensionType;

    fn to_extension(&self) -> Result<Extension, ExtensionError> {
        Ok(Extension {
            extension_type: Self::IDENTIFIER,
            extension_data: self.tls_serialize_detached()?,
        })
    }

    fn from_extension(extension: Extension) -> Result<Self, ExtensionError> {
        if extension.extension_type != Self::IDENTIFIER {
            Err(ExtensionError::UnexpectedExtensionType(
                extension.extension_type,
                Self::IDENTIFIER,
            ))
        } else {
            Self::tls_deserialize(&mut &*extension.extension_data).map_err(|e| e.into())
        }
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct ApplicationIdExt {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub identifier: Vec<u8>,
}

impl MlsExtension for ApplicationIdExt {
    const IDENTIFIER: ExtensionType = APPLICATION_ID_EXT_ID;
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct RatchetTreeExt {
    pub(crate) tree_data: NodeVec,
}

impl MlsExtension for RatchetTreeExt {
    const IDENTIFIER: ExtensionType = RATCHET_TREE_EXT_ID;
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize, Default)]
pub struct RequiredCapabilitiesExt {
    #[tls_codec(with = "crate::tls::DefVec")]
    pub extensions: Vec<ExtensionType>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub proposals: Vec<ProposalType>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub credentials: Vec<CredentialType>,
}

impl MlsExtension for RequiredCapabilitiesExt {
    const IDENTIFIER: ExtensionType = REQUIRED_CAPABILITIES_EXT_ID;
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct ExternalPubExt {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub external_pub: HpkePublicKey,
}

impl MlsExtension for ExternalPubExt {
    const IDENTIFIER: ExtensionType = EXTERNAL_PUB_EXT_ID;
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct Extension {
    pub extension_type: ExtensionType,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub extension_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Default, serde::Deserialize, serde::Serialize)]
pub struct ExtensionList(#[serde(with = "indexmap::serde_seq")] IndexMap<ExtensionType, Extension>);

impl Size for ExtensionList {
    fn tls_serialized_len(&self) -> usize {
        (self.len() as u32).tls_serialized_len()
            + self
                .iter()
                .map(|ext| ext.tls_serialized_len())
                .sum::<usize>()
    }
}

impl Serialize for ExtensionList {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let len = self
            .iter()
            .map(|ext| ext.tls_serialized_len())
            .sum::<usize>() as u32;
        self.iter()
            .try_fold(len.tls_serialize(writer)?, |acc, ext| {
                Ok(acc + ext.tls_serialize(writer)?)
            })
    }
}

impl Deserialize for ExtensionList {
    fn tls_deserialize<R: Read>(reader: &mut R) -> Result<Self, tls_codec::Error> {
        let len = u32::tls_deserialize(reader)? as usize;
        let reader = &mut ReadWithCount::new(reader);
        let mut items = IndexMap::new();
        while reader.bytes_read() < len {
            let ext = Extension::tls_deserialize(reader)?;
            let ext_type = ext.extension_type;
            if items.insert(ext_type, ext).is_some() {
                return Err(tls_codec::Error::DecodingError(format!(
                    "Extension list has duplicate extension of type {ext_type}"
                )));
            }
        }
        Ok(ExtensionList(items))
    }
}

impl From<Vec<Extension>> for ExtensionList {
    fn from(v: Vec<Extension>) -> Self {
        Self(v.into_iter().map(|ext| (ext.extension_type, ext)).collect())
    }
}

impl<'a> IntoIterator for &'a ExtensionList {
    type Item = &'a Extension;
    type IntoIter = ExtensionListIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        ExtensionListIter(self.0.values())
    }
}

pub struct ExtensionListIter<'a>(indexmap::map::Values<'a, ExtensionType, Extension>);

impl<'a> Iterator for ExtensionListIter<'a> {
    type Item = &'a Extension;

    fn next(&mut self) -> Option<&'a Extension> {
        self.0.next()
    }
}

impl ExtensionList {
    pub fn new() -> ExtensionList {
        Default::default()
    }

    pub fn get_extension<T: MlsExtension>(&self) -> Result<Option<T>, ExtensionError> {
        Ok(self
            .0
            .get(&T::IDENTIFIER)
            .map(|ext| T::tls_deserialize(&mut &*ext.extension_data))
            .transpose()?)
    }

    pub fn has_extension(&self, ext_id: ExtensionType) -> bool {
        self.0.contains_key(&ext_id)
    }

    pub fn set_extension<T: MlsExtension>(&mut self, ext: T) -> Result<(), ExtensionError> {
        let ext = ext.to_extension()?;
        self.0.insert(ext.extension_type, ext);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> ExtensionListIter<'_> {
        self.into_iter()
    }

    pub fn remove(&mut self, ext_type: ExtensionType) {
        self.0.shift_remove(&ext_type);
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;

    #[derive(TlsSize, TlsSerialize, TlsDeserialize, Clone, Debug, PartialEq)]
    pub(crate) struct TestExtension {
        pub(crate) foo: u8,
    }

    impl MlsExtension for TestExtension {
        const IDENTIFIER: crate::extension::ExtensionType = 42;
    }
}

#[cfg(test)]
mod tests {
    use crate::credential::CREDENTIAL_TYPE_BASIC;

    use super::*;
    use assert_matches::assert_matches;
    use ferriscrypt::rand::SecureRng;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_key_id_extension() {
        let test_id = vec![0u8; 32];
        let test_extension = ApplicationIdExt {
            identifier: test_id.clone(),
        };

        let as_extension = test_extension.to_extension().unwrap();
        assert_eq!(as_extension.extension_type, ApplicationIdExt::IDENTIFIER);

        let restored = ApplicationIdExt::from_extension(as_extension).unwrap();
        assert_eq!(restored.identifier, test_id);
    }

    #[test]
    fn test_ratchet_tree() {
        let ext = RatchetTreeExt {
            tree_data: NodeVec::from(vec![None, None]),
        };

        let as_extension = ext.to_extension().unwrap();
        assert_eq!(as_extension.extension_type, RatchetTreeExt::IDENTIFIER);

        let restored = RatchetTreeExt::from_extension(as_extension).unwrap();
        assert_eq!(ext, restored)
    }

    #[test]
    fn test_required_capabilities() {
        let ext = RequiredCapabilitiesExt {
            extensions: vec![0u16, 1u16],
            proposals: vec![42.into(), 43.into()],
            credentials: vec![CREDENTIAL_TYPE_BASIC],
        };

        let as_extension = ext.to_extension().unwrap();
        assert_eq!(
            as_extension.extension_type,
            RequiredCapabilitiesExt::IDENTIFIER
        );

        let restored = RequiredCapabilitiesExt::from_extension(as_extension).unwrap();
        assert_eq!(ext, restored)
    }

    #[test]
    fn test_bad_deserialize_data() {
        let bad_data = vec![255u8; 32];
        let test_extension = Extension {
            extension_type: APPLICATION_ID_EXT_ID,
            extension_data: bad_data,
        };

        let capabilities: Result<ApplicationIdExt, ExtensionError> =
            ApplicationIdExt::from_extension(test_extension);

        assert!(capabilities.is_err());
    }

    #[test]
    fn test_bad_deserialize_type() {
        let test_extension = Extension {
            extension_type: RatchetTreeExt::IDENTIFIER,
            extension_data: vec![0u8; 32],
        };
        assert!(ApplicationIdExt::from_extension(test_extension).is_err());
    }

    #[test]
    fn test_extension_list_get_set() {
        let mut list = ExtensionList::new();

        let required_capabilities = RequiredCapabilitiesExt::default();

        let key_id = ApplicationIdExt {
            identifier: SecureRng::gen(32).unwrap(),
        };

        // Add the extensions to the list
        list.set_extension(required_capabilities.clone()).unwrap();
        list.set_extension(key_id.clone()).unwrap();

        assert_eq!(list.len(), 2);

        assert_eq!(
            list.get_extension::<RequiredCapabilitiesExt>().unwrap(),
            Some(required_capabilities)
        );

        assert_eq!(
            list.get_extension::<ApplicationIdExt>().unwrap(),
            Some(key_id)
        );

        assert_eq!(list.get_extension::<RatchetTreeExt>().unwrap(), None);

        // Overwrite the extension in the list
        let key_id = ApplicationIdExt {
            identifier: SecureRng::gen(32).unwrap(),
        };

        list.set_extension(key_id.clone()).unwrap();
        assert_eq!(list.len(), 2);

        assert_eq!(
            list.get_extension::<ApplicationIdExt>().unwrap(),
            Some(key_id.clone())
        );

        assert_eq!(
            list.get_extension::<ApplicationIdExt>().unwrap(),
            Some(key_id)
        );

        assert_eq!(list.get_extension::<RatchetTreeExt>().unwrap(), None);
    }

    #[test]
    fn test_extension_list_has_ext() {
        let mut list = ExtensionList::new();

        let lifetime = ApplicationIdExt {
            identifier: SecureRng::gen(32).unwrap(),
        };

        list.set_extension(lifetime).unwrap();

        assert!(list.has_extension(ApplicationIdExt::IDENTIFIER));
        assert!(!list.has_extension(42));
    }

    #[test]
    fn extension_list_serialization_roundtrips() {
        let mut extensions = ExtensionList::default();

        extensions
            .set_extension(RequiredCapabilitiesExt::default())
            .unwrap();

        extensions
            .set_extension(ApplicationIdExt {
                identifier: SecureRng::gen(32).unwrap(),
            })
            .unwrap();

        assert_eq!(
            crate::tls::test_utils::ser_deser(&extensions).unwrap(),
            extensions
        );
    }

    #[test]
    fn extension_list_is_serialized_like_a_sequence_of_extensions() {
        let extension_vec = vec![
            RequiredCapabilitiesExt::default().to_extension().unwrap(),
            ApplicationIdExt {
                identifier: SecureRng::gen(32).unwrap(),
            }
            .to_extension()
            .unwrap(),
        ];

        let extension_list = ExtensionList::from(extension_vec.clone());

        assert_eq!(
            tls_codec::TlsSliceU32(&extension_vec)
                .tls_serialize_detached()
                .unwrap(),
            extension_list.tls_serialize_detached().unwrap(),
        );
    }

    #[test]
    fn deserializing_extension_list_fails_on_duplicate_extension() {
        let extensions = vec![
            RequiredCapabilitiesExt::default().to_extension().unwrap(),
            RequiredCapabilitiesExt::default().to_extension().unwrap(),
        ];

        let serialized_extensions = tls_codec::TlsSliceU32(&extensions)
            .tls_serialize_detached()
            .unwrap();

        assert_matches!(
            ExtensionList::tls_deserialize(&mut &*serialized_extensions),
            Err(tls_codec::Error::DecodingError(_))
        );
    }
}
