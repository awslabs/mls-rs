use crate::cipher_suite::CipherSuite;
use crate::group::proposal::ProposalType;
use crate::time::{MlsTime, SystemTimeError};
use crate::tls::ReadWithCount;
use crate::tree_kem::node::NodeVec;
use crate::tree_kem::parent_hash::ParentHash;
use crate::ProtocolVersion;
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
    #[error(transparent)]
    SystemTimeError(#[from] SystemTimeError),
    #[error("invalid lifetime, above max u64")]
    TimeOverflow,
}

pub type ExtensionType = u16;

const CAPABILITIES_EXT_ID: ExtensionType = 1u16;
const LIFETIME_EXT_ID: ExtensionType = 2u16;
const KEY_ID_EXT_ID: ExtensionType = 3u16;
const PARENT_HASH_EXT_ID: ExtensionType = 4u16;
const RATCHET_TREE_EXT_ID: ExtensionType = 5u16;
const REQUIRED_CAPABILITIES_EXT_ID: ExtensionType = 6u16;

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
pub struct ExternalKeyIdExt {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub identifier: Vec<u8>,
}

impl MlsExtension for ExternalKeyIdExt {
    const IDENTIFIER: ExtensionType = KEY_ID_EXT_ID;
}

#[derive(Clone, PartialEq, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct CapabilitiesExt {
    #[tls_codec(with = "crate::tls::DefVec::<u8>")]
    pub protocol_versions: Vec<ProtocolVersion>,
    #[tls_codec(with = "crate::tls::DefVec::<u8>")]
    pub cipher_suites: Vec<CipherSuite>,
    #[tls_codec(with = "crate::tls::DefVec::<u8>")]
    pub extensions: Vec<ExtensionType>,
    #[tls_codec(with = "crate::tls::DefVec::<u8>")]
    pub proposals: Vec<ProposalType>,
}

impl Default for CapabilitiesExt {
    fn default() -> Self {
        Self {
            protocol_versions: vec![ProtocolVersion::Mls10],
            cipher_suites: CipherSuite::all().collect(),
            extensions: Default::default(),
            proposals: Default::default(),
        }
    }
}

impl MlsExtension for CapabilitiesExt {
    const IDENTIFIER: ExtensionType = CAPABILITIES_EXT_ID;
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct LifetimeExt {
    pub not_before: u64,
    pub not_after: u64,
}

impl LifetimeExt {
    pub fn seconds(s: u64) -> Result<Self, ExtensionError> {
        let not_before = MlsTime::now().seconds_since_epoch()?;

        let not_after = not_before
            .checked_add(s)
            .ok_or(ExtensionError::TimeOverflow)?;

        Ok(LifetimeExt {
            not_before,
            not_after,
        })
    }

    pub fn days(d: u32) -> Result<Self, ExtensionError> {
        Self::seconds((d * 86400) as u64)
    }

    pub fn years(y: u8) -> Result<Self, ExtensionError> {
        Self::days(365 * y as u32)
    }

    pub fn within_lifetime(&self, time: MlsTime) -> Result<bool, ExtensionError> {
        let since_epoch = time.seconds_since_epoch()?;
        Ok(since_epoch >= self.not_before && since_epoch <= self.not_after)
    }
}

impl MlsExtension for LifetimeExt {
    const IDENTIFIER: ExtensionType = LIFETIME_EXT_ID;
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct ParentHashExt {
    pub parent_hash: ParentHash,
}

impl From<ParentHash> for ParentHashExt {
    fn from(parent_hash: ParentHash) -> Self {
        Self { parent_hash }
    }
}

impl MlsExtension for ParentHashExt {
    const IDENTIFIER: ExtensionType = PARENT_HASH_EXT_ID;
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
    #[tls_codec(with = "crate::tls::DefVec::<u8>")]
    pub extensions: Vec<ExtensionType>,
    #[tls_codec(with = "crate::tls::DefVec::<u8>")]
    pub proposals: Vec<ProposalType>,
}

impl MlsExtension for RequiredCapabilitiesExt {
    const IDENTIFIER: ExtensionType = REQUIRED_CAPABILITIES_EXT_ID;
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Extension {
    pub extension_type: ExtensionType,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub extension_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct ExtensionList(IndexMap<ExtensionType, Extension>);

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
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use ferriscrypt::rand::SecureRng;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    fn test_key_id_extension() {
        let test_id = vec![0u8; 32];
        let test_extension = ExternalKeyIdExt {
            identifier: test_id.clone(),
        };

        let as_extension = test_extension.to_extension().unwrap();
        assert_eq!(as_extension.extension_type, ExternalKeyIdExt::IDENTIFIER);

        let restored = ExternalKeyIdExt::from_extension(as_extension).unwrap();
        assert_eq!(restored.identifier, test_id);
    }

    #[test]
    fn test_capabilities() {
        let test_protocol_versions = vec![ProtocolVersion::Mls10];
        let test_ciphersuites = vec![CipherSuite::P256Aes128V1, CipherSuite::Curve25519Aes128V1];

        let test_extensions = vec![
            ParentHashExt::IDENTIFIER,
            LifetimeExt::IDENTIFIER,
            ExternalKeyIdExt::IDENTIFIER,
        ];

        let test_extension = CapabilitiesExt {
            protocol_versions: test_protocol_versions.clone(),
            cipher_suites: test_ciphersuites.clone(),
            extensions: test_extensions.clone(),
            proposals: vec![],
        };

        let as_extension = test_extension.to_extension().expect("serialization error");
        assert_eq!(as_extension.extension_type, CapabilitiesExt::IDENTIFIER);

        let restored =
            CapabilitiesExt::from_extension(as_extension).expect("deserialization error");
        assert_eq!(restored.protocol_versions, test_protocol_versions);
        assert_eq!(restored.cipher_suites, test_ciphersuites);
        assert_eq!(restored.extensions, test_extensions);
    }

    #[test]
    fn test_lifetime() {
        let lifetime = LifetimeExt::seconds(1).unwrap();
        assert_eq!(lifetime.not_after - 1, lifetime.not_before);

        let as_extension = lifetime.to_extension().expect("to extension error");
        assert_eq!(as_extension.extension_type, LifetimeExt::IDENTIFIER);

        let restored = LifetimeExt::from_extension(as_extension).expect("from extension error");
        assert_eq!(lifetime.not_after, restored.not_after);
        assert_eq!(lifetime.not_before, restored.not_before);
    }

    #[test]
    fn test_lifetime_overflow() {
        let res = LifetimeExt::seconds(u64::MAX);
        assert_matches!(res, Err(ExtensionError::TimeOverflow))
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
            proposals: vec![42u16, 43u16],
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
            extension_type: CAPABILITIES_EXT_ID,
            extension_data: bad_data,
        };
        let capabilities: Result<CapabilitiesExt, ExtensionError> =
            CapabilitiesExt::from_extension(test_extension);
        assert!(capabilities.is_err());
    }

    #[test]
    fn test_bad_deserialize_type() {
        let test_extension = Extension {
            extension_type: KEY_ID_EXT_ID,
            extension_data: vec![0u8; 32],
        };
        assert!(CapabilitiesExt::from_extension(test_extension).is_err());
    }

    #[test]
    fn test_extension_list_get_set() {
        let mut list = ExtensionList::new();

        let lifetime = LifetimeExt::seconds(42).unwrap();
        let key_id = ExternalKeyIdExt {
            identifier: SecureRng::gen(32).unwrap(),
        };

        // Add the extensions to the list
        list.set_extension(lifetime.clone()).unwrap();
        list.set_extension(key_id.clone()).unwrap();

        assert_eq!(list.len(), 2);
        assert_eq!(list.get_extension::<LifetimeExt>().unwrap(), Some(lifetime));
        assert_eq!(
            list.get_extension::<ExternalKeyIdExt>().unwrap(),
            Some(key_id.clone())
        );
        assert_eq!(list.get_extension::<CapabilitiesExt>().unwrap(), None);

        // Overwrite the extension in the list
        let lifetime = LifetimeExt::seconds(1).unwrap();

        list.set_extension(lifetime.clone()).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list.get_extension::<LifetimeExt>().unwrap(), Some(lifetime));
        assert_eq!(
            list.get_extension::<ExternalKeyIdExt>().unwrap(),
            Some(key_id)
        );
        assert_eq!(list.get_extension::<CapabilitiesExt>().unwrap(), None);
    }

    #[test]
    fn test_extension_list_has_ext() {
        let mut list = ExtensionList::new();

        let lifetime = LifetimeExt::seconds(42).unwrap();
        list.set_extension(lifetime).unwrap();

        assert!(list.has_extension(LifetimeExt::IDENTIFIER));
        assert!(!list.has_extension(42));
    }

    #[test]
    fn extension_list_serialization_roundtrips() {
        let mut extensions = ExtensionList::default();
        extensions
            .set_extension(LifetimeExt::seconds(42).unwrap())
            .unwrap();
        extensions
            .set_extension(ExternalKeyIdExt {
                identifier: SecureRng::gen(32).unwrap(),
            })
            .unwrap();
        assert_eq!(
            crate::tls::test_util::ser_deser(&extensions).unwrap(),
            extensions
        );
    }

    #[test]
    fn extension_list_is_serialized_like_a_sequence_of_extensions() {
        let extension_vec = vec![
            LifetimeExt::seconds(42).unwrap().to_extension().unwrap(),
            ExternalKeyIdExt {
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
            LifetimeExt::seconds(42).unwrap().to_extension().unwrap(),
            LifetimeExt::seconds(43).unwrap().to_extension().unwrap(),
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
