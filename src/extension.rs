use crate::cipher_suite::CipherSuite;
use crate::client_config::CredentialValidator;
use crate::group::proposal::ProposalType;
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::signing_identity::SigningIdentityError;
use crate::tls::ReadWithCount;
use crate::tree_kem::node::NodeVec;
use crate::{credential::CredentialType, signing_identity::SigningIdentity};
use ferriscrypt::hpke::kem::HpkePublicKey;
use serde_with::serde_as;
use std::fmt::Debug;
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

#[derive(Debug, PartialEq, Eq, Clone, Default, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LeafNodeExtension;

#[derive(Debug, PartialEq, Eq, Clone, Default, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct GroupInfoExtension;

#[derive(Debug, PartialEq, Eq, Clone, Default, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct GroupContextExtension;

#[derive(Debug, PartialEq, Eq, Clone, Default, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct KeyPackageExtension;

pub trait ExtensionClass {}
impl ExtensionClass for LeafNodeExtension {}
impl ExtensionClass for GroupInfoExtension {}
impl ExtensionClass for GroupContextExtension {}
impl ExtensionClass for KeyPackageExtension {}

pub type ExtensionType = u16;

const APPLICATION_ID_EXT_ID: ExtensionType = 1;
const RATCHET_TREE_EXT_ID: ExtensionType = 2;
const REQUIRED_CAPABILITIES_EXT_ID: ExtensionType = 3;
const EXTERNAL_PUB_EXT_ID: ExtensionType = 4;
const EXTERNAL_SENDERS_EXT_ID: ExtensionType = 5;

const DEFAULT_EXTENSIONS: &[ExtensionType] = &[
    APPLICATION_ID_EXT_ID,
    RATCHET_TREE_EXT_ID,
    REQUIRED_CAPABILITIES_EXT_ID,
    EXTERNAL_PUB_EXT_ID,
    EXTERNAL_SENDERS_EXT_ID,
];

pub(crate) fn is_default_extension(ext_type: ExtensionType) -> bool {
    DEFAULT_EXTENSIONS.contains(&ext_type)
}

pub trait MlsExtension<T>: Sized + Serialize + Deserialize
where
    T: ExtensionClass,
{
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

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct ApplicationIdExt {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub identifier: Vec<u8>,
}

impl MlsExtension<LeafNodeExtension> for ApplicationIdExt {
    const IDENTIFIER: ExtensionType = APPLICATION_ID_EXT_ID;
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct RatchetTreeExt {
    pub(crate) tree_data: NodeVec,
}

impl MlsExtension<GroupInfoExtension> for RatchetTreeExt {
    const IDENTIFIER: ExtensionType = RATCHET_TREE_EXT_ID;
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize, Default)]
pub struct RequiredCapabilitiesExt {
    #[tls_codec(with = "crate::tls::DefVec")]
    pub extensions: Vec<ExtensionType>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub proposals: Vec<ProposalType>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub credentials: Vec<CredentialType>,
}

impl MlsExtension<GroupContextExtension> for RequiredCapabilitiesExt {
    const IDENTIFIER: ExtensionType = REQUIRED_CAPABILITIES_EXT_ID;
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct ExternalPubExt {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub external_pub: HpkePublicKey,
}

impl MlsExtension<GroupInfoExtension> for ExternalPubExt {
    const IDENTIFIER: ExtensionType = EXTERNAL_PUB_EXT_ID;
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
#[non_exhaustive]
pub struct ExternalSendersExt {
    #[tls_codec(with = "crate::tls::DefVec")]
    pub allowed_senders: Vec<SigningIdentity>,
}

impl ExternalSendersExt {
    pub fn new(allowed_senders: Vec<SigningIdentity>) -> Self {
        Self { allowed_senders }
    }

    pub fn verify_all<C: CredentialValidator>(
        &self,
        validator: &C,
        cipher_suite: CipherSuite,
    ) -> Result<(), SigningIdentityError> {
        self.allowed_senders.iter().try_for_each(|id| {
            validator
                .validate(id, cipher_suite)
                .map_err(|e| SigningIdentityError::CredentialValidatorError(Box::new(e)))
        })
    }
}

impl MlsExtension<GroupContextExtension> for ExternalSendersExt {
    const IDENTIFIER: ExtensionType = EXTERNAL_SENDERS_EXT_ID;
}

#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Extension {
    pub extension_type: ExtensionType,
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    pub extension_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Default, serde::Deserialize, serde::Serialize)]
struct IndexMap(
    #[serde(with = "indexmap::serde_seq")] indexmap::IndexMap<ExtensionType, Extension>,
);

impl IndexMap {
    fn new() -> Self {
        IndexMap(indexmap::IndexMap::new())
    }
}

impl FromIterator<(ExtensionType, Extension)> for IndexMap {
    fn from_iter<T: IntoIterator<Item = (ExtensionType, Extension)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl std::ops::Deref for IndexMap {
    type Target = indexmap::IndexMap<ExtensionType, Extension>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for IndexMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for IndexMap {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        u.arbitrary_iter::<(ExtensionType, Extension)>()?
            .try_fold(indexmap::IndexMap::new(), |mut map, item| {
                let (ext_type, ext) = item?;
                map.insert(ext_type, ext);
                Ok(map)
            })
            .map(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ExtensionList<T: ExtensionClass> {
    extensions: IndexMap,
    #[serde(skip_serializing, default)]
    ext_class: T,
}

impl<T> From<IndexMap> for ExtensionList<T>
where
    T: ExtensionClass + Default,
{
    fn from(map: IndexMap) -> Self {
        Self {
            extensions: map,
            ext_class: Default::default(),
        }
    }
}

impl<T> Size for ExtensionList<T>
where
    T: ExtensionClass + Default,
{
    fn tls_serialized_len(&self) -> usize {
        (self.len() as u32).tls_serialized_len()
            + self
                .iter()
                .map(|ext| ext.tls_serialized_len())
                .sum::<usize>()
    }
}

impl<T> Serialize for ExtensionList<T>
where
    T: ExtensionClass + Default,
{
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

impl<T> Deserialize for ExtensionList<T>
where
    T: ExtensionClass + Default,
{
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
        Ok(ExtensionList::from(items))
    }
}

impl<T> From<Vec<Extension>> for ExtensionList<T>
where
    T: ExtensionClass + Default,
{
    fn from(v: Vec<Extension>) -> Self {
        Self::from(IndexMap::from_iter(
            v.into_iter().map(|ext| (ext.extension_type, ext)),
        ))
    }
}

impl<const N: usize, E, T> TryFrom<[E; N]> for ExtensionList<T>
where
    E: MlsExtension<T>,
    T: ExtensionClass + Default,
{
    type Error = ExtensionError;

    fn try_from(a: [E; N]) -> Result<Self, Self::Error> {
        a.into_iter()
            .try_fold(IndexMap::default(), |mut acc, x| {
                let ext = x.to_extension()?;
                acc.insert(ext.extension_type, ext);
                Ok(acc)
            })
            .map(Self::from)
    }
}

impl<'a, T> IntoIterator for &'a ExtensionList<T>
where
    T: ExtensionClass,
{
    type Item = &'a Extension;
    type IntoIter = ExtensionListIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        ExtensionListIter(self.extensions.values())
    }
}

pub struct ExtensionListIter<'a>(indexmap::map::Values<'a, ExtensionType, Extension>);

impl<'a> Iterator for ExtensionListIter<'a> {
    type Item = &'a Extension;

    fn next(&mut self) -> Option<&'a Extension> {
        self.0.next()
    }
}

impl<T> ExtensionList<T>
where
    T: ExtensionClass + Default,
{
    pub fn new() -> ExtensionList<T> {
        Default::default()
    }

    pub fn get_extension<E: MlsExtension<T>>(&self) -> Result<Option<E>, ExtensionError> {
        Ok(self
            .extensions
            .get(&E::IDENTIFIER)
            .map(|ext| E::tls_deserialize(&mut &*ext.extension_data))
            .transpose()?)
    }

    pub fn has_extension(&self, ext_id: ExtensionType) -> bool {
        self.extensions.contains_key(&ext_id)
    }

    pub fn set_extension<E: MlsExtension<T>>(&mut self, ext: E) -> Result<(), ExtensionError> {
        let ext = ext.to_extension()?;
        self.extensions.insert(ext.extension_type, ext);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.extensions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }

    pub fn iter(&self) -> ExtensionListIter<'_> {
        self.into_iter()
    }

    pub fn remove(&mut self, ext_type: ExtensionType) {
        self.extensions.shift_remove(&ext_type);
    }
}

#[cfg(any(test, feature = "benchmark"))]
pub(crate) mod test_utils {
    use super::*;

    #[derive(TlsSize, TlsSerialize, TlsDeserialize, Clone, Debug, PartialEq)]
    pub(crate) struct TestExtension {
        pub(crate) foo: u8,
    }

    impl MlsExtension<LeafNodeExtension> for TestExtension {
        const IDENTIFIER: crate::extension::ExtensionType = 42;
    }

    impl MlsExtension<GroupContextExtension> for TestExtension {
        const IDENTIFIER: crate::extension::ExtensionType = 42;
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        credential::CREDENTIAL_TYPE_BASIC, signing_identity::test_utils::get_test_signing_identity,
    };

    use super::*;
    use assert_matches::assert_matches;
    use ferriscrypt::rand::SecureRng;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Debug, Clone, TlsSerialize, TlsSize, TlsDeserialize, PartialEq)]
    struct TestExt;

    impl MlsExtension<GroupContextExtension> for TestExt {
        const IDENTIFIER: ExtensionType = 42;
    }

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

        let ext_senders = ExternalSendersExt {
            allowed_senders: vec![],
        };

        // Add the extensions to the list
        list.set_extension(required_capabilities.clone()).unwrap();
        list.set_extension(ext_senders.clone()).unwrap();

        assert_eq!(list.len(), 2);

        assert_eq!(
            list.get_extension::<RequiredCapabilitiesExt>().unwrap(),
            Some(required_capabilities)
        );

        assert_eq!(
            list.get_extension::<ExternalSendersExt>().unwrap(),
            Some(ext_senders)
        );

        assert_eq!(list.get_extension::<TestExt>().unwrap(), None);

        // Overwrite the extension in the list
        let ext_senders = ExternalSendersExt {
            allowed_senders: vec![
                get_test_signing_identity(CipherSuite::Curve25519Aes128, vec![]).0,
            ],
        };

        list.set_extension(ext_senders.clone()).unwrap();
        assert_eq!(list.len(), 2);

        assert_eq!(
            list.get_extension::<ExternalSendersExt>().unwrap(),
            Some(ext_senders.clone())
        );

        assert_eq!(
            list.get_extension::<ExternalSendersExt>().unwrap(),
            Some(ext_senders)
        );

        assert_eq!(list.get_extension::<TestExt>().unwrap(), None);
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
            .set_extension(ExternalSendersExt {
                allowed_senders: vec![],
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
            ExternalSendersExt {
                allowed_senders: vec![],
            }
            .to_extension()
            .unwrap(),
        ];

        let extension_list: ExtensionList<GroupContextExtension> =
            ExtensionList::from(extension_vec.clone());

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
            ExtensionList::<GroupContextExtension>::tls_deserialize(&mut &*serialized_extensions),
            Err(tls_codec::Error::DecodingError(_))
        );
    }
}
