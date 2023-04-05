use alloc::format;
use alloc::vec::Vec;

use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize, ReadWithCount, VarInt};
use indexmap::IndexMap;

use super::{Extension, ExtensionError, ExtensionType, MlsExtension};

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for ExtensionList {
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

/// A collection of MLS [Extensions](super::Extension).
///
///
/// # Warning
///
/// Extension lists require that each type of extension has at most one entry.
#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize, serde::Serialize)]
pub struct ExtensionList(#[serde(with = "indexmap::serde_seq")] IndexMap<ExtensionType, Extension>);

impl From<IndexMap<ExtensionType, Extension>> for ExtensionList {
    fn from(map: IndexMap<ExtensionType, Extension>) -> Self {
        Self(map)
    }
}

impl MlsSize for ExtensionList {
    fn mls_encoded_len(&self) -> usize {
        let len = self.iter().map(|x| x.mls_encoded_len()).sum::<usize>();

        let header_length = VarInt::try_from(len)
            .expect("exceeded max len of VarInt::MAX")
            .mls_encoded_len();

        header_length + len
    }
}

impl MlsEncode for ExtensionList {
    fn mls_encode<W: aws_mls_codec::Writer>(
        &self,
        mut writer: W,
    ) -> Result<(), aws_mls_codec::Error> {
        let mut buffer = Vec::new();

        self.iter().try_for_each(|x| x.mls_encode(&mut buffer))?;

        let len = VarInt::try_from(buffer.len())?;

        len.mls_encode(&mut writer)?;
        writer.write(&buffer)?;

        Ok(())
    }
}

impl MlsDecode for ExtensionList {
    fn mls_decode<R: aws_mls_codec::Reader>(mut reader: R) -> Result<Self, aws_mls_codec::Error> {
        let len = VarInt::mls_decode(&mut reader)?.0 as usize;

        let mut reader = ReadWithCount::new(&mut reader);
        let mut items = IndexMap::new();

        while reader.bytes_read() < len {
            let ext = Extension::mls_decode(&mut reader)?;
            let ext_type = ext.extension_type;

            if items.insert(ext_type, ext).is_some() {
                return Err(aws_mls_codec::Error::Custom(format!(
                    "Extension list has duplicate extension of type {ext_type:?}"
                )));
            }
        }

        Ok(items.into())
    }
}

impl From<Vec<Extension>> for ExtensionList {
    fn from(v: Vec<Extension>) -> Self {
        Self::from(IndexMap::from_iter(
            v.into_iter().map(|ext| (ext.extension_type, ext)),
        ))
    }
}

impl<const N: usize> From<[Extension; N]> for ExtensionList {
    fn from(value: [Extension; N]) -> Self {
        Self::from(IndexMap::from_iter(
            value.into_iter().map(|ext| (ext.extension_type, ext)),
        ))
    }
}

impl<'a> IntoIterator for &'a ExtensionList {
    type Item = &'a Extension;
    type IntoIter = ExtensionListIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        ExtensionListIter(self.0.values())
    }
}

/// An iterator created by [ExtensionList::iter](ExtensionList::iter)
pub struct ExtensionListIter<'a>(indexmap::map::Values<'a, ExtensionType, Extension>);

impl<'a> Iterator for ExtensionListIter<'a> {
    type Item = &'a Extension;

    fn next(&mut self) -> Option<&'a Extension> {
        self.0.next()
    }
}

impl ExtensionList {
    /// Create a new empty extension list.
    pub fn new() -> ExtensionList {
        Default::default()
    }

    /// Retrieve an extension by providing a type that implements the
    /// [MlsExtension](super::MlsExtension) trait.
    ///
    /// Returns an error if the underlying deserialization of the extension
    /// data fails.
    pub fn get_as<E: MlsExtension>(&self) -> Result<Option<E>, ExtensionError> {
        self.0
            .get(&E::extension_type())
            .map(E::from_extension)
            .transpose()
    }

    /// Determine if a specific extension exists within the list.
    pub fn has_extension(&self, ext_id: ExtensionType) -> bool {
        self.0.contains_key(&ext_id)
    }

    /// Set an extension in the list based on a provided type that implements
    /// the [MlsExtension](super::MlsExtension) trait.
    ///
    /// If there is already an entry in the list for the same extension type,
    /// then the prior value is removed as part of the insertion.
    ///
    /// This function will return an error if `ext` fails to serialize
    /// properly.
    pub fn set_from<E: MlsExtension>(&mut self, ext: E) -> Result<(), ExtensionError> {
        let ext = ext.into_extension()?;
        self.set(ext);
        Ok(())
    }

    /// Set an extension in the list based on a raw
    /// [Extension](super::Extension) value.
    ///
    /// If there is already an entry in the list for the same extension type,
    /// then the prior value is removed as part of the insertion.
    pub fn set(&mut self, ext: Extension) {
        self.0.insert(ext.extension_type, ext);
    }

    /// Get a raw [Extension](super::Extension) value based on an
    /// [ExtensionType](super::ExtensionType).
    pub fn get(&self, extension_type: ExtensionType) -> Option<Extension> {
        self.0.get(&extension_type).cloned()
    }

    /// The current number of extensions in the list.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Determine if this extension list is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over the raw [Extension](super::Extension) values contained
    /// within the list.
    pub fn iter(&self) -> ExtensionListIter<'_> {
        self.into_iter()
    }

    /// Remove an extension from the list by
    /// [ExtensionType](super::ExtensionType)
    pub fn remove(&mut self, ext_type: ExtensionType) {
        self.0.shift_remove(&ext_type);
    }

    /// Append another extension list to this one.
    ///
    /// If there is already an entry in the list for the same extension type,
    /// then the existing value is removed.
    pub fn append(&mut self, others: Self) {
        self.0.extend(others.0);
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use assert_matches::assert_matches;
    use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};

    use crate::extension::{
        Extension, ExtensionList, ExtensionType, MlsCodecExtension, MlsExtension,
    };

    #[derive(Debug, Clone, MlsSize, MlsEncode, MlsDecode, PartialEq, Eq)]
    struct TestExtensionA(u32);

    #[derive(Debug, Clone, MlsEncode, MlsDecode, MlsSize, PartialEq, Eq)]
    struct TestExtensionB(#[mls_codec(with = "aws_mls_codec::byte_vec")] Vec<u8>);

    impl MlsCodecExtension for TestExtensionA {
        fn extension_type() -> ExtensionType {
            ExtensionType(128)
        }
    }

    impl MlsCodecExtension for TestExtensionB {
        fn extension_type() -> ExtensionType {
            ExtensionType(129)
        }
    }

    #[test]
    fn test_extension_list_get_set_from_get_as() {
        let mut list = ExtensionList::new();

        let ext_a = TestExtensionA(0);
        let ext_b = TestExtensionB(vec![1]);

        // Add the extensions to the list
        list.set_from(ext_a.clone()).unwrap();
        list.set_from(ext_b.clone()).unwrap();

        assert_eq!(list.len(), 2);
        assert_eq!(list.get_as::<TestExtensionA>().unwrap(), Some(ext_a));
        assert_eq!(list.get_as::<TestExtensionB>().unwrap(), Some(ext_b));
    }

    #[test]
    fn test_extension_list_get_set() {
        let mut list = ExtensionList::new();

        let ext_a = Extension::new(ExtensionType(254), vec![0, 1, 2]);
        let ext_b = Extension::new(ExtensionType(255), vec![4, 5, 6]);

        // Add the extensions to the list
        list.set(ext_a.clone());
        list.set(ext_b.clone());

        assert_eq!(list.len(), 2);
        assert_eq!(list.get(ExtensionType(254)), Some(ext_a));
        assert_eq!(list.get(ExtensionType(255)), Some(ext_b));
    }

    #[test]
    fn extension_list_can_overwrite_values() {
        let mut list = ExtensionList::new();

        let ext_1 = TestExtensionA(0);
        let ext_2 = TestExtensionA(1);

        list.set_from(ext_1).unwrap();
        list.set_from(ext_2.clone()).unwrap();

        assert_eq!(list.get_as::<TestExtensionA>().unwrap(), Some(ext_2));
    }

    #[test]
    fn extension_list_will_return_none_for_type_not_stored() {
        let mut list = ExtensionList::new();

        assert!(list.get_as::<TestExtensionA>().unwrap().is_none());

        assert!(list
            .get(<TestExtensionA as MlsCodecExtension>::extension_type())
            .is_none());

        list.set_from(TestExtensionA(1)).unwrap();

        assert!(list.get_as::<TestExtensionB>().unwrap().is_none());

        assert!(list
            .get(<TestExtensionB as MlsCodecExtension>::extension_type())
            .is_none());
    }

    #[test]
    fn test_extension_list_has_ext() {
        let mut list = ExtensionList::new();

        let ext = TestExtensionA(255);

        list.set_from(ext).unwrap();

        assert!(list.has_extension(<TestExtensionA as MlsCodecExtension>::extension_type()));
        assert!(!list.has_extension(42.into()));
    }

    #[derive(MlsEncode, MlsSize)]
    struct ExtensionsVec(Vec<Extension>);

    #[test]
    fn extension_list_is_serialized_like_a_sequence_of_extensions() {
        let extension_vec = vec![
            Extension::new(ExtensionType(128), vec![0, 1, 2, 3]),
            Extension::new(ExtensionType(129), vec![1, 2, 3, 4]),
        ];

        let extension_list: ExtensionList = ExtensionList::from(extension_vec.clone());

        assert_eq!(
            ExtensionsVec(extension_vec).mls_encode_to_vec().unwrap(),
            extension_list.mls_encode_to_vec().unwrap(),
        );
    }

    #[test]
    fn deserializing_extension_list_fails_on_duplicate_extension() {
        let extensions = ExtensionsVec(vec![
            TestExtensionA(1).into_extension().unwrap(),
            TestExtensionA(2).into_extension().unwrap(),
        ]);

        let serialized_extensions = extensions.mls_encode_to_vec().unwrap();

        assert_matches!(
            ExtensionList::mls_decode(&*serialized_extensions),
            Err(aws_mls_codec::Error::Custom(_))
        );
    }
}
