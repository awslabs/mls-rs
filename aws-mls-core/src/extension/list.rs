use std::io::{Read, Write};

use indexmap::IndexMap;
use tls_codec::{Deserialize, Serialize, Size};

use crate::tls::{ReadWithCount, VarInt};

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

#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize, serde::Serialize)]
pub struct ExtensionList(#[serde(with = "indexmap::serde_seq")] IndexMap<ExtensionType, Extension>);

impl From<IndexMap<ExtensionType, Extension>> for ExtensionList {
    fn from(map: IndexMap<ExtensionType, Extension>) -> Self {
        Self(map)
    }
}

impl Size for ExtensionList {
    fn tls_serialized_len(&self) -> usize {
        let len = self
            .iter()
            .map(|ext| ext.tls_serialized_len())
            .sum::<usize>();

        let header_len = VarInt::try_from(len)
            .expect("Extension list has too many bytes to be serialized")
            .tls_serialized_len();

        header_len + len
    }
}

impl Serialize for ExtensionList {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut buffer = Vec::new();

        let len = self.iter().try_fold(0, |acc, x| {
            Ok::<_, tls_codec::Error>(acc + x.tls_serialize(&mut buffer)?)
        })?;

        let len = VarInt::try_from(len).map_err(|_| tls_codec::Error::InvalidVectorLength)?;
        let written = len.tls_serialize(writer)?;
        writer.write_all(&buffer)?;

        Ok(written + buffer.len())
    }
}

impl Deserialize for ExtensionList {
    fn tls_deserialize<R: Read>(reader: &mut R) -> Result<Self, tls_codec::Error> {
        let len: usize = VarInt::tls_deserialize(reader)?
            .try_into()
            .map_err(|_| tls_codec::Error::InvalidVectorLength)?;

        let reader = &mut ReadWithCount::new(reader);
        let mut items = IndexMap::new();

        while reader.bytes_read() < len {
            let ext = Extension::tls_deserialize(reader)?;
            let ext_type = ext.extension_type;

            if items.insert(ext_type, ext).is_some() {
                return Err(tls_codec::Error::DecodingError(format!(
                    "Extension list has duplicate extension of type {ext_type:?}"
                )));
            }
        }

        Ok(ExtensionList::from(items))
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

    pub fn get_as<E: MlsExtension>(&self) -> Result<Option<E>, ExtensionError> {
        self.0
            .get(&E::extension_type())
            .map(E::from_extension)
            .transpose()
    }

    pub fn has_extension(&self, ext_id: ExtensionType) -> bool {
        self.0.contains_key(&ext_id)
    }

    pub fn set_from<E: MlsExtension>(&mut self, ext: E) -> Result<(), ExtensionError> {
        let ext = ext.into_extension()?;
        self.set(ext);
        Ok(())
    }

    pub fn set(&mut self, ext: Extension) {
        self.0.insert(ext.extension_type, ext);
    }

    pub fn get(&self, extension_type: ExtensionType) -> Option<Extension> {
        self.0.get(&extension_type).cloned()
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

    pub fn append(&mut self, others: Self) {
        self.0.extend(others.0);
    }
}
