use core::hash::Hash;
use std::collections::HashMap;

use crate::{MlsDecode, MlsEncode, MlsSize};

impl<K, V> MlsSize for HashMap<K, V>
where
    K: MlsSize,
    V: MlsSize,
{
    fn mls_encoded_len(&self) -> usize {
        crate::iter::mls_encoded_len(self.iter())
    }
}

impl<K, V> MlsEncode for HashMap<K, V>
where
    K: MlsEncode,
    V: MlsEncode,
{
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), crate::Error> {
        crate::iter::mls_encode(self.iter(), writer)
    }
}

impl<K, V> MlsDecode for HashMap<K, V>
where
    K: MlsDecode + Hash + Eq,
    V: MlsDecode,
{
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, crate::Error> {
        crate::iter::mls_decode_collection(reader, |data| {
            let mut items = HashMap::new();

            while !data.is_empty() {
                items.insert(K::mls_decode(data)?, V::mls_decode(data)?);
            }

            Ok(items)
        })
    }
}
