// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::{collections::BTreeMap, vec::Vec};

#[cfg(feature = "std")]
use std::{collections::HashMap, hash::Hash};

use crate::{MlsDecode, MlsEncode, MlsSize};

#[cfg(feature = "std")]
impl<K, V> MlsSize for HashMap<K, V>
where
    K: MlsSize,
    V: MlsSize,
{
    fn mls_encoded_len(&self) -> usize {
        crate::iter::mls_encoded_len(self.iter())
    }
}

#[cfg(feature = "std")]
impl<K, V> MlsEncode for HashMap<K, V>
where
    K: MlsEncode + Ord,
    V: MlsEncode,
{
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), crate::Error> {
        use itertools::Itertools;
        crate::iter::mls_encode(self.iter().sorted_by_key(|(key, _)| *key), writer)
    }
}

#[cfg(feature = "std")]
impl<K, V> MlsDecode for HashMap<K, V>
where
    K: MlsDecode + Hash + Eq,
    V: MlsDecode,
{
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, crate::Error> {
        crate::iter::mls_decode_collection(reader, |data| {
            let mut items = HashMap::new();

            while !data.is_empty() {
                let before = data.len();
                let key = K::mls_decode(data)?;
                let value = V::mls_decode(data)?;

                if data.len() == before || items.insert(key, value).is_some() {
                    return Err(crate::Error::InvalidContent);
                }
            }

            Ok(items)
        })
    }
}

impl<K, V> MlsSize for BTreeMap<K, V>
where
    K: MlsSize,
    V: MlsSize,
{
    fn mls_encoded_len(&self) -> usize {
        crate::iter::mls_encoded_len(self.iter())
    }
}

impl<K, V> MlsEncode for BTreeMap<K, V>
where
    K: MlsEncode,
    V: MlsEncode,
{
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), crate::Error> {
        crate::iter::mls_encode(self.iter(), writer)
    }
}

impl<K, V> MlsDecode for BTreeMap<K, V>
where
    K: MlsDecode + Eq + Ord,
    V: MlsDecode,
{
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, crate::Error> {
        crate::iter::mls_decode_collection(reader, |data| {
            let mut items = BTreeMap::new();

            while !data.is_empty() {
                let before = data.len();
                let key = K::mls_decode(data)?;
                let value = V::mls_decode(data)?;

                if data.len() == before || items.insert(key, value).is_some() {
                    return Err(crate::Error::InvalidContent);
                }
            }

            Ok(items)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlsDecode, MlsEncode};
    use assert_matches::assert_matches;

    #[cfg(feature = "std")]
    #[test]
    fn test_basic_hashmap_roundtrip() {
        let mut original = HashMap::new();
        original.insert(1u32, 100);
        original.insert(2u32, 200);
        original.insert(3u32, 300);
        original.insert(4u32, 100);

        let mut encoded = Vec::new();
        original.mls_encode(&mut encoded).unwrap();

        let mut slice = encoded.as_slice();
        let decoded = HashMap::<u32, u32>::mls_decode(&mut slice).unwrap();

        assert_eq!(original, decoded);
        assert!(slice.is_empty());
    }

    #[test]
    fn test_basic_btreemap_roundtrip() {
        let mut original = BTreeMap::new();
        original.insert(1u32, 100);
        original.insert(2u32, 200);
        original.insert(3u32, 300);
        original.insert(4u32, 100);

        let mut encoded = Vec::new();
        original.mls_encode(&mut encoded).unwrap();

        let mut slice = encoded.as_slice();
        let decoded = BTreeMap::<u32, u32>::mls_decode(&mut slice).unwrap();

        assert_eq!(original, decoded);
        assert!(slice.is_empty());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_empty_structure_in_hashmap() {
        let mut original: HashMap<u8, [u8; 0]> = HashMap::new();
        original.insert(1u8, []);
        original.insert(2u8, []);

        let mut encoded = Vec::new();
        original.mls_encode(&mut encoded).unwrap();

        let mut slice = encoded.as_slice();
        let decoded = HashMap::<u8, [u8; 0]>::mls_decode(&mut slice).unwrap();
        assert_eq!(original, decoded);
        assert!(slice.is_empty());
    }

    #[cfg(feature = "std")]
    #[test]
    fn hashmap_zero_length_structure() {
        let res = HashMap::<[u8; 0], [u8; 0]>::mls_decode(&mut &[0x01, 0xff][..]);
        assert_matches!(res, Err(crate::Error::InvalidContent))
    }

    #[cfg(feature = "std")]
    #[test]
    fn hashmap_will_not_allow_duplicate_keys() {
        let mut encoded = Vec::new();

        vec![(1u8, 2u8), (3u8, 4u8), (1u8, 5u8)]
            .mls_encode(&mut encoded)
            .unwrap();

        let res = HashMap::<u8, u8>::mls_decode(&mut &*encoded);
        assert_matches!(res, Err(crate::Error::InvalidContent))
    }

    #[test]
    fn btree_map_will_not_allow_duplicate_keys() {
        let mut encoded = Vec::new();

        vec![(1u8, 2u8), (3u8, 4u8), (1u8, 5u8)]
            .mls_encode(&mut encoded)
            .unwrap();

        let res = BTreeMap::<u8, u8>::mls_decode(&mut &*encoded);
        assert_matches!(res, Err(crate::Error::InvalidContent))
    }

    #[test]
    fn btree_map_zero_length_structure() {
        let res = BTreeMap::<[u8; 0], [u8; 0]>::mls_decode(&mut &[0x01, 0xff][..]);
        assert_matches!(res, Err(crate::Error::InvalidContent))
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_hashmap_encoding_order() {
        let mut hash = HashMap::new();
        hash.insert(3u32, "c".to_string());
        hash.insert(1u32, "a".to_string());
        hash.insert(2u32, "b".to_string());

        let mut btree = BTreeMap::new();
        btree.insert(3u32, "c".to_string());
        btree.insert(1u32, "a".to_string());
        btree.insert(2u32, "b".to_string());

        let mut hash_encoded = Vec::new();
        hash.mls_encode(&mut hash_encoded).unwrap();

        let mut btree_encoded = Vec::new();
        btree.mls_encode(&mut btree_encoded).unwrap();

        assert_eq!(hash_encoded, btree_encoded);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_empty_hashmap() {
        let empty_hash: HashMap<u32, u32> = HashMap::new();
        let mut encoded = Vec::new();
        empty_hash.mls_encode(&mut encoded).unwrap();

        let mut slice = encoded.as_slice();
        let decoded = HashMap::<u32, u32>::mls_decode(&mut slice).unwrap();
        assert!(decoded.is_empty());
        assert!(slice.is_empty());
    }

    #[test]
    fn test_empty_btreemap() {
        let empty_btree: BTreeMap<u32, u32> = BTreeMap::new();
        let mut encoded = Vec::new();
        empty_btree.mls_encode(&mut encoded).unwrap();

        let mut slice = encoded.as_slice();
        let decoded = BTreeMap::<u32, u32>::mls_decode(&mut slice).unwrap();
        assert!(decoded.is_empty());
        assert!(slice.is_empty());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_large_hashmap() {
        let mut large_map = HashMap::new();
        for i in 0..1000u32 {
            large_map.insert(i, i * 2);
        }

        let mut encoded = Vec::new();
        large_map.mls_encode(&mut encoded).unwrap();

        let mut slice = encoded.as_slice();
        let decoded = HashMap::<u32, u32>::mls_decode(&mut slice).unwrap();

        assert_eq!(large_map, decoded);
        assert!(slice.is_empty());
    }

    #[test]
    fn test_large_btreemap() {
        let mut large_map = BTreeMap::new();
        for i in 0..1000u32 {
            large_map.insert(i, i * 2);
        }

        let mut encoded = Vec::new();
        large_map.mls_encode(&mut encoded).unwrap();

        let mut slice = encoded.as_slice();
        let decoded = BTreeMap::<u32, u32>::mls_decode(&mut slice).unwrap();

        assert_eq!(large_map, decoded);
        assert!(slice.is_empty());
    }

    #[test]
    fn test_invalid_btreemap_decode() {
        // Test with invalid data
        let invalid_data = vec![0xFF, 0xFF, 0xFF, 0xFF]; // Invalid length prefix
        let mut slice = invalid_data.as_slice();

        let result = BTreeMap::<u32, u32>::mls_decode(&mut slice);
        assert!(result.is_err());

        // Test with truncated data
        let mut valid_map = BTreeMap::new();
        valid_map.insert(1u32, 100u32);

        let mut encoded = Vec::new();
        valid_map.mls_encode(&mut encoded).unwrap();
        encoded.truncate(encoded.len() - 1); // Remove last byte

        let mut slice = encoded.as_slice();
        let result = BTreeMap::<u32, u32>::mls_decode(&mut slice);
        assert!(result.is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_invalid_hashmap_decode() {
        // Test with invalid data
        let invalid_data = vec![0xFF, 0xFF, 0xFF, 0xFF]; // Invalid length prefix
        let mut slice = invalid_data.as_slice();

        let result = HashMap::<u32, u32>::mls_decode(&mut slice);
        assert!(result.is_err());

        // Test with truncated data
        let mut valid_map = HashMap::new();
        valid_map.insert(1u32, 100u32);

        let mut encoded = Vec::new();
        valid_map.mls_encode(&mut encoded).unwrap();
        encoded.truncate(encoded.len() - 1); // Remove last byte

        let mut slice = encoded.as_slice();
        let result = HashMap::<u32, u32>::mls_decode(&mut slice);
        assert!(result.is_err());
    }
}
