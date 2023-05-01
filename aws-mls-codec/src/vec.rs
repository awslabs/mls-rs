use alloc::vec::Vec;

use crate::{varint::VarInt, MlsDecode, MlsEncode, MlsSize};

impl<T> MlsSize for [T]
where
    T: MlsSize,
{
    fn mls_encoded_len(&self) -> usize {
        let len = self.iter().map(|x| x.mls_encoded_len()).sum::<usize>();

        let header_length = VarInt::try_from(len)
            .expect("exceeded max len of VarInt::MAX")
            .mls_encoded_len();

        header_length + len
    }
}

impl<T> MlsSize for Vec<T>
where
    T: MlsSize,
{
    #[inline]
    fn mls_encoded_len(&self) -> usize {
        self.as_slice().mls_encoded_len()
    }
}

impl<T> MlsEncode for [T]
where
    T: MlsEncode,
{
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), crate::Error> {
        let mut buffer = Vec::new();

        self.iter().try_for_each(|x| x.mls_encode(&mut buffer))?;

        let len = VarInt::try_from(buffer.len())?;

        len.mls_encode(writer)?;
        writer.extend(buffer);

        Ok(())
    }
}

impl<T> MlsEncode for Vec<T>
where
    T: MlsEncode,
{
    #[inline]
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), crate::Error> {
        self.as_slice().mls_encode(writer)
    }
}

impl<T> MlsDecode for Vec<T>
where
    T: MlsDecode,
{
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, crate::Error> {
        let len = VarInt::mls_decode(reader)?.0 as usize;

        (len <= reader.len())
            .then_some(())
            .ok_or(crate::Error::UnexpectedEOF)?;

        let (mut data, rest) = reader.split_at(len);
        *reader = rest;
        let mut items = Vec::new();

        while !data.is_empty() {
            items.push(T::mls_decode(&mut data)?);
        }

        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Error, MlsDecode, MlsEncode};
    use alloc::{vec, vec::Vec};
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn serialization_works() {
        assert_eq!(
            vec![3, 1, 2, 3],
            vec![1u8, 2, 3].mls_encode_to_vec().unwrap()
        );
    }

    #[test]
    fn data_round_trips() {
        let val = vec![1u8, 2, 3];
        let x = val.mls_encode_to_vec().unwrap();
        assert_eq!(val, Vec::mls_decode(&mut &*x).unwrap());
    }

    #[test]
    fn empty_vec_can_be_deserialized() {
        assert_eq!(Vec::<u8>::new(), Vec::mls_decode(&mut &[0u8][..]).unwrap());
    }

    #[test]
    fn too_few_items_to_deserialize_gives_an_error() {
        assert_matches!(
            Vec::<u8>::mls_decode(&mut &[2, 3][..]),
            Err(Error::UnexpectedEOF)
        );
    }
}
