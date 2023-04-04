use crate::{MlsDecode, MlsEncode, MlsSize};

impl<const N: usize> MlsSize for [u8; N] {
    #[inline(always)]
    fn mls_encoded_len(&self) -> usize {
        N
    }
}

impl<const N: usize> MlsEncode for [u8; N] {
    #[inline(always)]
    fn mls_encode<W: crate::Writer>(&self, mut writer: W) -> Result<(), crate::Error> {
        writer.write(self)
    }
}

impl<const N: usize> MlsDecode for [u8; N] {
    fn mls_decode<R: crate::Reader>(mut reader: R) -> Result<Self, crate::Error> {
        let mut res = [0u8; N];
        reader.read(&mut res)?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use alloc::vec;

    use crate::{Error, MlsEncode};
    use assert_matches::assert_matches;

    #[test]
    fn serialize_works() {
        let arr = [0u8, 1u8, 2u8];
        assert_eq!(arr.mls_encode_to_vec().unwrap(), vec![0u8, 1u8, 2u8]);
    }

    #[test]
    fn serialize_round_trip() {
        let arr = [0u8, 1u8, 2u8];
        let serialized = arr.mls_encode_to_vec().unwrap();
        let restored: [u8; 3] = crate::MlsDecode::mls_decode(&*serialized).unwrap();
        assert_eq!(arr, restored);
    }

    #[test]
    fn end_of_file_error() {
        let arr = [0u8, 1u8, 2u8];
        let serialized = arr.mls_encode_to_vec().unwrap();
        let res: Result<[u8; 5], Error> = crate::MlsDecode::mls_decode(&*serialized);

        assert_matches!(res, Err(Error::UnexpectedEOF))
    }
}
