use crate::{Error, MlsDecode, MlsEncode, MlsSize, VarInt};

use alloc::vec::Vec;

/// Optimized length calculation for types that can be represented as u8 slices.
pub fn mls_encoded_len<T>(data: &T) -> usize
where
    T: AsRef<[u8]>,
{
    let len = data.as_ref().len();

    let header_length = VarInt::try_from(len)
        .expect("exceeded max len of VarInt::MAX")
        .mls_encoded_len();

    header_length + len
}

/// Optimized encoding for types that can be represented as u8 slices.
pub fn mls_encode<T>(data: &T, writer: &mut Vec<u8>) -> Result<(), Error>
where
    T: AsRef<[u8]>,
{
    let data = data.as_ref();
    let len = VarInt::try_from(data.len())?;

    len.mls_encode(writer)?;
    writer.extend_from_slice(data);

    Ok(())
}

/// Optimized decoding for types that can be represented as Vec<u8>
pub fn mls_decode<T>(reader: &mut &[u8]) -> Result<T, crate::Error>
where
    T: From<Vec<u8>>,
{
    let len = VarInt::mls_decode(reader)?.0 as usize;

    let out = reader
        .get(..len)
        .map(|head| head.to_vec().into())
        .ok_or(crate::Error::UnexpectedEOF)?;

    *reader = &reader[len..];
    Ok(out)
}