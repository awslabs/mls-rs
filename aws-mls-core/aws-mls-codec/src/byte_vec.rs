use crate::{Error, MlsDecode, MlsEncode, MlsSize, VarInt, Writer};

use alloc::{vec, vec::Vec};

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
pub fn mls_encode<T, W: Writer>(data: &T, mut writer: W) -> Result<(), Error>
where
    T: AsRef<[u8]>,
{
    let data = data.as_ref();
    let len = VarInt::try_from(data.len())?;

    len.mls_encode(&mut writer)?;
    writer.write(data)?;

    Ok(())
}

/// Optimized decoding for types that can be represented as Vec<u8>
pub fn mls_decode<T, R: crate::Reader>(mut reader: R) -> Result<T, crate::Error>
where
    T: From<Vec<u8>>,
{
    let len = VarInt::mls_decode(&mut reader)?.0 as usize;

    let mut out = vec![0u8; len];
    reader.read(&mut out)?;

    Ok(out.into())
}
