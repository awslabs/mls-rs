use crate::{MlsDecode, MlsEncode, MlsSize, VarInt};

use alloc::vec::Vec;

pub fn mls_encoded_len<T>(iter: impl Iterator<Item = T>) -> usize
where
    T: MlsSize,
{
    let len = iter.map(|x| x.mls_encoded_len()).sum::<usize>();

    let header_length = VarInt::try_from(len)
        .expect("exceeded max len of VarInt::MAX")
        .mls_encoded_len();

    header_length + len
}

pub fn mls_encode<T>(
    mut iter: impl Iterator<Item = T>,
    writer: &mut Vec<u8>,
) -> Result<(), crate::Error>
where
    T: MlsEncode,
{
    let mut buffer = Vec::new();

    iter.try_for_each(|x| x.mls_encode(&mut buffer))?;

    let len = VarInt::try_from(buffer.len())?;

    len.mls_encode(writer)?;
    writer.extend(buffer);

    Ok(())
}

pub fn mls_decode_collection<T, F>(reader: &mut &[u8], item_decode: F) -> Result<T, crate::Error>
where
    F: Fn(&mut &[u8]) -> Result<T, crate::Error>,
{
    let len = VarInt::mls_decode(reader)?.0 as usize;

    (len <= reader.len())
        .then_some(())
        .ok_or(crate::Error::UnexpectedEOF)?;

    let (mut data, rest) = reader.split_at(len);

    let items = item_decode(&mut data)?;

    *reader = rest;

    Ok(items)
}
