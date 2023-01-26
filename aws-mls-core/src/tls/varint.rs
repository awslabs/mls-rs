use std::{
    fmt::{self, Debug, Display},
    io::{Read, Write},
};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize, Size};

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VarInt(u32);

impl VarInt {
    pub const MAX: VarInt = VarInt((1 << 30) - 1);
}

impl Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Debug for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self, f)
    }
}

impl From<VarInt> for u32 {
    fn from(n: VarInt) -> u32 {
        n.0
    }
}

impl TryFrom<VarInt> for usize {
    type Error = std::num::TryFromIntError;

    fn try_from(n: VarInt) -> Result<usize, Self::Error> {
        u32::from(n).try_into()
    }
}

impl TryFrom<u32> for VarInt {
    type Error = VarIntOutOfRange;

    fn try_from(n: u32) -> Result<Self, VarIntOutOfRange> {
        (n <= u32::from(VarInt::MAX))
            .then_some(VarInt(n))
            .ok_or(VarIntOutOfRange)
    }
}

impl TryFrom<usize> for VarInt {
    type Error = VarIntOutOfRange;

    fn try_from(n: usize) -> Result<Self, VarIntOutOfRange> {
        u32::try_from(n).map_err(|_| VarIntOutOfRange)?.try_into()
    }
}

#[derive(Debug, Error)]
#[error("Integer out of range for VarInt (range is [0, {}])", VarInt::MAX)]
pub struct VarIntOutOfRange;

impl Size for VarInt {
    fn tls_serialized_len(&self) -> usize {
        count_bytes_to_encode_int(*self) as usize
    }
}

impl Serialize for VarInt {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut bytes = self.0.to_be_bytes();
        let bytes = match count_bytes_to_encode_int(*self) {
            LengthEncoding::One => &bytes[3..],
            LengthEncoding::Two => {
                bytes[2] |= 0x40;
                &bytes[2..]
            }
            LengthEncoding::Four => {
                bytes[0] |= 0x80;
                &bytes
            }
        };
        writer.write_all(bytes)?;
        Ok(bytes.len())
    }
}

impl Deserialize for VarInt {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let first = u8::tls_deserialize(bytes)?;
        let prefix = first >> 6;
        let count = (prefix < 3).then_some(1 << prefix).ok_or_else(|| {
            tls_codec::Error::DecodingError(format!("Invalid VarInt prefix {prefix}"))
        })?;
        let n = (1..count).try_fold(u32::from(first & 0x3f), |n, _| {
            u8::tls_deserialize(bytes).map(|b| n << 8 | u32::from(b))
        })?;
        let n = VarInt(n);
        if n.tls_serialized_len() == count {
            Ok(n)
        } else {
            Err(tls_codec::Error::DecodingError(
                "Invalid VarInt that does not use the minimum-length encoding".into(),
            ))
        }
    }
}

/// Number of bytes to encode a variable-size integer.
#[derive(Debug)]
enum LengthEncoding {
    One = 1,
    Two = 2,
    Four = 4,
}

fn count_bytes_to_encode_int(n: VarInt) -> LengthEncoding {
    let used_bits = 32 - n.0.leading_zeros();
    match used_bits {
        0..=6 => LengthEncoding::One,
        7..=14 => LengthEncoding::Two,
        15..=30 => LengthEncoding::Four,
        _ => panic!("Such a large VarInt cannot be instantiated ({n})"),
    }
}

#[cfg(test)]
mod tests {
    use super::{VarInt, VarIntOutOfRange};
    use crate::tls::test_utils::ser_deser;
    use assert_matches::assert_matches;
    use tls_codec::{Deserialize, Serialize};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn zero_is_convertible_to_varint() {
        assert_matches!(VarInt::try_from(0u32).map(u32::from), Ok(0));
    }

    #[test]
    fn successor_of_max_varint_is_not_convertible_to_varint() {
        let n = u32::from(VarInt::MAX) + 1;
        assert_matches!(VarInt::try_from(n), Err(VarIntOutOfRange));
    }

    #[test]
    fn zero_serializes_as_single_null_byte() {
        assert_eq!(
            VarInt::try_from(0u32)
                .unwrap()
                .tls_serialize_detached()
                .unwrap(),
            [0]
        );
    }

    #[test]
    fn zero_roundtrips() {
        let n = VarInt::try_from(0u32).unwrap();
        assert_eq!(ser_deser(&n).unwrap(), n);
    }

    #[test]
    fn varint_max_roundtrips() {
        assert_eq!(ser_deser(&VarInt::MAX).unwrap(), VarInt::MAX);
    }

    fn decoding_matches_rfc(encoded: u32, decoded: u32) {
        let bytes = encoded.to_be_bytes();
        let start = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let mut bytes = &bytes[start..];
        assert_eq!(
            VarInt::tls_deserialize(&mut bytes).unwrap(),
            VarInt::try_from(decoded).unwrap()
        );
    }

    #[test]
    fn decoding_0x25_matches_rfc_result() {
        decoding_matches_rfc(0x25, 37);
    }

    #[test]
    fn decoding_0x7bbd_matches_rfc_result() {
        decoding_matches_rfc(0x7bbd, 15293);
    }

    #[test]
    fn decoding_0x9d7f3e7d_matches_rfc_result() {
        decoding_matches_rfc(0x9d7f3e7d, 494878333);
    }
}
