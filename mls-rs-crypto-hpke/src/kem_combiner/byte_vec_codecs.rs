use alloc::vec::Vec;

use mls_rs_core::mls_rs_codec::{MlsDecode, MlsEncode};

use crate::kem_combiner::ghp::{ByteVecCodec, ByteVecEncoder};
use crate::kem_combiner::Error;

#[derive(Debug, Clone)]
pub struct MlsByteVecCodec;

impl<const N: usize> ByteVecEncoder<N> for MlsByteVecCodec {
    type Error = Error;

    fn encode(&self, data: [&[u8]; N]) -> Result<Vec<u8>, Error> {
        data.mls_encode_to_vec().map_err(Error::MlsCodecError)
    }
}

impl<const N: usize> ByteVecCodec<N> for MlsByteVecCodec {
    fn decode(&self, data: &[u8]) -> Result<[Vec<u8>; N], Error> {
        let vecs = Vec::<Vec<u8>>::mls_decode(&mut &*data).map_err(Error::MlsCodecError)?;

        vecs.try_into()
            .map_err(|vecs: Vec<Vec<u8>>| Error::InvalidInputLength(vecs.len()))
    }
}

/// The concatenation codec for two chunks to instantiate [GhpKemCombiner] as specified in the
/// [RFC draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems)
/// with input KEM's whose ciphertexts and public / secret keys are of fixed size.
#[derive(Debug, Clone)]
pub struct CatCodec2 {
    pub chunk_lengths: [usize; 2],
}

/// The concatenation codec for seven chunks to instantiate [GhpKemCombiner] as specified in the
/// [RFC draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems)
/// with input KEM's whose ciphertexts and public / secret keys are of fixed size.
#[derive(Debug, Clone)]
pub struct CatCodec7 {
    pub chunk_lengths: [usize; 7],
}

impl ByteVecEncoder<2> for CatCodec2 {
    type Error = Error;

    fn encode(&self, data: [&[u8]; 2]) -> Result<Vec<u8>, Error> {
        Ok(data.concat())
    }
}

impl ByteVecCodec<2> for CatCodec2 {
    fn decode(&self, data: &[u8]) -> Result<[Vec<u8>; 2], Error> {
        if data.len() != self.chunk_lengths.iter().sum::<usize>() {
            return Err(Error::InvalidKeyData);
        }

        let (first, second) = data.split_at(self.chunk_lengths[0]);

        Ok([first.to_vec(), second.to_vec()])
    }
}

impl ByteVecEncoder<7> for CatCodec7 {
    type Error = Error;

    fn encode(&self, data: [&[u8]; 7]) -> Result<Vec<u8>, Error> {
        Ok(data.concat())
    }
}

#[cfg(test)]
mod tests {
    use crate::kem_combiner::{
        byte_vec_codecs::{CatCodec2, CatCodec7, MlsByteVecCodec},
        ghp::{ByteVecCodec, ByteVecEncoder},
    };

    #[test]
    fn mls_byte_vec_codec() {
        let data = [b"hello".as_slice(), b"world"];
        let encoded = MlsByteVecCodec.encode(data).unwrap();
        let [decoded1, decoded2] = MlsByteVecCodec.decode(&encoded).unwrap();
        assert_eq!(data, [decoded1, decoded2]);
    }

    #[test]
    fn cat_codec_2() {
        let data = [b"hello".as_slice(), b"world!"];

        let codec = CatCodec2 {
            chunk_lengths: [5, 6],
        };

        let encoded = codec.encode(data).unwrap();
        let [decoded1, decoded2] = codec.decode(&encoded).unwrap();
        assert_eq!(data, [decoded1, decoded2]);
    }

    #[test]
    fn cat_codec_7() {
        let data = [
            b"1".as_slice(),
            b"12",
            b"123",
            b"1234",
            b"12345",
            b"123456",
            b"1234567",
        ];

        let codec = CatCodec7 {
            chunk_lengths: [1, 2, 3, 4, 5, 6, 7],
        };

        let encoded = codec.encode(data).unwrap();
        assert_eq!(encoded, b"1121231234123451234561234567");
    }
}
