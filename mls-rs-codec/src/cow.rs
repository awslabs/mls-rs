use alloc::borrow::Cow;

use crate::{Error, MlsDecode, MlsEncode, MlsSize};

impl<'a, T> MlsSize for Cow<'a, T>
where
    T: MlsSize + ToOwned,
{
    fn mls_encoded_len(&self) -> usize {
        self.as_ref().mls_encoded_len()
    }
}

impl<'a, T> MlsEncode for Cow<'a, T>
where
    T: MlsEncode + ToOwned,
{
    #[inline]
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), Error> {
        self.as_ref().mls_encode(writer)
    }
}

impl<'a, T> MlsDecode for Cow<'a, T>
where
    T: MlsDecode + ToOwned<Owned = T>,
{
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, Error> {
        T::mls_decode(reader).map(Cow::Owned)
    }
}
