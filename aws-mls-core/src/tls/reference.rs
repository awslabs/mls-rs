use crate::tls::{DefaultSer, Serializer, Sizer};
use std::io::Write;

/// Adapter for [`tls_codec::Size`] and [`tls_codec::Serialize`] for references to values whose
/// type implements these traits.
pub struct Ref<S = DefaultSer>(S);

pub type DefRef = Ref;

impl<S> Ref<S> {
    pub fn tls_serialized_len<T>(x: &&T) -> usize
    where
        S: Sizer<T>,
    {
        S::serialized_len(x)
    }

    pub fn tls_serialize<W, T>(x: &&T, writer: &mut W) -> Result<usize, tls_codec::Error>
    where
        S: Serializer<T>,
        W: Write,
    {
        S::serialize(x, writer)
    }
}

impl<'a, S, T> Sizer<&'a T> for Ref<S>
where
    S: Sizer<T>,
{
    fn serialized_len(x: &&'a T) -> usize {
        Self::tls_serialized_len(x)
    }
}

impl<'a, S, T> Serializer<&'a T> for Ref<S>
where
    S: Serializer<T>,
{
    fn serialize<W: Write>(x: &&'a T, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(x, writer)
    }
}
