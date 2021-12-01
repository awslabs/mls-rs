use std::io::{Read, Write};

mod boolean;
mod byte_vec;
mod default;
mod map;
mod optional;
mod secret_key;
mod vector;

pub use boolean::Boolean;
pub use byte_vec::ByteVec;
pub use default::DefaultSer;
pub use map::{DefMap, Map};
pub use optional::Optional;
pub use secret_key::SecretKeySer;
pub use vector::{DefVec, Vector};

pub trait Sizer<T: ?Sized> {
    fn serialized_len(x: &T) -> usize;
}

pub trait Serializer<T: ?Sized> {
    fn serialize<W: Write>(x: &T, writer: &mut W) -> Result<usize, tls_codec::Error>;
}

pub trait Deserializer<T> {
    fn deserialize<R: Read>(reader: &mut R) -> Result<T, tls_codec::Error>;
}
