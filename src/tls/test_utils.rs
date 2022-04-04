use tls_codec::{Deserialize, Serialize};

/// Serializes and deserializes its parameter.
pub fn ser_deser<T: Serialize + Deserialize>(x: &T) -> Result<T, tls_codec::Error> {
    T::tls_deserialize(&mut &*x.tls_serialize_detached()?)
}
