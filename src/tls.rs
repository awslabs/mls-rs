//! Helpers to support TLS-serializing foreign types
//!
//! Multiple foreign types used throughout this crate do not implement the `tls_codec` traits.
//! To avoid having to manually implement these traits for many types defined in this crate and be
//! able to derive them instead, `#[tls_codec(with = "path")]` is used to specify how these
//! foreign types are serialized.
//!
//! This module defines helper types that can be composed to customize how fields are serialized
//! thanks to the `with` attribute. Traits mirroring the `tls_codec` traits are defined to make this
//! composition possible.

use std::io::{Read, Write};

mod boolean;
mod byte_vec;
mod certificate_chain;
mod default;
mod map;
mod optional;
mod secret_key;
#[cfg(test)]
mod test_util;
mod vector;

pub use boolean::Boolean;
pub use byte_vec::ByteVec;
pub use certificate_chain::CertificateChainSer;
pub use default::DefaultSer;
pub use map::{DefMap, Map};
pub use optional::Optional;
pub use secret_key::SecretKeySer;
pub use vector::{DefVec, Vector};

/// Helper trait to derive [`tls_codec::Size`] when foreign types not implementing `Size` are
/// involved.
///
/// The methods mirror the methods from `Size`.
pub trait Sizer<T: ?Sized> {
    fn serialized_len(x: &T) -> usize;
}

/// Helper trait to derive [`tls_codec::Serialize`] when foreign types not implementing `Serialize`
/// are involved.
///
/// The methods mirror the methods from `Serialize`.
pub trait Serializer<T: ?Sized> {
    fn serialize<W: Write>(x: &T, writer: &mut W) -> Result<usize, tls_codec::Error>;
}

/// Helper trait to derive [`tls_codec::Deserialize`] when foreign types not implementing
/// `Deserialize` are involved.
///
/// The methods mirror the methods from `Deserialize`.
pub trait Deserializer<T> {
    fn deserialize<R: Read>(reader: &mut R) -> Result<T, tls_codec::Error>;
}
