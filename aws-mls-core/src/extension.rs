use core::ops::Deref;

use crate::error::{AnyError, IntoAnyError};
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};

mod list;

pub use list::*;

#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd, Ord, MlsSize, MlsEncode, MlsDecode,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// Wrapper type representing an extension identifier along with default values
/// defined by the MLS RFC.
pub struct ExtensionType(u16);

impl ExtensionType {
    pub const APPLICATION_ID: ExtensionType = ExtensionType(1);
    pub const RATCHET_TREE: ExtensionType = ExtensionType(2);
    pub const REQUIRED_CAPABILITIES: ExtensionType = ExtensionType(3);
    #[cfg(feature = "external_commit")]
    pub const EXTERNAL_PUB: ExtensionType = ExtensionType(4);
    #[cfg(feature = "external_proposal")]
    pub const EXTERNAL_SENDERS: ExtensionType = ExtensionType(5);

    /// Extension type from a raw value
    pub const fn new(raw_value: u16) -> Self {
        ExtensionType(raw_value)
    }

    /// Raw numerical wrapped value.
    pub const fn raw_value(&self) -> u16 {
        self.0
    }

    /// Determines if this extension type is required to be implemented
    /// by the MLS RFC.
    pub const fn is_default(&self) -> bool {
        self.0 <= 5
    }
}

impl From<u16> for ExtensionType {
    fn from(value: u16) -> Self {
        ExtensionType(value)
    }
}

impl Deref for ExtensionType {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum ExtensionError {
    #[cfg_attr(feature = "std", error(transparent))]
    SerializationError(AnyError),
    #[cfg_attr(feature = "std", error(transparent))]
    DeserializationError(AnyError),
    #[cfg_attr(
        feature = "std",
        error("incorrect extension type: {0:?}, expecting: {1:?}")
    )]
    IncorrectType(ExtensionType, ExtensionType),
}

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
/// An MLS protocol [extension](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-extensions).
///
/// Extensions are used as customization points in various parts of the
/// MLS protocol and are inserted into an [ExtensionList](self::ExtensionList).
pub struct Extension {
    pub(crate) extension_type: ExtensionType,
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub(crate) extension_data: Vec<u8>,
}

impl Extension {
    /// Create an extension with specified type and data properties.
    pub fn new(extension_type: ExtensionType, extension_data: Vec<u8>) -> Extension {
        Extension {
            extension_type,
            extension_data,
        }
    }

    /// Extension type of this extension
    pub fn extension_type(&self) -> ExtensionType {
        self.extension_type
    }

    /// Data held within this extension
    pub fn extension_data(&self) -> &[u8] {
        &self.extension_data
    }
}

/// Trait used to convert a type to and from an [Extension](self::Extension)
pub trait MlsExtension: Sized {
    /// Error type of the underlying serializer that can convert this type into a `Vec<u8>`.
    type SerializationError: IntoAnyError;

    /// Error type of the underlying deserializer that can convert a `Vec<u8>` into this type.
    type DeserializationError: IntoAnyError;

    /// Extension type value that this type represents.
    fn extension_type() -> ExtensionType;

    /// Convert this type to opaque bytes.
    fn to_bytes(&self) -> Result<Vec<u8>, Self::SerializationError>;

    /// Create this type from opaque bytes.
    fn from_bytes(data: &[u8]) -> Result<Self, Self::DeserializationError>;

    /// Convert this type into an [Extension](self::Extension).
    fn into_extension(self) -> Result<Extension, ExtensionError> {
        Ok(Extension::new(
            Self::extension_type(),
            self.to_bytes()
                .map_err(|e| ExtensionError::SerializationError(e.into_any_error()))?,
        ))
    }

    /// Create this type from an [Extension](self::Extension).
    fn from_extension(ext: &Extension) -> Result<Self, ExtensionError> {
        if ext.extension_type != Self::extension_type() {
            return Err(ExtensionError::IncorrectType(
                ext.extension_type,
                Self::extension_type(),
            ));
        }

        Self::from_bytes(&ext.extension_data)
            .map_err(|e| ExtensionError::DeserializationError(e.into_any_error()))
    }
}

/// Convenience trait for custom extension types that use
/// [aws_mls_codec](crate::aws_mls_codec) as an underlying serialization mechanism
pub trait MlsCodecExtension: MlsSize + MlsEncode + MlsDecode {
    fn extension_type() -> ExtensionType;
}

impl<T> MlsExtension for T
where
    T: MlsCodecExtension,
{
    type SerializationError = aws_mls_codec::Error;
    type DeserializationError = aws_mls_codec::Error;

    fn extension_type() -> ExtensionType {
        <Self as MlsCodecExtension>::extension_type()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Self::SerializationError> {
        self.mls_encode_to_vec()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, Self::DeserializationError> {
        Self::mls_decode(&mut &*data)
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use alloc::vec;
    use alloc::vec::Vec;
    use assert_matches::assert_matches;
    use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};

    use super::{Extension, ExtensionError, ExtensionType, MlsCodecExtension, MlsExtension};

    struct TestExtension;

    #[derive(Debug, MlsSize, MlsEncode, MlsDecode)]
    struct AnotherTestExtension;

    impl MlsExtension for TestExtension {
        type SerializationError = Infallible;
        type DeserializationError = Infallible;

        fn extension_type() -> super::ExtensionType {
            ExtensionType(42)
        }

        fn to_bytes(&self) -> Result<Vec<u8>, Self::SerializationError> {
            Ok(vec![0])
        }

        fn from_bytes(_data: &[u8]) -> Result<Self, Self::DeserializationError> {
            Ok(TestExtension)
        }
    }

    impl MlsCodecExtension for AnotherTestExtension {
        fn extension_type() -> ExtensionType {
            ExtensionType(43)
        }
    }

    #[test]
    fn into_extension() {
        assert_eq!(
            TestExtension.into_extension().unwrap(),
            Extension::new(42.into(), vec![0])
        )
    }

    #[test]
    fn incorrect_type_is_discovered() {
        let ext = Extension::new(42.into(), vec![0]);

        assert_matches!(AnotherTestExtension::from_extension(&ext), Err(ExtensionError::IncorrectType(found, expected)) if found == 42.into() && expected == 43.into());
    }
}
