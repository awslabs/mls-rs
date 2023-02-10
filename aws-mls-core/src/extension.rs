use std::ops::Deref;

use serde_with::serde_as;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

mod list;

pub use list::*;

#[derive(
    Debug,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Copy,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// Wrapper type representing an extension identifier along with default values
/// defined by the MLS RFC.
pub struct ExtensionType(u16);

impl ExtensionType {
    pub const APPLICATION_ID: ExtensionType = ExtensionType(1);
    pub const RATCHET_TREE: ExtensionType = ExtensionType(2);
    pub const REQUIRED_CAPABILITIES: ExtensionType = ExtensionType(3);
    pub const EXTERNAL_PUB: ExtensionType = ExtensionType(4);
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

#[derive(Debug, Error)]
pub enum ExtensionError {
    #[error(transparent)]
    SerializationError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    DeserializationError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("incorrect extension type: {0:?}, expecting: {1:?}")]
    IncorrectType(ExtensionType, ExtensionType),
}

#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
/// An MLS protocol [extension](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-extensions).
///
/// Extensions are used as customization points in various parts of the
/// MLS protocol and are inserted into an [ExtensionList](self::ExtensionList).
pub struct Extension {
    pub(crate) extension_type: ExtensionType,
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "crate::serde::vec_u8_as_base64::VecAsBase64")]
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
    type SerializationError: std::error::Error + Send + Sync + 'static;

    /// Error type of the underlying deserializer that can convert a Vec<u8> into this type.
    type DeserializationError: std::error::Error + Send + Sync + 'static;

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
                .map_err(|e| ExtensionError::SerializationError(e.into()))?,
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
            .map_err(|e| ExtensionError::DeserializationError(e.into()))
    }
}

/// Convenience trait for custom extension types that use
/// [tls_codec](self::tls_codec) as an underlying serialization mechanism
pub trait TlsCodecExtension:
    tls_codec::Serialize + tls_codec::Deserialize + tls_codec::Size
{
    fn extension_type() -> ExtensionType;
}

impl<T> MlsExtension for T
where
    T: TlsCodecExtension,
{
    type SerializationError = tls_codec::Error;
    type DeserializationError = tls_codec::Error;

    fn extension_type() -> ExtensionType {
        <Self as TlsCodecExtension>::extension_type()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, Self::SerializationError> {
        self.tls_serialize_detached()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, Self::DeserializationError> {
        Self::tls_deserialize(&mut &*data)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use assert_matches::assert_matches;
    use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

    use super::{Extension, ExtensionError, ExtensionType, MlsExtension, TlsCodecExtension};

    struct TestExtension;

    #[derive(Debug, TlsSerialize, TlsSize, TlsDeserialize)]
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

    impl TlsCodecExtension for AnotherTestExtension {
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
