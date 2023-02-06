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
pub struct ExtensionType(u16);

impl ExtensionType {
    pub fn new(raw_value: u16) -> Self {
        ExtensionType(raw_value)
    }

    pub fn raw_value(&self) -> u16 {
        self.0
    }

    pub fn is_default(&self) -> bool {
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
pub struct Extension {
    pub extension_type: ExtensionType,
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "crate::serde::vec_u8_as_base64::VecAsBase64")]
    pub extension_data: Vec<u8>,
}

impl Extension {
    pub fn new(extension_type: ExtensionType, extension_data: Vec<u8>) -> Extension {
        Extension {
            extension_type,
            extension_data,
        }
    }
}

pub trait MlsExtension: Sized {
    type SerializationError: std::error::Error + Send + Sync + 'static;
    type DeserializationError: std::error::Error + Send + Sync + 'static;

    fn extension_type() -> ExtensionType;

    fn to_bytes(&self) -> Result<Vec<u8>, Self::SerializationError>;
    fn from_bytes(data: &[u8]) -> Result<Self, Self::DeserializationError>;

    fn into_extension(self) -> Result<Extension, ExtensionError> {
        Ok(Extension::new(
            Self::extension_type(),
            self.to_bytes()
                .map_err(|e| ExtensionError::SerializationError(e.into()))?,
        ))
    }

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
