pub use aws_mls_core::extension::{
    ExtensionListIter, ExtensionType, MlsCodecExtension, MlsExtension,
};

pub(crate) use built_in::*;

/// Default extension types required by the MLS RFC.
pub mod built_in;

#[cfg(any(test, feature = "benchmark"))]
pub(crate) mod test_utils {
    use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
    use aws_mls_core::extension::MlsExtension;
    use std::convert::Infallible;
    use std::fmt::Debug;

    use super::*;

    pub const TEST_EXTENSION_TYPE: u16 = 42;

    #[derive(MlsSize, MlsEncode, MlsDecode, Clone, Debug, PartialEq)]
    pub(crate) struct TestExtension {
        pub(crate) foo: u8,
    }

    impl From<u8> for TestExtension {
        fn from(value: u8) -> Self {
            Self { foo: value }
        }
    }

    impl MlsExtension for TestExtension {
        type SerializationError = Infallible;

        type DeserializationError = Infallible;

        fn extension_type() -> ExtensionType {
            ExtensionType::from(TEST_EXTENSION_TYPE)
        }

        fn to_bytes(&self) -> Result<Vec<u8>, Self::SerializationError> {
            Ok([self.foo].to_vec())
        }

        fn from_bytes(data: &[u8]) -> Result<Self, Self::DeserializationError> {
            Ok(TestExtension { foo: data[0] })
        }
    }
}
