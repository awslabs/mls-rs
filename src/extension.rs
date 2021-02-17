use serde::{Serialize, Deserialize};
use serde::de::{DeserializeOwned};
use num_derive::{ FromPrimitive, ToPrimitive };
use crate::protocol_version::ProtocolVersion;
use thiserror::Error;
use crate::ciphersuite::CipherSuiteId;
use crate::extension::ExtensionError::IncorrectExtensionType;

#[derive(Error, Debug)]
pub enum ExtensionError {
    #[error("Bad extension type")]
    IncorrectExtensionType(ExtensionId),
    #[error("Serialization failure {0}")]
    BincodeError(#[from] bincode::Error)
}

#[derive(Clone, FromPrimitive, ToPrimitive, Debug, PartialEq, Deserialize, Serialize)]
pub enum ExtensionId {
    Capabilities = 0x0001,
    Lifetime = 0x0002,
    KeyId = 0x0003,
    ParentHash = 0x0004,
    RatchetTree = 0x0005,
}

trait ExtensionTrait: Sized + Serialize + DeserializeOwned {
    const IDENTIFIER: ExtensionId;

    fn to_extension(&self) -> Result<Extension, ExtensionError> {
        Ok(Extension { extension_id: Self::IDENTIFIER, data: bincode::serialize(self)? })
    }

    fn from_extension(extension: Extension) -> Result<Self, ExtensionError> {
        if extension.extension_id != Self::IDENTIFIER {
            Err(IncorrectExtensionType(extension.extension_id))
        } else {
            bincode::deserialize(&extension.data)
                .map_err(|e| e.into())
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyId<T> {
    pub identifier: T,
}

impl <T: DeserializeOwned + Serialize> ExtensionTrait for KeyId<T> {
    const IDENTIFIER: ExtensionId = ExtensionId::KeyId;
}

#[derive(Serialize, Deserialize)]
pub struct Capabilities {
    pub protocol_versions: Vec<ProtocolVersion>,
    pub ciphersuites: Vec<CipherSuiteId>,
    pub extensions: Vec<ExtensionId>,
}

impl ExtensionTrait for Capabilities {
    const IDENTIFIER: ExtensionId = ExtensionId::Capabilities;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Extension {
    pub extension_id: ExtensionId,
    pub data: Vec<u8>
}

#[cfg(test)]
mod tests {
    use crate::extension::{ExtensionId, KeyId, Capabilities, ExtensionTrait, Extension, ExtensionError};
    use crate::protocol_version::ProtocolVersion;
    use crate::ciphersuite::CipherSuiteId;

    #[test]
    fn test_key_extension() {
        let test_id = 42;
        let test_extension = KeyId { identifier: test_id };

        let as_extension = test_extension.to_extension().expect("serialization error");
        assert_eq!(as_extension.extension_id, ExtensionId::KeyId);

        let restored: KeyId<i32> = KeyId::from_extension(as_extension).expect("deserialization error");
        assert_eq!(restored.identifier, test_id);
    }

    #[test]
    fn test_capabilities() {
        let test_protocol_versions = vec![ProtocolVersion::Mls10];
        let test_ciphersuites = vec![CipherSuiteId::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256, CipherSuiteId::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519];
        let test_extensions = vec![ExtensionId::ParentHash, ExtensionId::Lifetime, ExtensionId::KeyId];

        let test_extension = Capabilities {
            protocol_versions: test_protocol_versions.clone(),
            ciphersuites: test_ciphersuites.clone(),
            extensions: test_extensions.clone()
        };

        let as_extension = test_extension.to_extension().expect("serialization error");
        assert_eq!(as_extension.extension_id, ExtensionId::Capabilities);

        let restored = Capabilities::from_extension(as_extension).expect("deserialization error");
        assert_eq!(restored.protocol_versions, test_protocol_versions);
        assert_eq!(restored.ciphersuites, test_ciphersuites);
        assert_eq!(restored.extensions, test_extensions);
    }

    #[test]
    fn test_bad_deserialize_data() {
        let bad_data = vec![255u8; 32];
        let test_extension = Extension { extension_id: ExtensionId::KeyId, data: bad_data.clone() };
        let key_id: Result<KeyId<Capabilities>, ExtensionError> = KeyId::from_extension(test_extension);
        assert_eq!(key_id.is_err(), true);
    }

    #[test]
    fn test_bad_deserialize_type() {
        let test_extension = Extension { extension_id: ExtensionId::KeyId, data: vec![0u8; 32] };
        assert_eq!(Capabilities::from_extension(test_extension).is_err(), true);
    }
}



