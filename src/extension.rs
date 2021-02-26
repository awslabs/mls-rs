use serde::{Serialize, Deserialize};
use serde::de::{DeserializeOwned};
use crate::protocol_version::ProtocolVersion;
use thiserror::Error;
use crate::extension::ExtensionError::IncorrectExtensionType;
use std::time::{SystemTime, SystemTimeError};
use crate::ciphersuite::CipherSuite;
use std::convert::TryFrom;
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Error, Debug)]
pub enum ExtensionError {
    #[error("Bad extension type")]
    IncorrectExtensionType(ExtensionId),
    #[error("Serialization failure {0}")]
    BincodeError(#[from] bincode::Error)
}

#[derive(IntoPrimitive, TryFromPrimitive, Clone, Debug, PartialEq, Deserialize, Serialize)]
#[repr(u16)]
#[serde(into = "u16", try_from = "u16")]
pub enum ExtensionId {
    Capabilities = 0x0001,
    Lifetime = 0x0002,
    KeyId = 0x0003,
    ParentHash = 0x0004,
    RatchetTree = 0x0005,
}

pub trait ExtensionTrait: Sized + Serialize + DeserializeOwned {
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KeyId<T> {
    pub identifier: T,
}

impl <T: DeserializeOwned + Serialize> ExtensionTrait for KeyId<T> {
    const IDENTIFIER: ExtensionId = ExtensionId::KeyId;
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Capabilities {
    pub protocol_versions: Vec<ProtocolVersion>,
    pub ciphersuites: Vec<CipherSuite>,
    pub extensions: Vec<ExtensionId>,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            protocol_versions: vec![ProtocolVersion::Mls10],
            ciphersuites: vec![
                CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
                CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
            ],
            extensions: vec![ExtensionId::Capabilities, ExtensionId::KeyId, ExtensionId::Lifetime]
        }
    }
}

impl ExtensionTrait for Capabilities {
    const IDENTIFIER: ExtensionId = ExtensionId::Capabilities;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Lifetime {
    pub not_before: u64,
    pub not_after: u64
}

impl Lifetime {
    pub fn days(d: u64, from: SystemTime) -> Result<Self, SystemTimeError> {
        let start_time = from.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();

        Ok(Lifetime {
            not_before: start_time,
            not_after: d * 86400 + start_time
        })
    }
}

impl ExtensionTrait for Lifetime {
    const IDENTIFIER: ExtensionId = ExtensionId::Lifetime;
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Extension {
    pub extension_id: ExtensionId,
    pub data: Vec<u8>
}

#[cfg(test)]
mod tests {
    use crate::extension::{ExtensionId, KeyId, Capabilities, ExtensionTrait, Extension, ExtensionError};
    use crate::protocol_version::ProtocolVersion;
    use crate::extension::Lifetime;
    use std::time::{SystemTime, Duration};
    use std::ops::Add;
    use crate::ciphersuite::CipherSuite;

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
        let test_ciphersuites = vec![CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256, CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519];
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
    fn test_lifetime() {
        let lifetime = Lifetime::days(1, SystemTime::UNIX_EPOCH
            .add(Duration::from_secs(1)))
            .expect("lifetime failure");

        assert_eq!(lifetime.not_before, 1);
        assert_eq!(lifetime.not_after, 86401);

        let as_extension = lifetime.to_extension().expect("to extension error");
        assert_eq!(as_extension.extension_id, ExtensionId::Lifetime);

        let restored = Lifetime::from_extension(as_extension).expect("from extension error");
        assert_eq!(lifetime.not_after, restored.not_after);
        assert_eq!(lifetime.not_before, restored.not_before);
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



