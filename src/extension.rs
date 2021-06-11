use crate::ciphersuite::CipherSuite;
use crate::extension::ExtensionError::IncorrectExtensionType;
use crate::protocol_version::ProtocolVersion;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};
use thiserror::Error;
use crate::tree_kem::parent_hash::ParentHash;

#[derive(Error, Debug)]
pub enum ExtensionError {
    #[error("Bad extension type")]
    IncorrectExtensionType(ExtensionId),
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
    #[error(transparent)]
    SystemTimeError(#[from] SystemTimeError),
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
        Ok(Extension {
            extension_id: Self::IDENTIFIER,
            data: bincode::serialize(self)?,
        })
    }

    fn from_extension(extension: Extension) -> Result<Self, ExtensionError> {
        if extension.extension_id != Self::IDENTIFIER {
            Err(IncorrectExtensionType(extension.extension_id))
        } else {
            bincode::deserialize(&extension.data).map_err(|e| e.into())
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KeyId<T> {
    pub identifier: T,
}

impl<T: DeserializeOwned + Serialize> ExtensionTrait for KeyId<T> {
    const IDENTIFIER: ExtensionId = ExtensionId::KeyId;
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct CapabilitiesExt {
    pub protocol_versions: Vec<ProtocolVersion>,
    pub ciphersuites: Vec<CipherSuite>,
    pub extensions: Vec<ExtensionId>,
}

impl Default for CapabilitiesExt {
    fn default() -> Self {
        Self {
            protocol_versions: vec![ProtocolVersion::Mls10],
            ciphersuites: vec![
                CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256,
                CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519,
                CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519,
                CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521,
            ],
            extensions: vec![
                ExtensionId::Capabilities,
                ExtensionId::KeyId,
                ExtensionId::Lifetime,
            ],
        }
    }
}

impl ExtensionTrait for CapabilitiesExt {
    const IDENTIFIER: ExtensionId = ExtensionId::Capabilities;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LifetimeExt {
    pub not_before: u64,
    pub not_after: u64,
}

impl LifetimeExt {
    pub fn seconds(s: u64, from: SystemTime) -> Result<Self, ExtensionError> {
        let start_time = from.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();

        Ok(LifetimeExt {
            not_before: start_time,
            not_after: start_time + s,
        })
    }

    pub fn within_lifetime(&self, system_time: SystemTime) -> Result<bool, ExtensionError> {
        let since_epoch = system_time.duration_since(UNIX_EPOCH)?.as_secs();
        Ok(since_epoch >= self.not_before && since_epoch <= self.not_after)
    }
}

impl ExtensionTrait for LifetimeExt {
    const IDENTIFIER: ExtensionId = ExtensionId::Lifetime;
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Extension {
    pub extension_id: ExtensionId,
    pub data: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ExtensionList(pub Vec<Extension>);

impl Deref for ExtensionList {
    type Target = Vec<Extension>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ExtensionList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ExtensionList {
    pub fn get_extension<T: ExtensionTrait>(&self) -> Result<Option<T>, ExtensionError> {
        let ext = self.iter().find(|v| v.extension_id == T::IDENTIFIER);

        if let Some(ext) = ext {
            Ok(Some(bincode::deserialize(&ext.data)?))
        } else {
            Ok(None)
        }
    }

    pub fn set_extension<T: ExtensionTrait>(&mut self, ext: T) -> Result<(), ExtensionError> {
        match self
            .iter_mut()
            .find(|v| v.extension_id == T::IDENTIFIER)
        {
            None => Ok(self.push(ext.to_extension()?)),
            Some(existing) => Ok(*existing = ext.to_extension()?)
        }
    }

    pub fn get_lifetime(&self) -> Result<Option<LifetimeExt>, ExtensionError> {
        self.get_extension()
    }

    pub fn get_parent_hash(&self) -> Result<Option<ParentHashExt>, ExtensionError> {
        self.get_extension()
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphersuite::CipherSuite;
    use crate::extension::LifetimeExt;
    use crate::extension::{
        CapabilitiesExt, Extension, ExtensionError, ExtensionId, ExtensionTrait, KeyId,
    };
    use crate::protocol_version::ProtocolVersion;
    use std::ops::Add;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_key_extension() {
        let test_id = 42;
        let test_extension = KeyId {
            identifier: test_id,
        };

        let as_extension = test_extension.to_extension().expect("serialization error");
        assert_eq!(as_extension.extension_id, ExtensionId::KeyId);

        let restored: KeyId<i32> =
            KeyId::from_extension(as_extension).expect("deserialization error");
        assert_eq!(restored.identifier, test_id);
    }

    #[test]
    fn test_capabilities() {
        let test_protocol_versions = vec![ProtocolVersion::Mls10];
        let test_ciphersuites = vec![
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256,
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519,
        ];
        let test_extensions = vec![
            ExtensionId::ParentHash,
            ExtensionId::Lifetime,
            ExtensionId::KeyId,
        ];

        let test_extension = CapabilitiesExt {
            protocol_versions: test_protocol_versions.clone(),
            ciphersuites: test_ciphersuites.clone(),
            extensions: test_extensions.clone(),
        };

        let as_extension = test_extension.to_extension().expect("serialization error");
        assert_eq!(as_extension.extension_id, ExtensionId::Capabilities);

        let restored = CapabilitiesExt::from_extension(as_extension).expect("deserialization error");
        assert_eq!(restored.protocol_versions, test_protocol_versions);
        assert_eq!(restored.ciphersuites, test_ciphersuites);
        assert_eq!(restored.extensions, test_extensions);
    }

    #[test]
    fn test_lifetime() {
        let lifetime = LifetimeExt::seconds(1, SystemTime::UNIX_EPOCH.add(Duration::from_secs(1)))
            .expect("lifetime failure");

        assert_eq!(lifetime.not_before, 1);
        assert_eq!(lifetime.not_after, 2);

        let as_extension = lifetime.to_extension().expect("to extension error");
        assert_eq!(as_extension.extension_id, ExtensionId::Lifetime);

        let restored = LifetimeExt::from_extension(as_extension).expect("from extension error");
        assert_eq!(lifetime.not_after, restored.not_after);
        assert_eq!(lifetime.not_before, restored.not_before);
    }

    #[test]
    fn test_bad_deserialize_data() {
        let bad_data = vec![255u8; 32];
        let test_extension = Extension {
            extension_id: ExtensionId::KeyId,
            data: bad_data.clone(),
        };
        let key_id: Result<KeyId<CapabilitiesExt>, ExtensionError> =
            KeyId::from_extension(test_extension);
        assert_eq!(key_id.is_err(), true);
    }

    #[test]
    fn test_bad_deserialize_type() {
        let test_extension = Extension {
            extension_id: ExtensionId::KeyId,
            data: vec![0u8; 32],
        };
        assert_eq!(CapabilitiesExt::from_extension(test_extension).is_err(), true);
    }
}
