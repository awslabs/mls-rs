use crate::cipher_suite::{CipherSuite, ProtocolVersion};
use crate::extension::ExtensionError::IncorrectExtensionType;
use crate::tree_kem::parent_hash::ParentHash;
use std::ops::{Deref, DerefMut};
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum ExtensionError {
    #[error("Bad extension type")]
    IncorrectExtensionType(ExtensionId),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    SystemTimeError(#[from] SystemTimeError),
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum ExtensionId {
    Capabilities = 0x0001,
    Lifetime = 0x0002,
    KeyId = 0x0003,
    ParentHash = 0x0004,
    RatchetTree = 0x0005,
}

pub(crate) trait ExtensionTrait: Sized + Serialize + Deserialize {
    const IDENTIFIER: ExtensionId;

    fn to_extension(&self) -> Result<Extension, ExtensionError> {
        Ok(Extension {
            extension_id: Self::IDENTIFIER,
            data: self.tls_serialize_detached()?,
        })
    }

    fn from_extension(extension: Extension) -> Result<Self, ExtensionError> {
        if extension.extension_id != Self::IDENTIFIER {
            Err(IncorrectExtensionType(extension.extension_id))
        } else {
            Self::tls_deserialize(&mut &*extension.data).map_err(|e| e.into())
        }
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct KeyIdExt {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub identifier: Vec<u8>,
}

impl ExtensionTrait for KeyIdExt {
    const IDENTIFIER: ExtensionId = ExtensionId::KeyId;
}

#[derive(Clone, PartialEq, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct CapabilitiesExt {
    #[tls_codec(with = "crate::tls::DefVec::<u32>")]
    pub protocol_versions: Vec<ProtocolVersion>,
    #[tls_codec(with = "crate::tls::DefVec::<u32>")]
    pub cipher_suites: Vec<CipherSuite>,
    #[tls_codec(with = "crate::tls::DefVec::<u32>")]
    pub extensions: Vec<ExtensionId>,
}

impl Default for CapabilitiesExt {
    fn default() -> Self {
        Self {
            protocol_versions: vec![ProtocolVersion::Mls10],
            cipher_suites: vec![
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

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
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

    pub fn days(d: u32, from: SystemTime) -> Result<Self, ExtensionError> {
        Self::seconds((d * 86400) as u64, from)
    }

    pub fn years(y: u8, from: SystemTime) -> Result<Self, ExtensionError> {
        Self::days(365 * y as u32, from)
    }

    pub fn within_lifetime(&self, system_time: SystemTime) -> Result<bool, ExtensionError> {
        let since_epoch = system_time.duration_since(UNIX_EPOCH)?.as_secs();
        Ok(since_epoch >= self.not_before && since_epoch <= self.not_after)
    }
}

impl ExtensionTrait for LifetimeExt {
    const IDENTIFIER: ExtensionId = ExtensionId::Lifetime;
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct ParentHashExt {
    pub parent_hash: ParentHash,
}

impl From<ParentHash> for ParentHashExt {
    fn from(parent_hash: ParentHash) -> Self {
        Self { parent_hash }
    }
}

impl ExtensionTrait for ParentHashExt {
    const IDENTIFIER: ExtensionId = ExtensionId::ParentHash;
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Extension {
    pub extension_id: ExtensionId,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct ExtensionList(#[tls_codec(with = "crate::tls::DefVec::<u32>")] Vec<Extension>);

impl From<Vec<Extension>> for ExtensionList {
    fn from(v: Vec<Extension>) -> Self {
        Self(v)
    }
}

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
    pub(crate) fn get_extension<T: ExtensionTrait>(&self) -> Result<Option<T>, ExtensionError> {
        let ext = self.iter().find(|v| v.extension_id == T::IDENTIFIER);

        if let Some(ext) = ext {
            Ok(Some(T::tls_deserialize(&mut &*ext.data)?))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn set_extension<T: ExtensionTrait>(
        &mut self,
        ext: T,
    ) -> Result<(), ExtensionError> {
        match self.iter_mut().find(|v| v.extension_id == T::IDENTIFIER) {
            None => {
                self.push(ext.to_extension()?);
                Ok(())
            }
            Some(existing) => {
                *existing = ext.to_extension()?;
                Ok(())
            }
        }
    }

    pub(crate) fn get_lifetime(&self) -> Result<Option<LifetimeExt>, ExtensionError> {
        self.get_extension()
    }

    pub(crate) fn get_parent_hash(&self) -> Result<Option<ParentHashExt>, ExtensionError> {
        self.get_extension()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Add;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_key_id_extension() {
        let test_id = vec![0u8; 32];
        let test_extension = KeyIdExt {
            identifier: test_id.clone(),
        };

        let as_extension = test_extension.to_extension().unwrap();
        assert_eq!(as_extension.extension_id, ExtensionId::KeyId);

        let restored = KeyIdExt::from_extension(as_extension).unwrap();
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
            cipher_suites: test_ciphersuites.clone(),
            extensions: test_extensions.clone(),
        };

        let as_extension = test_extension.to_extension().expect("serialization error");
        assert_eq!(as_extension.extension_id, ExtensionId::Capabilities);

        let restored =
            CapabilitiesExt::from_extension(as_extension).expect("deserialization error");
        assert_eq!(restored.protocol_versions, test_protocol_versions);
        assert_eq!(restored.cipher_suites, test_ciphersuites);
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
            extension_id: ExtensionId::Capabilities,
            data: bad_data,
        };
        let capabilities: Result<CapabilitiesExt, ExtensionError> =
            CapabilitiesExt::from_extension(test_extension);
        assert!(capabilities.is_err());
    }

    #[test]
    fn test_bad_deserialize_type() {
        let test_extension = Extension {
            extension_id: ExtensionId::KeyId,
            data: vec![0u8; 32],
        };
        assert!(CapabilitiesExt::from_extension(test_extension).is_err());
    }
}
