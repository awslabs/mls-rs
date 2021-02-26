use crate::credential::Credential;
use crate::asym::{AsymmetricKeyError};
use crate::protocol_version::ProtocolVersion;
use crate::extension::{Extension, ExtensionError};
use crate::ciphersuite::{CipherSuite};
use serde::{Serialize, Deserialize};
use crate::signature::{SignatureError, Signable};
use thiserror::Error;
use std::convert::TryFrom;
use bincode::Options;

#[derive(Error, Debug)]
pub enum KeyPackageError {
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    AsymmetricKeyError(#[from] AsymmetricKeyError),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KeyPackageData {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub hpke_init_key: Vec<u8>,
    pub credential: Credential,
    pub extensions: Vec<Extension>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct KeyPackage {
    #[serde(flatten)]
    pub data: KeyPackageData,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct KeyPackageSecret {
    pub cipher_suite: CipherSuite,
    pub hpke_secret_key: Vec<u8>,
    pub extensions: Vec<Extension>
}

impl Signable for KeyPackageData {
    type E = bincode::Error;
    fn to_signable_vec(&self) -> Result<Vec<u8>, Self::E> {
        bincode::DefaultOptions::new().with_big_endian().serialize(self)
    }
}

impl TryFrom<Vec<u8>> for KeyPackageData {
    type Error = bincode::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        bincode::DefaultOptions::new().with_big_endian().deserialize(&value)
    }
}

#[cfg(test)]
mod test {
    use crate::key_package::KeyPackageData;
    use crate::protocol_version::ProtocolVersion;
    use crate::ciphersuite::CipherSuite;
    use crate::extension::{Lifetime, ExtensionTrait};
    use crate::credential::{BasicCredential, CredentialConvertable};
    use crate::signature::{SignatureSchemeId, Signable};
    use std::convert::TryFrom;

    #[test]
    fn test_signable_key_package_data() {
        let data = KeyPackageData {
            version: ProtocolVersion::Mls10,
            cipher_suite: CipherSuite::MLS10_TEST,
            hpke_init_key: vec![0u8; 4],
            credential: BasicCredential {
                identity: vec![0u8;4],
                signature_scheme: SignatureSchemeId::Test,
                signature_key: vec![0u8;4]
            }.to_credential(),
            extensions: vec![Lifetime { not_before: 42, not_after: 42 }.to_extension().unwrap()]
        };

        let serialized = data.to_signable_vec().expect("failed serialization");
        let restored = KeyPackageData::try_from(serialized)
            .expect("failed deserialization");
        assert_eq!(data, restored);
    }
}

