use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

pub use aws_mls_core::identity::*;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct BasicCredentialError(#[from] tls_codec::Error);

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct BasicCredential {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub credential: Vec<u8>,
}

impl BasicCredential {
    pub fn credential_type() -> aws_mls_core::identity::CredentialType {
        CredentialType::new(1)
    }

    pub fn into_credential(self) -> Result<Credential, BasicCredentialError> {
        Ok(Credential {
            credential_type: BasicCredential::credential_type(),
            credential_data: self.tls_serialize_detached()?,
        })
    }
}

impl MlsCredential for BasicCredential {
    type Error = BasicCredentialError;

    fn credential_type() -> aws_mls_core::identity::CredentialType {
        Self::credential_type()
    }

    fn into_credential(self) -> Result<Credential, Self::Error> {
        self.into_credential()
    }
}

#[cfg(any(test, feature = "benchmark"))]
pub mod test_utils {
    use aws_mls_core::{
        crypto::{CipherSuite, CipherSuiteProvider, SignatureSecretKey},
        identity::{Credential, SigningIdentity},
    };

    use crate::provider::crypto::test_utils::test_cipher_suite_provider;

    use super::BasicCredential;

    pub const INVALID_CREDENTIAL_TYPE: u16 = 42;

    pub fn get_test_signing_identity(
        cipher_suite: CipherSuite,
        identity: Vec<u8>,
    ) -> (SigningIdentity, SignatureSecretKey) {
        let provider = test_cipher_suite_provider(cipher_suite);
        let (secret_key, public_key) = provider.signature_key_generate().unwrap();

        let basic = get_test_basic_credential(identity);

        (SigningIdentity::new(basic, public_key), secret_key)
    }

    pub fn get_test_basic_credential(identity: Vec<u8>) -> Credential {
        let cred = BasicCredential {
            credential: identity,
        };

        cred.into_credential().unwrap()
    }
}
