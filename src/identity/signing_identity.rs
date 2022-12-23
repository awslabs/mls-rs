use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{identity::Credential, provider::crypto::SignaturePublicKey};

use super::{CredentialError, MlsCredential};

#[derive(
    Debug,
    Clone,
    Eq,
    Hash,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
pub struct SigningIdentity {
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
}

impl SigningIdentity {
    pub fn new(credential: Credential, signature_key: SignaturePublicKey) -> SigningIdentity {
        SigningIdentity {
            credential,
            signature_key,
        }
    }

    pub fn credential<C: MlsCredential>(&self) -> Result<C, CredentialError> {
        C::from_credential(&self.credential)
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.signature_key
    }
}

#[cfg(any(test, feature = "benchmark"))]
pub(crate) mod test_utils {
    use super::SigningIdentity;
    use crate::{
        cipher_suite::CipherSuite,
        identity::test_utils::get_test_basic_credential,
        provider::crypto::{test_utils::test_cipher_suite_provider, SignatureSecretKey},
    };

    pub fn get_test_signing_identity(
        cipher_suite: CipherSuite,
        identity: Vec<u8>,
    ) -> (SigningIdentity, SignatureSecretKey) {
        let provider = test_cipher_suite_provider(cipher_suite);
        let (secret_key, public_key) = provider.signature_key_generate().unwrap();

        let basic = get_test_basic_credential(identity);

        (SigningIdentity::new(basic, public_key), secret_key)
    }
}
