use crate::ciphersuite::CipherSuiteError;
use crate::credential::Credential;
use crate::crypto::asym::AsymmetricKey;
use crate::crypto::signature::{ed25519, Signable, SignatureError, SignatureSchemeId, Signer};
use crate::extension::{CapabilitiesExt, ExtensionError, ExtensionList, ExtensionTrait, LifetimeExt};
use crate::key_package::{KeyPackage, KeyPackageError, KeyPackageGenerator};
use cfg_if::cfg_if;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use thiserror::Error;

cfg_if! {
    if #[cfg(test)] {
        use crate::ciphersuite::test_util::MockCipherSuite as CipherSuite;
    } else {
        use crate::ciphersuite::{CipherSuite};
    }
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    CipherSuiteError(#[from] CipherSuiteError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Client {
    pub signature_key: Vec<u8>,
    pub credential: Credential,
    pub capabilities: CapabilitiesExt,
    pub key_lifetime: u64,
}

impl Client {
    #[inline]
    pub(crate) fn get_extensions(&self) -> Result<ExtensionList, ExtensionError> {
        Ok(ExtensionList(vec![
            self.capabilities.to_extension()?,
            LifetimeExt::seconds(self.key_lifetime, SystemTime::now())?.to_extension()?,
        ]))
    }
}

impl Signer for Client {
    fn sign<T: Signable + 'static>(&self, data: &T) -> Result<Vec<u8>, SignatureError> {
        match self.credential.get_signature_type() {
            SignatureSchemeId::EcdsaSecp256r1Sha256 => {
                let key = crate::crypto::asym::p256::SecretKey::from_bytes(&self.signature_key)?;
                key.sign(data)
            }
            SignatureSchemeId::EcdsaSecp521r1Sha512 => {
                let key = crate::crypto::asym::p521::SecretKey::from_bytes(&self.signature_key)?;
                key.sign(data)
            }
            SignatureSchemeId::Ed25519 => {
                let key = ed25519::SecretKey::from_bytes(&self.signature_key)?;
                key.sign(data)
            }
            #[cfg(test)]
            SignatureSchemeId::Test => Ok(data.to_signable_vec().unwrap()),
        }
    }
}

impl KeyPackageGenerator for Client {
    fn package_from_pub_key(
        &self,
        cipher_suite: &CipherSuite,
        pub_key: Vec<u8>,
    ) -> Result<KeyPackage, KeyPackageError> {
        let mut package = KeyPackage {
            version: cipher_suite.get_protocol_version(),
            cipher_suite: cipher_suite.clone(),
            hpke_init_key: pub_key,
            credential: self.credential.clone(),
            extensions: self.get_extensions()?,
            signature: vec![],
        };

        package.signature = self.sign(&package)?;

        Ok(package)
    }
}

#[cfg(test)]
mod test {
    use crate::ciphersuite::test_util::MockCipherSuite;
    use crate::ciphersuite::KemKeyPair;
    use crate::client::Client;
    use crate::credential::{BasicCredential, CredentialConvertable};
    use crate::crypto::asym::AsymmetricKey;
    use crate::crypto::rand::test_rng::ZerosRng;
    use crate::crypto::rand::OpenSslRng;
    use crate::crypto::signature::test_utils::{get_test_signer, get_test_verifier};
    use crate::crypto::signature::{
        ed25519::EdDsa25519, p256::EcDsaP256, p521::EcDsaP521, test_utils::MockTestSignatureScheme,
        Signable, SignatureScheme, Signer, Verifier,
    };
    use crate::key_package::{KeyPackage, KeyPackageGenerator};
    use crate::protocol_version::ProtocolVersion;

    fn get_test_client<SS: SignatureScheme>(sig_scheme: &SS) -> Client {
        let signature_key = sig_scheme
            .as_public_signature_key()
            .expect("failed sig key");

        Client {
            signature_key: sig_scheme
                .get_signer()
                .to_bytes()
                .expect("failed serialize"),
            credential: BasicCredential {
                identity: vec![0u8; 4],
                signature_key: signature_key.signature_key,
                signature_scheme: signature_key.signature_scheme,
            }
            .to_credential(),
            capabilities: Default::default(),
            key_lifetime: 42,
        }
    }

    fn test_signature<V: Verifier>(client: &Client, verifier: &V) {
        let test_input = b"test".to_vec();
        let signature = client.sign(&test_input).expect("failed signature");
        assert!(verifier
            .verify(&signature, &test_input)
            .expect("failed verify"))
    }

    #[test]
    fn test_client_signatures_ed25519() {
        let sig_scheme = EdDsa25519::new_random(OpenSslRng).expect("keygen fail");
        let client = get_test_client(&sig_scheme);
        test_signature(&client, sig_scheme.get_verifier())
    }

    #[test]
    fn test_client_signatures_p256() {
        let sig_scheme = EcDsaP256::new_random(OpenSslRng).expect("keygen fail");
        let client = get_test_client(&sig_scheme);
        test_signature(&client, sig_scheme.get_verifier())
    }

    #[test]
    fn test_client_signatures_p521() {
        let sig_scheme = EcDsaP521::new_random(OpenSslRng).expect("keygen fail");
        let client = get_test_client(&sig_scheme);
        test_signature(&client, sig_scheme.get_verifier())
    }

    fn get_mock_cipher_suite() -> MockCipherSuite {
        let mut cipher_suite = MockCipherSuite::new();

        cipher_suite
            .expect_generate_kem_key_pair()
            .return_once_st(move |_: &ZerosRng| {
                Ok(KemKeyPair {
                    public_key: vec![0u8; 4],
                    secret_key: vec![255u8; 4],
                })
            });

        cipher_suite.expect_get_id().return_const(42u16);
        cipher_suite
            .expect_get_protocol_version()
            .return_const(ProtocolVersion::Test);
        cipher_suite
    }

    #[test]
    fn test_key_package_generation() {
        let mut mock_sig_scheme = MockTestSignatureScheme::new();
        mock_sig_scheme
            .expect_get_signer()
            .return_const(get_test_signer(&b"test".to_vec()));
        mock_sig_scheme
            .expect_get_verifier()
            .return_const(get_test_verifier(&b"test".to_vec()));

        let client = get_test_client(&mock_sig_scheme);

        let mut mock_cipher_suite = get_mock_cipher_suite();
        mock_cipher_suite
            .expect_clone()
            .returning_st(move || get_mock_cipher_suite());
        mock_cipher_suite
            .expect_hash()
            .returning_st(move |value| Ok(value.to_vec()));

        let key_package_generation = client
            .gen_key_package(&mut ZerosRng, &mock_cipher_suite)
            .expect("key error");

        assert_eq!(key_package_generation.secret_key, vec![255u8; 4]);

        let expected_package = KeyPackage {
            version: ProtocolVersion::Test,
            cipher_suite: get_mock_cipher_suite(),
            hpke_init_key: vec![0u8; 4],
            credential: client.credential.clone(),
            extensions: client.get_extensions().expect("failed extensions"),
            signature: key_package_generation
                .key_package
                .to_signable_vec()
                .unwrap(),
        };

        assert_eq!(key_package_generation.key_package, expected_package);
    }
}
