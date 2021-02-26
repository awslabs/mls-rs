use crate::credential::Credential;
use crate::signature::{Signer, SignatureError, Signable, SignatureSchemeId, ed25519};
use rand_core::{RngCore, CryptoRng};
use crate::extension::{Lifetime, Capabilities, ExtensionTrait, ExtensionError, Extension};
use crate::key_package::{KeyPackageData, KeyPackage, KeyPackageSecret};
use crate::ciphersuite::{CipherSuite, CipherSuiteError};
use crate::asym::{AsymmetricKey};
use serde::{Serialize, Deserialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    CipherSuiteError(#[from] CipherSuiteError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError)
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Client {
    pub signature_key: Vec<u8>,
    pub credential: Credential,
    pub capabilities: Capabilities,
    pub key_lifetime: Lifetime
}

impl Client {
    #[inline]
    pub (crate) fn get_extensions(&self) -> Result<Vec<Extension>, ClientError> {
        Ok(vec![self.capabilities.to_extension()?, self.key_lifetime.to_extension()?])
    }
}

impl Signer for Client {
    fn sign<T: Signable + 'static>(&self, data: &T) -> Result<Vec<u8>, SignatureError> {
        match self.credential.get_signature_type() {
            SignatureSchemeId::EcdsaSecp256r1Sha256 => {
                let key = crate::asym::p256::SecretKey::from_bytes(&self.signature_key)?;
                key.sign(data)
            }
            SignatureSchemeId::EcdsaSecp521r1Sha512 => {
                let key = crate::asym::p521::SecretKey::from_bytes(&self.signature_key)?;
                key.sign(data)
            }
            SignatureSchemeId::Ed25519 => {
                let key = ed25519::SecretKey::from_bytes(&self.signature_key)?;
                key.sign(data)
            }
            #[cfg(test)]
            SignatureSchemeId::Test => {
                Ok(data.to_signable_vec().unwrap())
            }
        }
    }
}

impl Client {

    pub fn gen_init_key_package<RNG: RngCore + CryptoRng>(
        &self,
        rng: RNG,
        cipher_suite: &CipherSuite,
    ) -> Result<(KeyPackageSecret, KeyPackage) ,ClientError> {
        let kem_key_pair = cipher_suite.generate_kem_key_pair(rng)?;

        let package_data = KeyPackageData {
            version: cipher_suite.get_protocol_version(),
            cipher_suite: cipher_suite.clone(),
            hpke_init_key: kem_key_pair.public_key,
            credential: self.credential.clone(),
            extensions: self.get_extensions()?
        };

        let signature = self.sign(&package_data)?;

        let package = KeyPackage {
            data: package_data,
            signature
        };

        let secret = KeyPackageSecret {
            cipher_suite: cipher_suite.clone(),
            hpke_secret_key: kem_key_pair.secret_key,
            extensions: vec![self.capabilities.to_extension()?, self.key_lifetime.to_extension()?]
        };

        Ok((secret, package))
    }
}

#[cfg(test)]
mod test {
    use crate::signature::{ed25519::EdDsa25519, p256::EcDsaP256, p521::EcDsaP521, SignatureScheme, Verifier, Signer, test_utils::MockTestSignatureScheme, Signable};
    use crate::rand::test_rng::ZerosRng;
    use crate::client::Client;
    use crate::credential::{Credential, BasicCredential, CredentialConvertable};
    use crate::asym::AsymmetricKey;
    use crate::extension::Lifetime;
    use crate::ciphersuite::CipherSuite;
    use crate::key_package::{KeyPackageData, KeyPackageSecret};
    use crate::protocol_version::ProtocolVersion;
    use crate::signature::test_utils::{get_test_signer, get_test_verifier};
    use crate::rand::OpenSslRng;

    fn get_test_client<SS: SignatureScheme>(sig_scheme: &SS) -> Client {
        let signature_key = sig_scheme.as_public_signature_key().expect("failed sig key");

        Client {
            signature_key: sig_scheme.get_signer().to_bytes().expect("failed serialize"),
            credential: BasicCredential {
                identity: vec![0u8; 15],
                signature_key: signature_key.signature_key,
                signature_scheme: signature_key.signature_scheme
            }.to_credential(),
            capabilities: Default::default(),
            key_lifetime: Lifetime { not_before: 0, not_after: 0 }
        }
    }

    fn test_signature<V: Verifier>(client: &Client, verifier: &V) {
        let test_input = b"test".to_vec();
        let signature = client.sign(&test_input).expect("failed signature");
        assert!(verifier.verify(&signature, &test_input).expect("failed verify"))
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
        let ciphersuite = CipherSuite::MLS10_TEST;

        let (sec_package, pub_package) = client
            .gen_init_key_package(ZerosRng, &ciphersuite)
            .expect("key error");

        let expected_sec_package = KeyPackageSecret {
            cipher_suite: ciphersuite.clone(),
            hpke_secret_key: vec![0u8; 4],
            extensions: client.get_extensions().expect("failed extensions")
        };

        assert_eq!(expected_sec_package, sec_package);

        let expected_package_data = KeyPackageData {
            version: ProtocolVersion::Test,
            cipher_suite: ciphersuite.clone(),
            hpke_init_key: vec![0u8; 4],
            credential: client.credential.clone(),
            extensions: client.get_extensions().expect("failed extensions")
        };

        assert_eq!(pub_package.data, expected_package_data);

        // The signature function for testing is just returning the input it receives
        assert_eq!(pub_package.signature,
                   pub_package.data.to_signable_vec()
                       .expect("failed signing"))
    }
}