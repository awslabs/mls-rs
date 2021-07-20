use crate::ciphersuite::CipherSuite;
use crate::credential::Credential;
use crate::extension::{
    CapabilitiesExt, ExtensionError, ExtensionList, ExtensionTrait, LifetimeExt,
};
use crate::key_package::{KeyPackageError, KeyPackageGeneration, KeyPackageGenerator};
use ferriscrypt::asym::ec_key::Curve;
use ferriscrypt::asym::ec_key::{EcKeyError, SecretKey};
use ferriscrypt::Signer;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error("signature key provided does not match the selected cipher suite")]
    SignatureCipherSuiteMismatch,
    #[error("credential provided does not match the selected cipher suite")]
    CredentialCipherSuiteMismatch,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Client {
    pub cipher_suite: CipherSuite,
    pub signature_key: SecretKey,
    pub credential: Credential,
    pub capabilities: CapabilitiesExt,
    phantom: PhantomData<u8>, // Don't allow direct construction
}

impl Client {
    pub fn new(
        cipher_suite: CipherSuite,
        signature_key: SecretKey,
        credential: Credential,
    ) -> Result<Client, ClientError> {
        if signature_key.curve != Curve::from(cipher_suite.signature_scheme()) {
            return Err(ClientError::SignatureCipherSuiteMismatch);
        }

        if credential.get_signature_scheme() != cipher_suite.signature_scheme() {
            return Err(ClientError::CredentialCipherSuiteMismatch);
        }

        Ok(Client {
            cipher_suite,
            signature_key,
            credential,
            capabilities: CapabilitiesExt::default(),
            phantom: PhantomData::default(),
        })
    }
}

impl Client {
    pub fn gen_key_package(
        &self,
        lifetime: &LifetimeExt,
    ) -> Result<KeyPackageGeneration, ClientError> {
        let key_package_generator = KeyPackageGenerator {
            cipher_suite: self.cipher_suite,
            credential: &self.credential,
            extensions: ExtensionList(vec![
                self.capabilities.to_extension()?,
                lifetime.to_extension()?,
            ]),
            signing_key: &self.signature_key,
        };

        key_package_generator.generate().map_err(Into::into)
    }
}

impl Signer for Client {
    type ErrorType = ClientError;
    type SignatureType = Vec<u8>;

    #[inline(always)]
    fn sign(&self, data: &[u8]) -> Result<Self::SignatureType, Self::ErrorType> {
        self.signature_key.sign(data).map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::credential::BasicCredential;
    use ferriscrypt::asym::ec_key::Curve;
    use ferriscrypt::rand::SecureRng;
    use ferriscrypt::Verifier;
    use std::time::SystemTime;

    fn get_test_credential(identity: Vec<u8>, signature_key: &SecretKey) -> Credential {
        Credential::Basic(
            BasicCredential::new(identity, signature_key.to_public().unwrap()).unwrap(),
        )
    }

    fn get_test_client(identity: Vec<u8>, cipher_suite: CipherSuite) -> Client {
        let signature_key =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();
        let credential = get_test_credential(identity, &signature_key);

        Client::new(cipher_suite, signature_key, credential).unwrap()
    }

    #[test]
    fn test_construction() {
        for cipher_suite in CipherSuite::all() {
            println!("Running client construction for {:?}", cipher_suite);
            let identity = SecureRng::gen(42).unwrap();
            let test_client = get_test_client(identity, cipher_suite);
            assert_eq!(test_client.cipher_suite, cipher_suite);
            assert_eq!(test_client.capabilities, CapabilitiesExt::default());
            assert_eq!(
                test_client
                    .credential
                    .get_public_key()
                    .unwrap()
                    .to_uncompressed_bytes()
                    .unwrap(),
                test_client
                    .signature_key
                    .to_public()
                    .unwrap()
                    .to_uncompressed_bytes()
                    .unwrap()
            );
        }
    }

    #[test]
    fn test_bad_sig_key() {
        // Signature key is P256 but cipher suite expects Ed25519
        let sig_key = SecretKey::generate(Curve::P256).unwrap();
        let credential = get_test_credential(vec![], &sig_key);
        let client_res = Client::new(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519,
            sig_key,
            credential,
        );
        assert!(client_res.is_err());
    }

    #[test]
    fn test_bad_credential() {
        let sig_key = SecretKey::generate(Curve::P256).unwrap();
        let other_sig_key = SecretKey::generate(Curve::Ed25519).unwrap();

        let credential = Credential::Basic(
            BasicCredential::new(vec![], other_sig_key.to_public().unwrap()).unwrap(),
        );

        let client_res = Client::new(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256,
            sig_key,
            credential,
        );
        assert!(client_res.is_err());
    }

    #[test]
    fn test_signing() {
        for cipher_suite in CipherSuite::all() {
            println!("Running client signatures for {:?}", cipher_suite);
            let client = get_test_client(vec![], cipher_suite);
            let test_input = SecureRng::gen(42).unwrap();

            // Signatures created by the client should be able to be verified by the credential
            let signature = client.sign(&test_input).unwrap();
            assert!(client.credential.verify(&signature, &test_input).unwrap());
        }
    }

    #[test]
    fn test_keygen() {
        // This is meant to test the inputs to the internal key package generator
        // See KeyPackageGenerator tests for key generation specific tests
        for cipher_suite in CipherSuite::all() {
            println!("Running client keygen for {:?}", cipher_suite);

            let cred_identity = SecureRng::gen(42).unwrap();
            let client = get_test_client(cred_identity, cipher_suite);
            let key_lifetime = LifetimeExt::years(1, SystemTime::now()).unwrap();
            let package_gen = client.gen_key_package(&key_lifetime).unwrap();

            assert_eq!(package_gen.key_package.cipher_suite, cipher_suite);
            assert_eq!(package_gen.key_package.credential, client.credential);
            assert_eq!(
                package_gen
                    .key_package
                    .extensions
                    .get_lifetime()
                    .unwrap()
                    .unwrap(),
                key_lifetime
            );

            let capabilities: Option<CapabilitiesExt> =
                package_gen.key_package.extensions.get_extension().unwrap();
            assert_eq!(capabilities, Some(client.capabilities));
        }
    }
}
