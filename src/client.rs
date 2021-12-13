use crate::cipher_suite::CipherSuite;
use crate::credential::{BasicCredential, Credential, CredentialError};
use crate::extension::{
    CapabilitiesExt, ExtensionError, ExtensionList, ExtensionTrait, LifetimeExt,
};
use crate::key_package::{KeyPackageError, KeyPackageGeneration, KeyPackageGenerator};
use crate::session::{Session, SessionError, SessionOpts};
use ferriscrypt::asym::ec_key::Curve;
use ferriscrypt::asym::ec_key::{EcKeyError, SecretKey};
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    SessionError(#[from] SessionError),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error("signature key provided does not match the selected cipher suite")]
    SignatureCipherSuiteMismatch,
    #[error("the secret key provided does not match the public key in the credential")]
    IncorrectSecretKey,
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Client {
    pub cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::SecretKeySer")]
    pub signature_key: SecretKey,
    pub credential: Credential,
    pub capabilities: CapabilitiesExt,
    private: (),
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

        if credential.public_key()? != signature_key.to_public()? {
            return Err(ClientError::IncorrectSecretKey);
        }

        Ok(Client {
            cipher_suite,
            signature_key,
            credential,
            capabilities: CapabilitiesExt::default(),
            private: (),
        })
    }

    pub fn generate_basic(
        cipher_suite: CipherSuite,
        identifier: Vec<u8>,
    ) -> Result<Client, ClientError> {
        let signature_key = SecretKey::generate(Curve::from(cipher_suite.signature_scheme()))?;
        let credential = Credential::Basic(BasicCredential::new(
            identifier,
            signature_key.to_public()?,
        )?);
        Client::new(cipher_suite, signature_key, credential)
    }

    pub fn gen_key_package(
        &self,
        lifetime: &LifetimeExt,
    ) -> Result<KeyPackageGeneration, ClientError> {
        let key_package_generator = KeyPackageGenerator {
            cipher_suite: self.cipher_suite,
            credential: &self.credential,
            extensions: ExtensionList::from(vec![
                self.capabilities.to_extension()?,
                lifetime.to_extension()?,
            ]),
            signing_key: &self.signature_key,
        };

        key_package_generator.generate().map_err(Into::into)
    }

    pub fn create_session(
        &self,
        key_package: KeyPackageGeneration,
        group_id: Vec<u8>,
        opts: SessionOpts,
    ) -> Result<Session, ClientError> {
        Session::create(group_id, self.signature_key.clone(), key_package, opts).map_err(Into::into)
    }

    pub fn join_session(
        &self,
        key_package: KeyPackageGeneration,
        tree_data: &[u8],
        welcome_message: &[u8],
        opts: SessionOpts,
    ) -> Result<Session, ClientError> {
        Session::join(
            self.signature_key.clone(),
            key_package,
            tree_data,
            welcome_message,
            opts,
        )
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::credential::BasicCredential;
    use ferriscrypt::asym::ec_key::Curve;
    use ferriscrypt::rand::SecureRng;
    use std::time::SystemTime;
    use tls_codec::Serialize;

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
                    .public_key()
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

            assert!(matches!(
                package_gen.key_package.credential,
                Credential::Basic(_)
            ));

            assert_eq!(
                package_gen
                    .key_package
                    .credential
                    .tls_serialize_detached()
                    .unwrap(),
                client.credential.tls_serialize_detached().unwrap()
            );

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
