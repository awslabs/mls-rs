use crate::cipher_suite::CipherSuite;
use crate::client_config::{ClientConfig, DefaultClientConfig};
use crate::credential::{BasicCredential, Credential, CredentialError};
use crate::extension::{CapabilitiesExt, ExtensionError, ExtensionList, LifetimeExt, MlsExtension};
use crate::group::framing::{Content, MLSMessage, MLSPlaintext, Sender, WireFormat};
use crate::group::message_signature::{MessageSignature, MessageSignatureError};
use crate::group::proposal::{AddProposal, Proposal, RemoveProposal};
use crate::key_package::{KeyPackage, KeyPackageError, KeyPackageGeneration, KeyPackageGenerator};
use crate::session::{Session, SessionError};
use ferriscrypt::asym::ec_key::{Curve, EcKeyError, SecretKey};
use thiserror::Error;
use tls_codec::Serialize;

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
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    MessageSignatureError(#[from] MessageSignatureError),
    #[error("proposing as external without external key ID")]
    ProposingAsExternalWithoutExternalKeyId,
}

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Client<C = DefaultClientConfig> {
    pub cipher_suite: CipherSuite,
    pub signature_key: SecretKey,
    pub credential: Credential,
    pub capabilities: CapabilitiesExt,
    pub config: C,
}

impl<C: ClientConfig + Clone> Client<C> {
    pub fn new(
        cipher_suite: CipherSuite,
        signature_key: SecretKey,
        credential: Credential,
        config: C,
    ) -> Result<Self, ClientError> {
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
            config,
        })
    }

    pub fn generate_basic(
        cipher_suite: CipherSuite,
        identifier: Vec<u8>,
        config: C,
    ) -> Result<Self, ClientError> {
        let signature_key = SecretKey::generate(Curve::from(cipher_suite.signature_scheme()))?;
        let credential = Credential::Basic(BasicCredential::new(
            identifier,
            signature_key.to_public()?,
        )?);
        Client::new(cipher_suite, signature_key, credential, config)
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
    ) -> Result<Session<C>, ClientError> {
        Session::create(
            group_id,
            self.signature_key.clone(),
            key_package,
            self.config.clone(),
        )
        .map_err(Into::into)
    }

    pub fn join_session(
        &self,
        key_package: KeyPackageGeneration,
        tree_data: Option<&[u8]>,
        welcome_message: &[u8],
    ) -> Result<Session<C>, ClientError> {
        Session::join(
            self.signature_key.clone(),
            key_package,
            tree_data,
            welcome_message,
            self.config.clone(),
        )
        .map_err(Into::into)
    }

    pub fn propose_as_external_new_member(
        &self,
        group_id: Vec<u8>,
        key_package: KeyPackage,
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        self.propose_as_external(
            group_id,
            Sender::NewMember,
            Proposal::Add(AddProposal { key_package }),
            epoch,
        )
    }

    pub fn propose_add_as_external_preconfigured(
        &self,
        group_id: Vec<u8>,
        proposal: AddProposal,
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        self.propose_as_external(
            group_id,
            Sender::Preconfigured(
                self.config
                    .external_key_id()
                    .ok_or(ClientError::ProposingAsExternalWithoutExternalKeyId)?,
            ),
            Proposal::Add(proposal),
            epoch,
        )
    }

    pub fn propose_remove_as_external_preconfigured(
        &self,
        group_id: Vec<u8>,
        proposal: RemoveProposal,
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        self.propose_as_external(
            group_id,
            Sender::Preconfigured(
                self.config
                    .external_key_id()
                    .ok_or(ClientError::ProposingAsExternalWithoutExternalKeyId)?,
            ),
            Proposal::Remove(proposal),
            epoch,
        )
    }

    fn propose_as_external(
        &self,
        group_id: Vec<u8>,
        sender: Sender,
        proposal: Proposal,
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        let mut message = MLSPlaintext {
            group_id,
            epoch,
            sender,
            authenticated_data: Vec::new(),
            content: Content::Proposal(proposal),
            signature: MessageSignature::empty(),
            confirmation_tag: None,
            membership_tag: None,
        };
        message.sign(&self.signature_key, None, WireFormat::Plain)?;
        let message = MLSMessage::Plain(message);
        Ok(message.tls_serialize_detached()?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{credential::BasicCredential, group::ProcessedMessage};
    use ferriscrypt::asym::ec_key::Curve;
    use ferriscrypt::rand::SecureRng;
    use std::time::SystemTime;
    use tls_codec::Serialize;

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;
    const TEST_GROUP: &[u8] = b"group";

    struct TestClientBuilder<C = DefaultClientConfig> {
        identity: Vec<u8>,
        cipher_suite: Option<CipherSuite>,
        signing_key: Option<SecretKey>,
        config: C,
    }

    impl TestClientBuilder<DefaultClientConfig> {
        fn new(identity: Vec<u8>) -> Self {
            TestClientBuilder {
                identity,
                cipher_suite: None,
                signing_key: None,
                config: DefaultClientConfig::default(),
            }
        }

        fn named(s: &str) -> Self {
            Self::new(s.as_bytes().to_vec())
        }
    }

    impl<C: ClientConfig + Clone> TestClientBuilder<C> {
        fn with_cipher_suite(self, cipher_suite: CipherSuite) -> Self {
            Self {
                cipher_suite: Some(cipher_suite),
                ..self
            }
        }

        fn with_signing_key(self, signing_key: SecretKey) -> Self {
            Self {
                signing_key: Some(signing_key),
                ..self
            }
        }

        fn with_config<D>(self, config: D) -> TestClientBuilder<D>
        where
            D: ClientConfig + Clone,
        {
            TestClientBuilder {
                identity: self.identity,
                cipher_suite: self.cipher_suite,
                signing_key: self.signing_key,
                config,
            }
        }

        fn build(self) -> Client<C> {
            let cipher_suite = self.cipher_suite.unwrap_or(TEST_CIPHER_SUITE);
            let signature_key = self.signing_key.unwrap_or_else(|| {
                SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap()
            });
            let credential = get_test_credential(self.identity, &signature_key);
            Client::new(cipher_suite, signature_key, credential, self.config).unwrap()
        }

        fn build_with_key_pkg(self) -> (Client<C>, KeyPackageGeneration) {
            let client = self.build();
            let gen = client
                .gen_key_package(&LifetimeExt::years(1, SystemTime::now()).unwrap())
                .unwrap();
            (client, gen)
        }
    }

    fn get_test_credential(identity: Vec<u8>, signature_key: &SecretKey) -> Credential {
        Credential::Basic(
            BasicCredential::new(identity, signature_key.to_public().unwrap()).unwrap(),
        )
    }

    fn get_test_client(identity: Vec<u8>, cipher_suite: CipherSuite) -> Client {
        TestClientBuilder::new(identity)
            .with_cipher_suite(cipher_suite)
            .build()
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
            CipherSuite::Curve25519Aes128V1,
            sig_key,
            credential,
            DefaultClientConfig::default(),
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
            CipherSuite::P256Aes128V1,
            sig_key,
            credential,
            DefaultClientConfig::default(),
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
                    .get_extension::<LifetimeExt>()
                    .unwrap()
                    .unwrap(),
                key_lifetime
            );

            let capabilities: Option<CapabilitiesExt> =
                package_gen.key_package.extensions.get_extension().unwrap();
            assert_eq!(capabilities, Some(client.capabilities));
        }
    }

    #[test]
    fn new_member_proposition_is_interpreted_by_members() {
        let (alice, alice_key_gen) = TestClientBuilder::named("alice").build_with_key_pkg();
        let mut session = alice
            .create_session(alice_key_gen, TEST_GROUP.to_vec())
            .unwrap();
        let (bob, bob_key_gen) = TestClientBuilder::named("bob").build_with_key_pkg();
        let proposal = bob
            .propose_as_external_new_member(
                TEST_GROUP.to_vec(),
                bob_key_gen.key_package.clone(),
                session.group_stats().unwrap().epoch,
            )
            .unwrap();
        let message = session.process_incoming_bytes(&proposal).unwrap();
        assert!(matches!(
            message,
            ProcessedMessage::Proposal(Proposal::Add(AddProposal { key_package })) if key_package == bob_key_gen.key_package
        ));
    }

    fn preconfigured_external_proposition_is_interpreted_by_members<F>(mut propose: F)
    where
        F: FnMut(&Client, KeyPackage, u64) -> (Proposal, Vec<u8>),
    {
        const TED_EXTERNAL_KEY_ID: &[u8] = b"ted";
        let ted_signing_key =
            SecretKey::generate(Curve::from(TEST_CIPHER_SUITE.signature_scheme())).unwrap();
        let ted = TestClientBuilder::named("ted")
            .with_signing_key(ted_signing_key.clone())
            .with_config(
                DefaultClientConfig::default().with_external_key_id(TED_EXTERNAL_KEY_ID.to_vec()),
            )
            .build();
        let (alice, alice_key_gen) = TestClientBuilder::named("alice")
            .with_config(DefaultClientConfig::default().with_external_signing_key(
                TED_EXTERNAL_KEY_ID.to_vec(),
                ted_signing_key.to_public().unwrap(),
            ))
            .build_with_key_pkg();
        let mut session = alice
            .create_session(alice_key_gen, TEST_GROUP.to_vec())
            .unwrap();
        let (_, bob_key_gen) = TestClientBuilder::named("bob").build_with_key_pkg();
        let (expected_proposal, msg) = propose(
            &ted,
            bob_key_gen.key_package,
            session.group_stats().unwrap().epoch,
        );
        let msg = session.process_incoming_bytes(&msg).unwrap();
        assert!(matches!(
            msg,
            ProcessedMessage::Proposal(actual_proposal) if expected_proposal == actual_proposal
        ));
    }

    #[test]
    fn preconfigured_external_addition_is_interpreted_by_members() {
        preconfigured_external_proposition_is_interpreted_by_members(
            |client, key_package, epoch| {
                let proposal = AddProposal { key_package };
                let msg = client
                    .propose_add_as_external_preconfigured(
                        TEST_GROUP.to_vec(),
                        proposal.clone(),
                        epoch,
                    )
                    .unwrap();
                (Proposal::Add(proposal), msg)
            },
        );
    }

    #[test]
    fn preconfigured_external_removal_is_interpreted_by_members() {
        preconfigured_external_proposition_is_interpreted_by_members(|client, key_pkg, epoch| {
            let proposal = RemoveProposal {
                to_remove: key_pkg.to_reference().unwrap(),
            };
            let msg = client
                .propose_remove_as_external_preconfigured(
                    TEST_GROUP.to_vec(),
                    proposal.clone(),
                    epoch,
                )
                .unwrap();
            (Proposal::Remove(proposal), msg)
        });
    }

    #[test]
    fn proposition_from_unknown_external_is_rejected_by_members() {
        let ted = TestClientBuilder::named("ted").build();
        let (alice, alice_key_gen) = TestClientBuilder::named("alice").build_with_key_pkg();
        let mut session = alice
            .create_session(alice_key_gen, TEST_GROUP.to_vec())
            .unwrap();
        let (_, bob_key_gen) = TestClientBuilder::named("bob").build_with_key_pkg();
        let msg = ted
            .propose_as_external_new_member(
                TEST_GROUP.to_vec(),
                bob_key_gen.key_package,
                session.group_stats().unwrap().epoch,
            )
            .unwrap();
        let msg = session.process_incoming_bytes(&msg);
        assert!(msg.is_err());
    }
}
