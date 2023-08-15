use aws_mls::{
    client_builder::{MlsConfig, Preferences},
    error::MlsError,
    external_client::{
        builder::MlsConfig as ExternalMlsConfig, ExternalClient, ExternalReceivedMessage,
        ExternalSnapshot,
    },
    group::{CachedProposal, ReceivedMessage},
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, MLSMessage,
};
use aws_mls_core::crypto::SignatureSecretKey;

const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

fn cipher_suite_provider() -> impl CipherSuiteProvider {
    crypto_provider()
        .cipher_suite_provider(CIPHERSUITE)
        .unwrap()
}

fn crypto_provider() -> impl CryptoProvider + Clone {
    aws_mls_crypto_openssl::OpensslCryptoProvider::default()
}

#[derive(Default)]
struct BasicServer {
    group_state: Vec<u8>,
    cached_proposals: Vec<Vec<u8>>,
    message_queue: Vec<Vec<u8>>,
}

impl BasicServer {
    // Client uploads group data after creating the group
    async fn create_group(group_info: &[u8], tree: &[u8]) -> Result<Self, MlsError> {
        let server = make_server();
        let group_info = MLSMessage::from_bytes(group_info)?;
        let group = server.observe_group(group_info, Some(tree)).await?;

        Ok(Self {
            group_state: group.snapshot().to_bytes()?,
            ..Default::default()
        })
    }

    // Client uploads a proposal. This doesn't change the server's group state, so clients can
    // upload prposals without synchronization (`cached_proposals` and `message_queue` collect
    // all proposals in any order).
    async fn upload_proposal(&mut self, proposal: Vec<u8>) -> Result<(), MlsError> {
        let server = make_server();
        let group_state = ExternalSnapshot::from_bytes(&self.group_state)?;
        let mut group = server.load_group(group_state).await?;

        let proposal_msg = MLSMessage::from_bytes(&proposal)?;
        let res = group.process_incoming_message(proposal_msg).await?;

        let ExternalReceivedMessage::Proposal(proposal_desc) = res else {
            panic!("expected proposal message!")
        };

        self.cached_proposals
            .push(proposal_desc.cached_proposal().to_bytes()?);

        self.message_queue.push(proposal);

        Ok(())
    }

    // Client uploads a commit. This changes the server's group state, so in a real application,
    // it must be synchronized. That is, only one `upload_commit` operation can succeed.
    async fn upload_commit(&mut self, commit: Vec<u8>) -> Result<(), MlsError> {
        let server = make_server();
        let group_state = ExternalSnapshot::from_bytes(&self.group_state)?;
        let mut group = server.load_group(group_state).await?;

        for p in &self.cached_proposals {
            group.insert_proposal(CachedProposal::from_bytes(p)?);
        }

        let commit_msg = MLSMessage::from_bytes(&commit)?;
        let res = group.process_incoming_message(commit_msg).await?;

        let ExternalReceivedMessage::Commit(_commit_desc) = res else {
            panic!("expected commit message!")
        };

        self.cached_proposals = Vec::new();
        self.group_state = group.snapshot().to_bytes()?;
        self.message_queue.push(commit);

        Ok(())
    }

    pub fn download_messages(&self, i: usize) -> &[Vec<u8>] {
        &self.message_queue[i..]
    }
}

fn make_server() -> ExternalClient<impl ExternalMlsConfig> {
    ExternalClient::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto_provider())
        .build()
}

fn make_client(name: &str) -> Result<Client<impl MlsConfig>, MlsError> {
    let (secret, signing_identity) = make_identity(name);

    Ok(Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto_provider())
        .preferences(Preferences::default().with_ratchet_tree_extension(true))
        .signing_identity(signing_identity, secret, CIPHERSUITE)
        .build())
}

fn make_identity(name: &str) -> (SignatureSecretKey, SigningIdentity) {
    let cipher_suite = cipher_suite_provider();
    let (secret, public) = cipher_suite.signature_key_generate().unwrap();

    // Create a basic credential for the session.
    // NOTE: BasicCredential is for demonstration purposes and not recommended for production.
    // X.509 credentials are recommended.
    let basic_identity = BasicCredential::new(name.as_bytes().to_vec());
    let identity = SigningIdentity::new(basic_identity.into_credential(), public);

    (secret, identity)
}

#[tokio::main]
async fn main() -> Result<(), MlsError> {
    // Create clients for Alice and Bob
    let alice = make_client("alice")?;
    let bob = make_client("bob")?;

    // Alice creates a group with bob
    let mut alice_group = alice.create_group(ExtensionList::default()).await?;
    let bob_key_package = bob.generate_key_package_message().await?;

    let welcome = alice_group
        .commit_builder()
        .add_member(bob_key_package)?
        .build()
        .await?
        .welcome_message
        .expect("key package shouldn't be rejected");

    let (mut bob_group, _) = bob.join_group(None, welcome).await?;
    alice_group.apply_pending_commit().await?;

    // Server starts observing Alice's group
    let group_info = alice_group.group_info_message().await?.to_bytes()?;
    let tree = alice_group.export_tree()?;

    let mut server = BasicServer::create_group(&group_info, &tree).await?;

    // Bob uploads a proposal
    let proposal = bob_group
        .propose_group_context_extensions(ExtensionList::new(), Vec::new())
        .await?
        .to_bytes()?;

    server.upload_proposal(proposal).await?;

    // Alice downloads all messages and commits
    for m in server.download_messages(0) {
        alice_group
            .process_incoming_message(MLSMessage::from_bytes(m)?)
            .await?;
    }

    let commit = alice_group
        .commit(b"changing extensions".to_vec())
        .await?
        .commit_message
        .to_bytes()?;

    server.upload_commit(commit).await?;

    // Alice waits for an ACK from the server and applies the commit
    alice_group.apply_pending_commit().await?;

    // Bob downloads the commit
    let message = server.download_messages(1).first().unwrap();

    let res = bob_group
        .process_incoming_message(MLSMessage::from_bytes(message)?)
        .await?;

    let ReceivedMessage::Commit(commit_desc) = res else {
        panic!("expected commit message")
    };

    assert_eq!(&commit_desc.authenticated_data, b"changing extensions");

    Ok(())
}
