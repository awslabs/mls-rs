use aws_mls::{
    client_builder::{MlsConfig, Preferences},
    error::MlsError,
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, ProtocolVersion,
};

const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::MLS_10;

fn make_client<P: CryptoProvider + Clone>(
    crypto_provider: P,
    name: &str,
) -> Result<(SigningIdentity, Client<impl MlsConfig>), MlsError> {
    let cipher_suite = crypto_provider.cipher_suite_provider(CIPHERSUITE).unwrap();

    // Generate a signature key pair.
    let (secret, public) = cipher_suite.signature_key_generate().unwrap();

    // Create a basic credential for the session.
    // NOTE: BasicCredential is for demonstration purposes and not recommended for production.
    // X.509 credentials are recommended.
    let basic_identity = BasicCredential::new(name.as_bytes().to_vec());
    let signing_identity = SigningIdentity::new(basic_identity.into_credential(), public);

    // Use default preferences but with the ratchet tree extension on so that commits will
    // include a copy of the MLS ratchet tree.
    let preferences = Preferences::default().with_ratchet_tree_extension(true);

    Ok((
        signing_identity.clone(),
        Client::builder()
            .preferences(preferences)
            .identity_provider(BasicIdentityProvider)
            .crypto_provider(crypto_provider)
            .single_signing_identity(signing_identity, secret, CIPHERSUITE)
            .build(),
    ))
}

#[tokio::main]
async fn main() -> Result<(), MlsError> {
    let crypto_provider = aws_mls_crypto_openssl::OpensslCryptoProvider::default();

    // Create clients for Alice and Bob
    let (alice_identity, alice) = make_client(crypto_provider.clone(), "alice")?;
    let (bob_identity, bob) = make_client(crypto_provider.clone(), "bob")?;

    // Alice creates a new group.
    let mut alice_group = alice
        .create_group(
            PROTOCOL_VERSION,
            CIPHERSUITE,
            alice_identity,
            ExtensionList::default(),
        )
        .await?;

    // Bob generates a key package that Alice needs to add Bob to the group.
    let bob_key_package = bob
        .generate_key_package_message(PROTOCOL_VERSION, CIPHERSUITE, bob_identity)
        .await?;

    // Alice issues a commit that adds Bob to the group.
    let alice_commit = alice_group
        .commit_builder()
        .add_member(bob_key_package)?
        .build()
        .await?;

    // Alice confirms that the commit was accepted by the group so it can be applied locally.
    // This would normally happen after a server confirmed your commit was accepted and can
    // be broadcasted.
    alice_group.apply_pending_commit().await?;

    // Bob joins the group with the welcome message created as part of Alice's commit.
    let (mut bob_group, _) = bob
        .join_group(None, alice_commit.welcome_message.unwrap())
        .await?;

    // Alice encrypts an application message to Bob.
    let msg = alice_group
        .encrypt_application_message(b"hello world", Default::default())
        .await?;

    // Bob decrypts the application message from Alice.
    let msg = bob_group.process_incoming_message(msg).await?;

    println!("Received message: {:?}", msg);

    // Alice and bob write the group state to their configured storage engine
    alice_group.write_to_storage().await?;
    bob_group.write_to_storage().await?;

    Ok(())
}
