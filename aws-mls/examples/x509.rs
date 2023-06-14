use aws_mls::{CipherSuite, Client, ProtocolVersion};
use aws_mls_crypto_openssl::OpensslCryptoProvider;

const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

#[tokio::main]
async fn main() {
    let crypto_provider = OpensslCryptoProvider::new();

    let secret_key = aws_mls_crypto_openssl::x509::signature_secret_key_from_bytes(include_bytes!(
        "../../aws-mls-crypto-openssl/test_data/x509/leaf/key.pem"
    ))
    .unwrap();

    let signing_identity = aws_mls_crypto_openssl::x509::signing_identity_from_certificate(
        include_bytes!("../../aws-mls-crypto-openssl/test_data/x509/leaf/cert.der"),
    )
    .unwrap();

    let alice_client = Client::builder()
        .crypto_provider(crypto_provider)
        .identity_provider(
            aws_mls_crypto_openssl::x509::identity_provider_from_certificate(include_bytes!(
                "../../aws-mls-crypto-openssl/test_data/x509/root_ca/cert.der"
            ))
            .unwrap(),
        )
        .single_signing_identity(signing_identity.clone(), secret_key, CIPHERSUITE)
        .build();

    let mut alice_group = alice_client
        .create_group(
            ProtocolVersion::MLS_10,
            CIPHERSUITE,
            signing_identity,
            Default::default(),
        )
        .await
        .unwrap();

    alice_group.commit(Vec::new()).await.unwrap();
    alice_group.apply_pending_commit().await.unwrap();
}
