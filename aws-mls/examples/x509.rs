use aws_mls::{identity::SigningIdentity, CipherSuite, Client, ProtocolVersion};
use aws_mls_core::{crypto::SignatureSecretKey, identity::DerCertificate};
use aws_mls_crypto_openssl::{
    x509::{X509Reader, X509Validator},
    OpensslCryptoProvider,
};
use aws_mls_identity_x509::{
    CertificateChain, NoOpWarningProvider, SubjectIdentityExtractor, X509CertificateReader,
    X509IdentityProvider,
};

const CIPHERSUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

#[tokio::main]
async fn main() {
    let crypto_provider = OpensslCryptoProvider::new();

    let cert = DerCertificate::new(
        include_bytes!("../../aws-mls-crypto-openssl/test_data/x509/leaf/cert.der").to_vec(),
    );

    let public_key = X509Reader::new().public_key(&cert).unwrap();

    let secret_key = aws_mls_crypto_openssl::openssl::pkey::PKey::private_key_from_pem(
        include_bytes!("../../aws-mls-crypto-openssl/test_data/x509/leaf/key.pem"),
    )
    .unwrap();
    let secret_key = SignatureSecretKey::from(if let Ok(ec_key) = secret_key.ec_key() {
        ec_key.private_key().to_vec()
    } else {
        secret_key.raw_private_key().unwrap()
    });

    let signing_identity = SigningIdentity::new(
        CertificateChain::from(vec![cert]).into_credential(),
        public_key,
    );

    let alice_client = Client::builder()
        .crypto_provider(crypto_provider)
        .identity_provider(X509IdentityProvider::new(
            SubjectIdentityExtractor::new(0, X509Reader::new()),
            X509Validator::new(vec![DerCertificate::new(
                include_bytes!("../../aws-mls-crypto-openssl/test_data/x509/root_ca/cert.der")
                    .to_vec(),
            )])
            .unwrap(),
            NoOpWarningProvider::new(),
        ))
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
