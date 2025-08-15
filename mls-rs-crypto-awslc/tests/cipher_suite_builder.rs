use mls_rs_core::crypto::{CipherSuite, CipherSuiteProvider};
use mls_rs_crypto_awslc::{AwsLcCipherSuiteBuilder, AwsLcHash, AwsLcHmac};
use mls_rs_crypto_traits::{AeadId, Curve, KdfId};

#[test]
fn custom_cipher_suite() {
    let cs = AwsLcCipherSuiteBuilder::new()
        .aead(AeadId::Aes128Gcm)
        .hash(AwsLcHash::new(CipherSuite::P256_AES128).unwrap())
        .kdf(KdfId::HkdfSha384)
        .hmac(AwsLcHmac::new(CipherSuite::P384_AES256).unwrap())
        .signing(Curve::P521)
        .hpke(CipherSuite::P521_AES256)
        .build(CipherSuite::new(12345))
        .unwrap();

    let (sk, pk) = cs.kem_derive(b"12345").unwrap();
    let ctxt = cs.hpke_seal(&pk, b"info", Some(b"aad"), b"pt").unwrap();

    cs.hpke_open(&ctxt, &sk, &pk, b"info", Some(b"aad"))
        .unwrap();
}

#[cfg(feature = "post-quantum")]
#[test]
fn custom_pq_cipher_suite() {
    use mls_rs_crypto_awslc::{MlKem, Sha3};

    let hash = AwsLcHash::new_sha3(Sha3::SHA3_384).unwrap();

    let cs = AwsLcCipherSuiteBuilder::new()
        .hash(hash)
        .combined_hpke(
            CipherSuite::CURVE25519_AES128,
            MlKem::MlKem1024,
            KdfId::HkdfSha384,
            AeadId::Aes256Gcm,
            hash,
        )
        .fallback_cipher_suite(CipherSuite::P384_AES256)
        .build(CipherSuite::new(12345))
        .unwrap();

    let (sk, pk) = cs.kem_derive(b"12345").unwrap();
    let ctxt = cs.hpke_seal(&pk, b"info", Some(b"aad"), b"pt").unwrap();

    cs.hpke_open(&ctxt, &sk, &pk, b"info", Some(b"aad"))
        .unwrap();
}
