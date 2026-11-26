#![cfg(not(mls_build_async))]

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

#[cfg(feature = "post-quantum")]
#[path = "common/hpke_pq.rs"]
mod hpke_pq;

#[cfg(feature = "post-quantum")]
mod mlkem768_x25519 {
    use mls_rs_core::crypto::{
        CipherSuite, CipherSuiteProvider, HpkeContextR, HpkePublicKey, HpkeSecretKey,
    };
    use mls_rs_crypto_awslc::AwsLcCipherSuiteBuilder;
    use mls_rs_crypto_traits::{AeadId, KdfId};

    use crate::hpke_pq::{test_vector, TestVector};

    const PRIVATE_USE: CipherSuite = CipherSuite::new(0xF0A0);

    /// draft-ietf-hpke-pq-05 Appendix A.5.
    fn appendix_a5() -> TestVector {
        test_vector(0x647a)
    }

    #[test]
    fn reproduces_the_appendix_a5_vector() {
        let v = appendix_a5();
        assert_eq!((v.kdf_id, v.aead_id), (0x0001, 0x0003));

        let cs = AwsLcCipherSuiteBuilder::new()
            .mlkem768_x25519_hpke(KdfId::HkdfSha256, AeadId::Chacha20Poly1305)
            .fallback_cipher_suite(CipherSuite::CURVE25519_CHACHA)
            .build(PRIVATE_USE)
            .unwrap();

        let (sk, pk) = cs.kem_derive(&v.ikm_r).unwrap();
        assert_eq!(sk.as_ref(), v.sk_rm.as_slice());
        assert_eq!(pk.as_ref(), v.pk_rm.as_slice());

        let mut ctx = cs.hpke_setup_r(&v.enc, &sk, &pk, &v.info).unwrap();

        for e in &v.encryptions {
            assert_eq!(ctx.open(Some(&e.aad), &e.ct).unwrap().as_slice(), e.pt);
        }

        for e in &v.exports {
            assert_eq!(
                ctx.export(&e.exporter_context, e.len).unwrap().as_slice(),
                e.exported_value
            );
        }
    }

    /// DeriveKeyPair uses only the KEM's suite_id (draft-ietf-hpke-hpke-06 §4.4).
    #[test]
    fn composes_with_any_kdf_and_aead() {
        let v = appendix_a5();

        for (kdf, aead) in [
            (KdfId::HkdfSha256, AeadId::Aes256Gcm),
            (KdfId::HkdfSha384, AeadId::Aes256Gcm),
            (KdfId::HkdfSha512, AeadId::Aes128Gcm),
        ] {
            let cs = AwsLcCipherSuiteBuilder::new()
                .mlkem768_x25519_hpke(kdf, aead)
                .fallback_cipher_suite(CipherSuite::CURVE25519_AES128)
                .build(PRIVATE_USE)
                .unwrap();

            let (sk, pk) = cs.kem_derive(&v.ikm_r).unwrap();
            assert_eq!(pk.as_ref(), v.pk_rm.as_slice());
            cs.kem_public_key_validate(&pk).unwrap();

            let ct = cs.hpke_seal(&pk, b"info", Some(b"aad"), b"pt").unwrap();
            assert_eq!(ct.kem_output.len(), 1120);
            let pt = cs.hpke_open(&ct, &sk, &pk, b"info", Some(b"aad")).unwrap();
            assert_eq!(pt.as_slice(), b"pt");
        }
    }

    #[test]
    fn rejects_malformed_keys() {
        let cs = AwsLcCipherSuiteBuilder::new()
            .mlkem768_x25519_hpke(KdfId::HkdfSha256, AeadId::Aes256Gcm)
            .fallback_cipher_suite(CipherSuite::CURVE25519_AES128)
            .build(PRIVATE_USE)
            .unwrap();

        let (sk, pk) = cs.kem_generate().unwrap();
        let short_pk = HpkePublicKey::from(pk.as_ref()[..1215].to_vec());
        assert!(cs.kem_public_key_validate(&short_pk).is_err());

        let ct = cs.hpke_seal(&pk, b"info", None, b"pt").unwrap();
        let short_sk = HpkeSecretKey::from(sk.as_ref()[..31].to_vec());
        assert!(cs.hpke_open(&ct, &short_sk, &pk, b"info", None).is_err());
    }
}
