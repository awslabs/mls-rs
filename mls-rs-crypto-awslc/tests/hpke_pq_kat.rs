//! draft-ietf-hpke-pq-05 Appendix A vectors (see `test_data/hpke_pq/README.md`).

#![cfg(feature = "post-quantum")]

#[path = "common/hpke_pq.rs"]
mod hpke_pq;

use mls_rs_crypto_awslc::AwsLcShake256;
use mls_rs_crypto_hpke::kdf::labeled_derive;

fn seed_len(kem_id: u16) -> u16 {
    match kem_id {
        0x0041 => 64,
        0x647a => 32,
        other => panic!("unexpected kem_id {other:#06x}"),
    }
}

/// draft-ietf-hpke-pq §3, §4: `skRm` is the `LabeledDerive` seed.
#[test]
fn labeled_derive_reproduces_sk_rm() {
    let vectors = hpke_pq::test_vectors();
    assert_eq!(vectors.len(), 2);

    for v in vectors {
        let suite_id = [b"KEM" as &[u8], &v.kem_id.to_be_bytes()].concat();

        let seed = labeled_derive(
            &AwsLcShake256,
            &suite_id,
            &v.ikm_r,
            b"DeriveKeyPair",
            b"",
            seed_len(v.kem_id),
        )
        .unwrap();

        assert_eq!(seed, v.sk_rm, "kem_id {:#06x}", v.kem_id);
    }
}

/// Checks shared by every KEM below, each against its own vector.
#[cfg(not(mls_build_async))]
mod kat {
    use mls_rs_core::crypto::{
        CipherSuite, HpkeContextR, HpkeContextS, HpkePublicKey, HpkeSecretKey,
    };
    use mls_rs_crypto_awslc::{AwsLcAead, AwsLcHkdf};
    use mls_rs_crypto_hpke::hpke::Hpke;
    use mls_rs_crypto_traits::{AeadType, KdfType, KemType};

    use crate::hpke_pq::{test_vector, TestVector};

    /// A KEM, its sizes (draft-ietf-hpke-pq-05 §3, §4) and the AEAD of its vector.
    pub struct Kem<K> {
        pub kem: fn() -> K,
        pub kem_id: u16,
        pub aead: CipherSuite,
        pub sk_len: usize,
        pub pk_len: usize,
        pub enc_len: usize,
        /// Length of the expanded decapsulation key, which is not a valid secret key.
        pub expanded_sk_len: usize,
    }

    impl<K: KemType> Kem<K> {
        pub fn vector(&self) -> TestVector {
            test_vector(self.kem_id)
        }

        /// Every vector uses HKDF-SHA256.
        fn hpke(&self) -> Hpke<K, AwsLcHkdf, AwsLcAead> {
            Hpke::new(
                (self.kem)(),
                AwsLcHkdf::new(CipherSuite::CURVE25519_AES128).unwrap(),
                Some(AwsLcAead::new(self.aead).unwrap()),
            )
        }
    }

    pub fn derive_key_pair<K: KemType>(k: &Kem<K>) {
        let v = k.vector();

        let (sk, pk) = k.hpke().derive(&v.ikm_r).unwrap();

        assert_eq!(sk.as_ref(), v.sk_rm.as_slice());
        assert_eq!(pk.as_ref(), v.pk_rm.as_slice());
    }

    pub fn receiver_context_matches_vector<K: KemType>(k: &Kem<K>) {
        let v = k.vector();
        let kem = (k.kem)();
        let sk = HpkeSecretKey::from(v.sk_rm.clone());
        let pk = HpkePublicKey::from(v.pk_rm.clone());

        // The ids enter the key schedule's suite_id (RFC 9180 §5.1).
        let hkdf = AwsLcHkdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert_eq!(kem.kem_id(), v.kem_id);
        assert_eq!(hkdf.kdf_id(), v.kdf_id);
        assert_eq!(AwsLcAead::new(k.aead).unwrap().aead_id(), v.aead_id);
        assert_eq!(kem.decap(&v.enc, &sk, &pk).unwrap(), v.shared_secret);

        let mut ctx = k
            .hpke()
            .setup_receiver(&v.enc, &sk, &pk, &v.info, None)
            .unwrap();

        assert_eq!(v.encryptions.len(), 10);

        for e in &v.encryptions {
            assert_eq!(*ctx.open(Some(&e.aad), &e.ct).unwrap(), e.pt);
        }

        assert_eq!(v.exports.len(), 5);

        for e in &v.exports {
            assert_eq!(
                *ctx.export(&e.exporter_context, e.len).unwrap(),
                e.exported_value
            );
        }
    }

    pub fn round_trip_with_fresh_keys<K: KemType>(k: &Kem<K>) {
        let hpke = k.hpke();
        let (sk, pk) = hpke.generate().unwrap();

        let (enc, mut ctx_s) = hpke.setup_sender(&pk, b"info", None).unwrap();
        let mut ctx_r = hpke.setup_receiver(&enc, &sk, &pk, b"info", None).unwrap();

        let ct = ctx_s.seal(Some(b"aad"), b"plaintext").unwrap();
        assert_eq!(
            ctx_r.open(Some(b"aad"), &ct).unwrap().as_slice(),
            b"plaintext"
        );
        assert_eq!(
            *ctx_s.export(b"ctx", 32).unwrap(),
            *ctx_r.export(b"ctx", 32).unwrap()
        );
    }

    pub fn rejects_wrong_lengths<K: KemType>(k: &Kem<K>) {
        let v = k.vector();
        let kem = (k.kem)();
        let sk = HpkeSecretKey::from(v.sk_rm.clone());
        let pk = HpkePublicKey::from(v.pk_rm.clone());

        assert_eq!(
            (v.sk_rm.len(), v.pk_rm.len(), v.enc.len()),
            (k.sk_len, k.pk_len, k.enc_len)
        );

        let short_pk = HpkePublicKey::from(v.pk_rm[..k.pk_len - 1].to_vec());
        assert!(kem.encap(&short_pk).is_err());
        assert!(kem.public_key_validate(&short_pk).is_err());
        assert!(kem
            .encap(&[v.pk_rm.as_slice(), &[0]].concat().into())
            .is_err());

        assert!(kem.decap(&v.enc[..k.enc_len - 1], &sk, &pk).is_err());
        assert!(kem
            .decap(&[v.enc.as_slice(), &[0]].concat(), &sk, &pk)
            .is_err());

        assert!(kem
            .decap(&v.enc, &v.sk_rm[..k.sk_len - 1].to_vec().into(), &pk)
            .is_err());
        assert!(kem
            .decap(&v.enc, &vec![1u8; k.expanded_sk_len].into(), &pk)
            .is_err());
    }

    /// draft-ietf-hpke-pq-05 §3: an invalid ML-KEM key (FIPS 203 §7.2), here the start of
    /// `pkRm`, is an EncapError.
    pub fn non_canonical_ml_kem_component_fails_encap<K: KemType>(k: &Kem<K>) {
        let v = k.vector();
        let kem = (k.kem)();
        kem.encap(&v.pk_rm.clone().into()).unwrap();

        let mut bad = v.pk_rm.clone();
        bad[0] = 0xFF;
        bad[1] |= 0x0F;

        assert!(kem.encap(&bad.into()).is_err());
    }
}

#[cfg(not(mls_build_async))]
mod mlkem768_x25519 {
    use mls_rs_core::crypto::CipherSuite;
    use mls_rs_crypto_awslc::{mlkem768_x25519_kem, MlKem768X25519Kem};
    use mls_rs_crypto_traits::KemType;

    use crate::kat::{self, Kem};

    fn kem() -> MlKem768X25519Kem {
        mlkem768_x25519_kem().unwrap()
    }

    /// draft-ietf-hpke-pq-05 §4 and Appendix A.5.
    const KEM: Kem<MlKem768X25519Kem> = Kem {
        kem,
        kem_id: 0x647a,
        aead: CipherSuite::CURVE25519_CHACHA,
        sk_len: 32,
        pk_len: 1216,
        enc_len: 1120,
        expanded_sk_len: 2432,
    };

    #[test]
    fn derive_key_pair() {
        kat::derive_key_pair(&KEM);
    }

    #[test]
    fn receiver_context_matches_vector() {
        kat::receiver_context_matches_vector(&KEM);
    }

    #[test]
    fn round_trip_with_fresh_keys() {
        kat::round_trip_with_fresh_keys(&KEM);
    }

    #[test]
    fn rejects_wrong_lengths() {
        kat::rejects_wrong_lengths(&KEM);
    }

    #[test]
    fn non_canonical_ml_kem_component_fails_encap() {
        kat::non_canonical_ml_kem_component_fails_encap(&KEM);
    }

    #[test]
    fn tampered_ciphertexts_change_the_shared_secret() {
        let v = KEM.vector();
        let kem = kem();
        let sk = v.sk_rm.clone().into();
        let pk = v.pk_rm.clone().into();

        for i in [0, 1087, 1088, 1119] {
            let mut enc = v.enc.clone();
            enc[i] ^= 1;

            let ss = kem.decap(&enc, &sk, &pk);
            assert_ne!(ss.ok(), Some(v.shared_secret.clone()), "byte {i}");
        }
    }

    /// aws-lc's X25519 rejects an all-zero shared secret (RFC 7748 §6.1).
    #[test]
    fn all_zero_x25519_component_is_rejected() {
        let v = KEM.vector();
        let kem = kem();

        let enc = [&v.enc[..1088], &[0u8; 32]].concat();
        assert!(kem
            .decap(&enc, &v.sk_rm.clone().into(), &v.pk_rm.clone().into())
            .is_err());

        let pk = [&v.pk_rm[..1184], &[0u8; 32]].concat();
        assert!(kem.encap(&pk.into()).is_err());
    }
}
