use mls_rs_core::crypto::CipherSuite;
use mls_rs_crypto_hpke::kem_combiner::cg::{
    CgHybridKem, MLKEM768_X25519_KEM_ID, MLKEM768_X25519_LABEL,
};

use crate::{AwsLcHash, AwsLcRandom, AwsLcShake256, Ecdh, MlKemKem, Sha3};

/// MLKEM768-X25519 (X-Wing), HPKE KEM 0x647a (draft-ietf-hpke-pq-05 §4).
pub type MlKem768X25519Kem = CgHybridKem<MlKemKem, Ecdh, AwsLcShake256, AwsLcHash, AwsLcRandom>;

/// Build the aws-lc [`MlKem768X25519Kem`].
/// aws-lc's X25519 rejects an all-zero shared secret (RFC 7748 §6.1).
pub fn mlkem768_x25519_kem() -> Option<MlKem768X25519Kem> {
    let pq = MlKemKem::new(CipherSuite::ML_KEM_768)?;

    let group = Ecdh::new(CipherSuite::CURVE25519_AES128)?;

    let kdf = AwsLcHash::new_sha3(Sha3::SHA3_256)?;

    Some(CgHybridKem::new(
        pq,
        group,
        AwsLcShake256,
        kdf,
        AwsLcRandom,
        MLKEM768_X25519_LABEL,
        MLKEM768_X25519_KEM_ID,
    ))
}
