use crate::{
    cipher_suite::CipherSuite,
    group::{KeyScheduleKdf, KeyScheduleKdfError},
};
use ferriscrypt::{
    hpke::{
        kem::{HpkePublicKey, KemType},
        HpkeError,
    },
    kdf::hkdf::Hkdf,
    rand::{SecureRng, SecureRngError},
};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

const EXPORTER_CONTEXT: &[u8] = b"MLS 1.0 external init secret";

#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct InitSecret(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

impl AsRef<[u8]> for InitSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl InitSecret {
    pub fn random(kdf: &Hkdf) -> Result<Self, SecureRngError> {
        SecureRng::gen(kdf.extract_size()).map(InitSecret)
    }

    pub fn from_epoch_secret(
        kdf: &KeyScheduleKdf,
        epoch_secret: &[u8],
    ) -> Result<Self, KeyScheduleKdfError> {
        kdf.derive_secret(epoch_secret, "init").map(InitSecret)
    }

    /// Returns init secret and KEM output to be used when creating an external commit.
    pub fn encode_for_external(
        cipher_suite: CipherSuite,
        external_pub: &HpkePublicKey,
    ) -> Result<(Self, Vec<u8>), HpkeError> {
        let (kem_output, context) = cipher_suite.hpke().setup_sender(external_pub, &[], None)?;

        let kdf_extract_size = Hkdf::from(cipher_suite.kdf_type()).extract_size();
        let mut init_secret = vec![0; kdf_extract_size];
        context.export(EXPORTER_CONTEXT, &mut init_secret)?;

        Ok((InitSecret(init_secret), kem_output))
    }

    pub fn decode_for_external(
        cipher_suite: CipherSuite,
        kem_output: &[u8],
        external_secret: &[u8],
    ) -> Result<Self, HpkeError> {
        let context = cipher_suite.hpke().setup_receiver(
            kem_output,
            &cipher_suite.kem().derive(external_secret)?.0,
            &[],
            None,
        )?;

        let kdf_extract_size = Hkdf::from(cipher_suite.kdf_type()).extract_size();

        let mut init_secret = vec![0; kdf_extract_size];
        context.export(EXPORTER_CONTEXT, &mut init_secret)?;
        Ok(InitSecret(init_secret))
    }
}
