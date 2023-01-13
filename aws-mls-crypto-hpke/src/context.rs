use aws_mls_core::crypto::HpkeContext;
use aws_mls_crypto_traits::{AeadType, KdfType};

use crate::{hpke::HpkeError, kdf::HpkeKdf};

/// A type representing an HPKE context
#[derive(Debug, Clone)]
pub struct Context<KDF: KdfType, AEAD: AeadType> {
    exporter_secret: Vec<u8>,
    encryption_context: Option<EncryptionContext<AEAD>>,
    kdf: HpkeKdf<KDF>,
}

impl<KDF: KdfType, AEAD: AeadType> Context<KDF, AEAD> {
    #[inline]
    pub(super) fn new(
        encryption_context: Option<EncryptionContext<AEAD>>,
        exporter_secret: Vec<u8>,
        kdf: HpkeKdf<KDF>,
    ) -> Self {
        Self {
            exporter_secret,
            encryption_context,
            kdf,
        }
    }

    #[cfg(test)]
    pub fn exporter_secret(&self) -> &[u8] {
        &self.exporter_secret
    }

    #[cfg(test)]
    pub fn base_nonce(&self) -> Option<&[u8]> {
        self.encryption_context
            .as_ref()
            .map(|c| c.base_nonce.as_slice())
    }

    #[cfg(test)]
    pub fn aead_key(&self) -> Option<&[u8]> {
        self.encryption_context
            .as_ref()
            .map(|c| c.aead_key.as_slice())
    }
}

impl<KDF: KdfType, AEAD: AeadType> HpkeContext for Context<KDF, AEAD> {
    type Error = HpkeError;

    /// Encrypt `data` using the cipher key of the context with optional `aad`.
    /// This function will internally increment the sequence number.
    ///
    /// # Errors
    ///
    /// Returns [SequenceNumberOverflow](HpkeError::SequenceNumberOverflow)
    /// in the event that the sequence number overflows. The sequence number is a u64 and starts
    /// at 0.
    fn seal(&mut self, aad: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.encryption_context
            .as_mut()
            .ok_or(HpkeError::ExportOnlyMode)?
            .seal(aad, data)
    }

    /// Decrypt `ciphertext` using the cipher key of the context with optional `aad`.
    /// This function will internally increment the sequence number.
    ///
    /// # Errors
    ///
    /// Returns [SequenceNumberOverflow](HpkeError::SequenceNumberOverflow)
    /// in the event that the sequence number overflows. The sequence number is a u64 and starts
    /// at 0.
    ///
    /// Returns [AeadError](HpkeError::AeadError) if decryption fails due to either an invalid
    /// `aad` value, or incorrect cipher key.
    fn open(&mut self, aad: Option<&[u8]>, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.encryption_context
            .as_mut()
            .ok_or(HpkeError::ExportOnlyMode)?
            .open(aad, ciphertext)
    }

    /// Export secret from encryption context.
    fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        self.kdf
            .labeled_expand(&self.exporter_secret, b"sec", exporter_context, len)
            .map_err(|e| HpkeError::KdfError(e.into()))
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub(super) struct EncryptionContext<AEAD: AeadType> {
    base_nonce: Vec<u8>,
    seq_number: u64,
    aead: AEAD,
    aead_key: Vec<u8>,
}

impl<AEAD: AeadType> EncryptionContext<AEAD> {
    pub fn new(base_nonce: Vec<u8>, aead: AEAD, aead_key: Vec<u8>) -> Self {
        EncryptionContext {
            base_nonce,
            seq_number: 0,
            aead,
            aead_key,
        }
    }
}

impl<AEAD: AeadType> EncryptionContext<AEAD> {
    //draft-irtf-cfrg-hpke Section 5.2.  Encryption and Decryption
    fn compute_nonce(&self) -> Vec<u8> {
        // Extend the sequence number out to the same number of bytes as the base nonce
        let seq_num_bytes = &self.seq_number.to_be_bytes() as &[u8];
        let mut seq_bytes = vec![0u8; self.aead.nonce_size() - seq_num_bytes.len()];
        seq_bytes.extend_from_slice(seq_num_bytes);

        // XOR base nonce with current sequence bytes
        self.base_nonce
            .iter()
            .zip(seq_bytes.iter())
            .map(|(&a, &b)| a ^ b)
            .collect()
    }

    #[inline]
    fn increment_seq(&mut self) -> Result<(), HpkeError> {
        // If the sequence number is going to roll over just throw an error
        if self.seq_number == u64::MAX {
            Err(HpkeError::SequenceNumberOverflow)
        } else {
            self.seq_number += 1;
            Ok(())
        }
    }

    pub fn seal(&mut self, aad: Option<&[u8]>, pt: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let ct = self
            .aead
            .seal(&self.aead_key, pt, aad, &self.compute_nonce())
            .map_err(|e| HpkeError::AeadError(e.into()))?;

        self.increment_seq()?;

        Ok(ct)
    }

    pub fn open(&mut self, aad: Option<&[u8]>, ct: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let pt = self
            .aead
            .open(&self.aead_key, ct, aad, &self.compute_nonce())
            .map_err(|e| HpkeError::AeadError(e.into()))?;

        self.increment_seq()?;

        Ok(pt)
    }
}

#[cfg(test)]
mod test {

    use aws_mls_core::crypto::HpkeContext;
    use aws_mls_crypto_openssl::{aead::Aead, ecdh::*, kdf::Kdf};
    use serde::Deserialize;

    use crate::{
        context::{Context, EncryptionContext},
        dhkem::DhKem,
        hpke::Hpke,
        test_utils::{filter_test_case, TestCaseAlgo},
    };

    #[test]
    fn rfc_context_test_vector() {
        let file = include_str!("../test_data/test_hpke.json");
        let test_vectors: Vec<ContextTestCase> = serde_json::from_str(file).unwrap();
        test_vectors.into_iter().for_each(context_test_case);
    }

    #[derive(Deserialize, Debug)]
    struct ContextTestCase {
        #[serde(flatten)]
        algo: TestCaseAlgo,
        #[serde(with = "hex::serde")]
        exporter_secret: Vec<u8>,
        #[serde(with = "hex::serde")]
        base_nonce: Vec<u8>,
        #[serde(with = "hex::serde")]
        key: Vec<u8>,
        encryptions: Vec<EncryptionTestCase>,
        exports: Vec<ExportTestCase>,
    }

    #[derive(Deserialize, Debug)]
    struct EncryptionTestCase {
        #[serde(with = "hex::serde", rename = "pt")]
        plaintext: Vec<u8>,
        #[serde(with = "hex::serde")]
        aad: Vec<u8>,
        #[serde(with = "hex::serde", rename = "ct")]
        ciphertext: Vec<u8>,
    }

    #[derive(Deserialize, Debug)]
    struct ExportTestCase {
        #[serde(with = "hex::serde")]
        exporter_context: Vec<u8>,
        #[serde(rename = "L")]
        length: usize,
        #[serde(with = "hex::serde")]
        exported_value: Vec<u8>,
    }

    fn context_test_case(test_case: ContextTestCase) {
        let cipher_suite = match filter_test_case(&test_case.algo) {
            Some(cipher_suite) => cipher_suite,
            None => return,
        };

        println!("Testing Context for ciphersuite {:?}", cipher_suite,);

        let kdf = Kdf::new(cipher_suite);
        let aead = Aead::new(cipher_suite);
        let kem_id = KemId::new(cipher_suite);

        let kem = DhKem::new(
            Ecdh::new(cipher_suite),
            kdf.clone(),
            kem_id as u16,
            kem_id.n_secret(),
        );

        // Create HPKE to compute correct suite_id and instantiate HpkeKdf
        let hpke = Hpke::new(kem, kdf, Some(aead.clone()));
        let encryption_context = EncryptionContext::new(test_case.base_nonce, aead, test_case.key);

        let mut s_context = Context::new(
            Some(encryption_context),
            test_case.exporter_secret,
            hpke.hpke_kdf(),
        );

        let mut r_context = s_context.clone();

        for enc_test_case in test_case.encryptions {
            // Encrypt
            let ct = s_context
                .seal(Some(&enc_test_case.aad), &enc_test_case.plaintext)
                .unwrap();

            assert_eq!(ct, enc_test_case.ciphertext);

            // Decrypt
            let pt = r_context.open(Some(&enc_test_case.aad), &ct).unwrap();

            assert_eq!(pt, enc_test_case.plaintext);

            // The state of the sender and receiver should be equal
            assert_eq!(s_context.aead_key(), r_context.aead_key());
            assert_eq!(s_context.base_nonce(), r_context.base_nonce());
            assert_eq!(s_context.exporter_secret(), r_context.exporter_secret());
        }

        for test in test_case.exports {
            let s_exported = s_context.export(&test.exporter_context, test.length);
            assert_eq!(s_exported.unwrap(), test.exported_value);

            let r_exported = r_context.export(&test.exporter_context, test.length);
            assert_eq!(r_exported.unwrap(), test.exported_value);
        }
    }
}