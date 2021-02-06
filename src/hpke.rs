use crate::kem::{KeyEncapsulationMechanism, AsymmetricKeyEngine};
use crate::aead;
use thiserror::Error;
use std::marker::PhantomData;
use crate::kdf::KeyDerivationFunction;

#[derive(Error, Debug)]
pub enum HPKEError {
    #[error("cipher error")]
    CipherError(#[from] aead::CipherError)
}

pub struct Ciphertext {
    pub kem_output: Vec<u8>,
    pub ciphertext: aead::CipherText,
}

pub struct HPKEOneShot<
    CT: aead::Cipher,
    AKE: AsymmetricKeyEngine,
    KDF: KeyDerivationFunction,
    KEM: KeyEncapsulationMechanism<AKE, KDF>> {
    pub kem: KEM,
    pub cipher: CT,
    phantom_ake: PhantomData<AKE>,
    phantom_kdf: PhantomData<KDF>
}

impl <
    CT: aead::Cipher,
    AKE: AsymmetricKeyEngine,
    KDF: KeyDerivationFunction,
    KEM: KeyEncapsulationMechanism<AKE, KDF>> HPKEOneShot<CT, AKE, KDF, KEM> {
    pub fn seal<NG: aead::NonceGenerator>(&self, data: Vec<u8>,
                                    nonce: &NG,
                                    aad: Option<&Vec<u8>>,
                                    remote_key: &AKE::PubKeyType) -> Result<Ciphertext, HPKEError> {

        let (shared_secret, kem_output) = self.kem.encapsulate(remote_key,
                                                          CT::info().key_len as usize);

        let ciphertext = self.cipher.encrypt(&shared_secret, &data, aad, nonce)?;

        Ok(Ciphertext {
            kem_output,
            ciphertext
        })
    }

    pub fn open(&self, ciphertext: &Ciphertext,
                aad: Option<&Vec<u8>>, secret_key: AKE::SecretKeyType) -> Result<Vec<u8>, HPKEError> {
        let shared_secret = self.kem.decapsulate(&ciphertext.kem_output,
                                                 &secret_key);
        self.cipher
            .decrypt(&shared_secret, &ciphertext.ciphertext, aad)
            .map_err(|e| e.into())
    }
}

