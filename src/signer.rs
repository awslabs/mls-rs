use ferriscrypt::asym::ec_key::{PublicKey, SecretKey};
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsSerialize, TlsSize};

#[derive(Debug, Clone, TlsSize, TlsSerialize)]
struct SignContent {
    #[tls_codec(with = "crate::tls::ByteVec")]
    label: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    content: Vec<u8>,
}

impl SignContent {
    pub fn new(label: &str, content: Vec<u8>) -> Self {
        Self {
            label: format!("MLS 1.0 {}", label).into_bytes(),
            content,
        }
    }
}

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error(transparent)]
    TlsSerializationError(#[from] tls_codec::Error),
    #[error("internal signer error: {0:?}")]
    InternalSignerError(#[source] Box<dyn std::error::Error>),
    #[error("signature validation failed, info: {0:?}")]
    SignatureValidationFailed(#[source] Box<dyn std::error::Error>),
}

pub(crate) trait Signable<'a> {
    const SIGN_LABEL: &'static str;

    type SigningContext;

    fn signature(&self) -> &[u8];

    fn signable_content(&self, context: &Self::SigningContext)
        -> Result<Vec<u8>, tls_codec::Error>;

    fn write_signature(&mut self, signature: Vec<u8>);

    fn sign<S: Signer>(
        &mut self,
        signer: &S,
        context: &Self::SigningContext,
    ) -> Result<(), SignatureError> {
        let sign_content = SignContent::new(Self::SIGN_LABEL, self.signable_content(context)?);

        let signature = signer
            .sign(&sign_content.tls_serialize_detached()?)
            .map_err(|e| SignatureError::InternalSignerError(e.into()))?;

        self.write_signature(signature);

        Ok(())
    }

    fn verify(
        &self,
        pub_key: &PublicKey,
        context: &Self::SigningContext,
    ) -> Result<(), SignatureError> {
        let sign_content = SignContent::new(Self::SIGN_LABEL, self.signable_content(context)?);

        let valid_signature = pub_key
            .verify(self.signature(), &sign_content.tls_serialize_detached()?)
            .map_err(|e| SignatureError::SignatureValidationFailed(e.into()))?;

        if valid_signature {
            Ok(())
        } else {
            Err(SignatureError::SignatureValidationFailed(
                "Invalid Signature".into(),
            ))
        }
    }
}

pub trait Signer {
    type Error: std::error::Error + Send + Sync + 'static;

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn public_key(&self) -> Result<PublicKey, Self::Error>;
}

impl Signer for SecretKey {
    type Error = ferriscrypt::asym::ec_key::EcKeyError;

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.sign(data)
    }

    fn public_key(&self) -> Result<PublicKey, Self::Error> {
        self.to_public()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher_suite::CipherSuite;
    use assert_matches::assert_matches;
    use ferriscrypt::{asym::ec_key::SecretKey, rand::SecureRng};
    use tls_codec::{Serialize, TlsByteVecU32};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        content: Vec<u8>,
        #[serde(with = "hex::serde")]
        context: Vec<u8>,
        #[serde(with = "hex::serde")]
        signature: Vec<u8>,
        #[serde(with = "hex::serde")]
        signer: Vec<u8>,
    }

    struct TestSignable {
        content: Vec<u8>,
        signature: Vec<u8>,
    }

    impl<'a> Signable<'a> for TestSignable {
        const SIGN_LABEL: &'static str = "TestLabel";

        type SigningContext = Vec<u8>;

        fn signature(&self) -> &[u8] {
            &self.signature
        }

        fn signable_content(
            &self,
            context: &Self::SigningContext,
        ) -> Result<Vec<u8>, tls_codec::Error> {
            let data = [context.as_slice(), self.content.as_slice()].concat();
            TlsByteVecU32::new(data).tls_serialize_detached()
        }

        fn write_signature(&mut self, signature: Vec<u8>) {
            self.signature = signature
        }
    }

    fn generate_test_cases() -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for cipher_suite in CipherSuite::all() {
            let signing_key = cipher_suite.generate_signing_key().unwrap();
            let content = SecureRng::gen(32).unwrap();
            let context = SecureRng::gen(32).unwrap();

            let mut test_signable = TestSignable {
                content: content.clone(),
                signature: Vec::new(),
            };

            test_signable.sign(&signing_key, &context).unwrap();

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                content,
                context,
                signature: test_signable.signature,
                signer: (*signing_key.to_der().unwrap()).clone(),
            });
        }

        test_cases
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(signatures, generate_test_cases)
    }

    #[test]
    fn test_signatures() {
        let cases = load_test_cases();

        for one_case in cases {
            if CipherSuite::from_raw(one_case.cipher_suite).is_none() {
                println!("Skipping test for unsupported cipher suite");
                continue;
            }

            let signature_key = SecretKey::from_der(&one_case.signer).unwrap();

            // Test signature generation
            let mut test_signable = TestSignable {
                content: one_case.content.clone(),
                signature: Vec::new(),
            };

            test_signable
                .sign(&signature_key, &one_case.context)
                .unwrap();

            test_signable
                .verify(&signature_key.to_public().unwrap(), &one_case.context)
                .unwrap();

            // Test verifying an existing signature
            test_signable = TestSignable {
                content: one_case.content,
                signature: one_case.signature,
            };

            test_signable
                .verify(&signature_key.to_public().unwrap(), &one_case.context)
                .unwrap();
        }
    }

    #[test]
    fn test_invalid_signature() {
        let correct_key = CipherSuite::Curve25519Aes128
            .generate_signing_key()
            .unwrap();
        let incorrect_key = CipherSuite::Curve25519Aes128
            .generate_signing_key()
            .unwrap();

        let mut test_signable = TestSignable {
            content: SecureRng::gen(32).unwrap(),
            signature: vec![],
        };

        test_signable.sign(&correct_key, &vec![]).unwrap();

        let res = test_signable.verify(&incorrect_key.to_public().unwrap(), &vec![]);
        assert_matches!(res, Err(SignatureError::SignatureValidationFailed(_)));
    }

    #[test]
    fn test_invalid_context() {
        let signing_key = CipherSuite::Curve25519Aes128
            .generate_signing_key()
            .unwrap();

        let correct_context = SecureRng::gen(32).unwrap();
        let incorrect_context = SecureRng::gen(32).unwrap();

        let mut test_signable = TestSignable {
            content: SecureRng::gen(32).unwrap(),
            signature: vec![],
        };

        test_signable.sign(&signing_key, &correct_context).unwrap();

        let res = test_signable.verify(&signing_key.to_public().unwrap(), &incorrect_context);
        assert_matches!(res, Err(SignatureError::SignatureValidationFailed(_)));
    }
}
