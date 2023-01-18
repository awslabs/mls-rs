use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsSerialize, TlsSize};

use crate::provider::crypto::{CipherSuiteProvider, SignaturePublicKey, SignatureSecretKey};

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
    InternalSignerError(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("signature validation failed, info: {0:?}")]
    SignatureValidationFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
}

pub(crate) trait Signable<'a> {
    const SIGN_LABEL: &'static str;

    type SigningContext;

    fn signature(&self) -> &[u8];

    fn signable_content(&self, context: &Self::SigningContext)
        -> Result<Vec<u8>, tls_codec::Error>;

    fn write_signature(&mut self, signature: Vec<u8>);

    fn sign<P: CipherSuiteProvider>(
        &mut self,
        signature_provider: &P,
        signer: &SignatureSecretKey,
        context: &Self::SigningContext,
    ) -> Result<(), SignatureError> {
        let sign_content = SignContent::new(Self::SIGN_LABEL, self.signable_content(context)?);

        let signature = signature_provider
            .sign(signer, &sign_content.tls_serialize_detached()?)
            .map_err(|e| SignatureError::InternalSignerError(e.into()))?;

        self.write_signature(signature);

        Ok(())
    }

    fn verify<P: CipherSuiteProvider>(
        &self,
        signature_provider: &P,
        public_key: &SignaturePublicKey,
        context: &Self::SigningContext,
    ) -> Result<(), SignatureError> {
        let sign_content = SignContent::new(Self::SIGN_LABEL, self.signable_content(context)?);

        signature_provider
            .verify(
                public_key,
                self.signature(),
                &sign_content.tls_serialize_detached()?,
            )
            .map_err(|e| SignatureError::SignatureValidationFailed(e.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        client::test_utils::TEST_CIPHER_SUITE,
        group::test_utils::random_bytes,
        provider::crypto::test_utils::{
            test_cipher_suite_provider, try_test_cipher_suite_provider, TestCryptoProvider,
        },
    };
    use assert_matches::assert_matches;
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
        #[serde(with = "hex::serde")]
        public: Vec<u8>,
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

        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let provider = test_cipher_suite_provider(cipher_suite);

            let (signer, public) = provider.signature_key_generate().unwrap();

            let content = random_bytes(32);
            let context = random_bytes(32);

            let mut test_signable = TestSignable {
                content: content.clone(),
                signature: Vec::new(),
            };

            test_signable.sign(&provider, &signer, &context).unwrap();

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                content,
                context,
                signature: test_signable.signature,
                signer: signer.to_vec(),
                public: public.to_vec(),
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
            let Some(cipher_suite_provider) = try_test_cipher_suite_provider(one_case.cipher_suite) else {
                continue;
            };

            let signature_key = SignatureSecretKey::from(one_case.signer);
            let public_key = SignaturePublicKey::from(one_case.public);

            // Test signature generation
            let mut test_signable = TestSignable {
                content: one_case.content.clone(),
                signature: Vec::new(),
            };

            test_signable
                .sign(&cipher_suite_provider, &signature_key, &one_case.context)
                .unwrap();

            test_signable
                .verify(&cipher_suite_provider, &public_key, &one_case.context)
                .unwrap();

            // Test verifying an existing signature
            test_signable = TestSignable {
                content: one_case.content,
                signature: one_case.signature,
            };

            test_signable
                .verify(&cipher_suite_provider, &public_key, &one_case.context)
                .unwrap();
        }
    }

    #[test]
    fn test_invalid_signature() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (correct_secret, _) = cipher_suite_provider.signature_key_generate().unwrap();
        let (_, incorrect_public) = cipher_suite_provider.signature_key_generate().unwrap();

        let mut test_signable = TestSignable {
            content: random_bytes(32),
            signature: vec![],
        };

        test_signable
            .sign(&cipher_suite_provider, &correct_secret, &vec![])
            .unwrap();

        let res = test_signable.verify(&cipher_suite_provider, &incorrect_public, &vec![]);

        assert_matches!(res, Err(SignatureError::SignatureValidationFailed(_)));
    }

    #[test]
    fn test_invalid_context() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (secret, public) = cipher_suite_provider.signature_key_generate().unwrap();

        let correct_context = random_bytes(32);
        let incorrect_context = random_bytes(32);

        let mut test_signable = TestSignable {
            content: random_bytes(32),
            signature: vec![],
        };

        test_signable
            .sign(&cipher_suite_provider, &secret, &correct_context)
            .unwrap();

        let res = test_signable.verify(&cipher_suite_provider, &public, &incorrect_context);
        assert_matches!(res, Err(SignatureError::SignatureValidationFailed(_)));
    }
}
