use ferriscrypt::asym::ec_key::{PublicKey, SecretKey};
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsSerialize, TlsSize};

#[derive(Debug, Clone, TlsSize, TlsSerialize)]
struct SignContent {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    label: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
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

    type SignableContent: tls_codec::Serialize;
    type SigningContext;

    fn signature(&self) -> &[u8];
    fn signable_content(&self, context: &Self::SigningContext) -> Self::SignableContent;
    fn write_signature(&mut self, signature: Vec<u8>);

    fn sign<S: Signer>(
        &mut self,
        signer: &S,
        context: &Self::SigningContext,
    ) -> Result<(), SignatureError> {
        let sign_content = SignContent::new(
            Self::SIGN_LABEL,
            self.signable_content(context).tls_serialize_detached()?,
        );

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
        let sign_content = SignContent::new(
            Self::SIGN_LABEL,
            self.signable_content(context).tls_serialize_detached()?,
        );

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
