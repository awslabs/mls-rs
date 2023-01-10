use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::crypto::SignaturePublicKey;

use super::Credential;

#[derive(
    Debug,
    Clone,
    Eq,
    Hash,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SigningIdentity {
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
}

impl SigningIdentity {
    pub fn new(credential: Credential, signature_key: SignaturePublicKey) -> SigningIdentity {
        SigningIdentity {
            credential,
            signature_key,
        }
    }
}
