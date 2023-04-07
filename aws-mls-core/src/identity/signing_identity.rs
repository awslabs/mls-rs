use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};

use crate::crypto::SignaturePublicKey;

use super::Credential;

#[derive(
    Debug,
    Clone,
    Eq,
    Hash,
    PartialEq,
    PartialOrd,
    Ord,
    MlsSize,
    MlsEncode,
    MlsDecode,
    serde::Serialize,
    serde::Deserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// MLS group member identity represented as a combination of a
/// public [`SignaturePublicKey`] and [`Credential`].
pub struct SigningIdentity {
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
}

impl SigningIdentity {
    /// Create a new signing identity from `credential` and `signature_key`
    pub fn new(credential: Credential, signature_key: SignaturePublicKey) -> SigningIdentity {
        SigningIdentity {
            credential,
            signature_key,
        }
    }
}
