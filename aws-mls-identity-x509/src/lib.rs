#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(error_in_core))]
extern crate alloc;

mod builder;
mod error;
mod identity_extractor;
mod provider;
mod traits;
mod util;

pub use builder::*;
pub use error::*;
pub use identity_extractor::*;
pub use provider::*;
pub use traits::*;

pub use aws_mls_core::identity::{CertificateChain, DerCertificate};

#[cfg(all(test, feature = "std"))]
pub(crate) mod test_utils {

    use alloc::vec;
    use aws_mls_core::{crypto::SignaturePublicKey, identity::SigningIdentity};
    use rand::{thread_rng, Rng};

    use crate::{CertificateChain, DerCertificate};

    #[derive(Debug, thiserror::Error)]
    #[error("test error")]
    pub struct TestError;

    pub fn test_certificate_chain() -> CertificateChain {
        (0..3)
            .map(|_| {
                let mut data = [0u8; 32];
                thread_rng().fill(&mut data);
                DerCertificate::from(data.to_vec())
            })
            .collect::<CertificateChain>()
    }

    pub fn test_signing_identity() -> SigningIdentity {
        let chain = test_certificate_chain();
        test_signing_identity_with_chain(chain)
    }

    pub fn test_signing_identity_with_chain(chain: CertificateChain) -> SigningIdentity {
        SigningIdentity {
            signature_key: SignaturePublicKey::from(vec![0u8; 128]),
            credential: chain.into_credential(),
        }
    }
}
