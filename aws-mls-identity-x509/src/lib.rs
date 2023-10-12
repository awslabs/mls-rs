// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![cfg_attr(not(feature = "std"), no_std)]
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
    use aws_mls_core::{
        crypto::SignaturePublicKey, error::IntoAnyError, identity::SigningIdentity,
    };
    use rand::{thread_rng, Rng};

    use crate::{CertificateChain, DerCertificate};

    #[derive(Debug, thiserror::Error)]
    #[error("test error")]
    pub struct TestError;

    impl IntoAnyError for TestError {
        fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
            Ok(self.into())
        }
    }

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
