use aws_mls_core::identity::Credential;

use crate::{CertificateChain, X509IdentityError};

pub(crate) fn credential_to_chain(
    credential: &Credential,
) -> Result<CertificateChain, X509IdentityError> {
    credential
        .as_x509()
        .ok_or_else(|| X509IdentityError::UnsupportedCredentialType(credential.credential_type()))
        .cloned()
}
