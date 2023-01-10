use aws_mls_core::{identity::Credential, tls::tls_codec::Deserialize};

use crate::{CertificateChain, X509IdentityError, CERTIFICATE_CREDENTIAL_ID};

pub(crate) fn credential_to_chain(
    credential: &Credential,
) -> Result<CertificateChain, X509IdentityError> {
    if credential.credential_type.raw_value() != CERTIFICATE_CREDENTIAL_ID {
        return Err(X509IdentityError::UnsupportedCredentialType(
            credential.credential_type,
        ));
    }

    CertificateChain::tls_deserialize(&mut &*credential.credential_data)
        .map_err(|_| X509IdentityError::InvalidCertificateChain)
}
