use crate::crypto::asym::AsymmetricKey;
use crate::crypto::signature::{
    PublicSignatureKey, Signable, SignatureError, SignatureScheme, SignatureSchemeId, Verifier,
};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

#[derive(IntoPrimitive, TryFromPrimitive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum CredentialIdentifier {
    Basic = 0x0001,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum Credential {
    Basic(BasicCredential), //TODO: X509
}

impl Credential {
    pub fn get_signature_type(&self) -> &SignatureSchemeId {
        match self {
            Credential::Basic(credential) => &credential.signature_scheme,
        }
    }
}

impl Verifier for Credential {
    fn verify<T: Signable + 'static>(
        &self,
        signature: &[u8],
        data: &T,
    ) -> Result<bool, SignatureError> {
        match self {
            Credential::Basic(b) => b.verify(signature, data),
        }
    }
}

pub trait CredentialConvertable {
    fn to_credential(&self) -> Credential;
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BasicCredential {
    pub signature_key: Vec<u8>,
    pub identity: Vec<u8>,
    pub signature_scheme: SignatureSchemeId,
}

impl CredentialConvertable for BasicCredential {
    fn to_credential(&self) -> Credential {
        Credential::Basic(self.clone())
    }
}

impl BasicCredential {
    pub fn new<SS: SignatureScheme>(
        identity: Vec<u8>,
        signature_scheme: SS,
    ) -> Result<Self, SignatureError> {
        Ok(Self {
            identity,
            signature_scheme: SS::IDENTIFIER,
            signature_key: signature_scheme.get_verifier().to_bytes()?,
        })
    }
}

impl From<&BasicCredential> for PublicSignatureKey {
    fn from(cred: &BasicCredential) -> Self {
        PublicSignatureKey {
            signature_scheme: cred.signature_scheme.clone(),
            signature_key: cred.signature_key.clone(),
        }
    }
}

impl Verifier for BasicCredential {
    fn verify<T: Signable + 'static>(
        &self,
        signature: &[u8],
        data: &T,
    ) -> Result<bool, SignatureError> {
        PublicSignatureKey::from(self).verify(signature, data)
    }
}

#[cfg(test)]
mod test {
    use crate::credential::{BasicCredential, Credential, CredentialConvertable};
    use crate::crypto::signature::test_utils::{get_test_verifier, MockTestSignatureScheme};
    use crate::crypto::signature::{SignatureSchemeId, Verifier};

    fn get_test_basic_credential() -> Credential {
        BasicCredential {
            identity: vec![],
            signature_scheme: SignatureSchemeId::Test,
            signature_key: vec![],
        }
        .to_credential()
    }

    #[test]
    fn test_credential_get_signature_type() {
        let cred = get_test_basic_credential();
        let cred_sig_type = cred.get_signature_type().clone();
        assert_eq!(cred_sig_type, SignatureSchemeId::Test);
    }

    #[test]
    fn test_credential_verify() {
        let cred = get_test_basic_credential();
        // The test signature function returns false if length is 0 for sig and data
        let pass = vec![0u8];
        let fail = vec![];

        assert!(cred.verify(&pass, &pass).expect("failed verify"));
        assert!(!cred.verify(&fail, &fail).expect("failed verify"));
        assert!(!cred.verify(&pass, &fail).expect("failed verify"));
        assert!(!cred.verify(&fail, &pass).expect("failed verify"));
    }

    #[test]
    fn test_new_basic_credential() {
        let test_data = b"test".to_vec();
        let test_verifier = get_test_verifier(&test_data);
        let mut signature_scheme = MockTestSignatureScheme::new();
        signature_scheme
            .expect_get_verifier()
            .return_const(test_verifier);

        let test_identity = b"identity".to_vec();
        let basic_cred = BasicCredential::new(test_identity.clone(), signature_scheme)
            .expect("credential error");

        assert_eq!(basic_cred.identity, test_identity);
        assert_eq!(basic_cred.signature_key, test_data);
        assert_eq!(basic_cred.signature_scheme, SignatureSchemeId::Test);
    }

    #[test]
    fn test_basic_credential_verify() {
        let cred = BasicCredential {
            identity: vec![],
            signature_scheme: SignatureSchemeId::Test,
            signature_key: vec![],
        };

        // The test signature function returns true if length > 0 and data length > 0
        let pass = vec![0u8];
        let fail = vec![];

        assert!(cred.verify(&pass, &pass).expect("failed verify"));
        assert!(!cred.verify(&fail, &fail).expect("failed verify"));
        assert!(!cred.verify(&pass, &fail).expect("failed verify"));
        assert!(!cred.verify(&fail, &pass).expect("failed verify"));
    }
}
