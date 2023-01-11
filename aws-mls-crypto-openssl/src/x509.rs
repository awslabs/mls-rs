use aws_mls_core::{crypto::SignaturePublicKey, time::SystemTimeError};
use aws_mls_identity_x509::{DerCertificate, SubjectParser, X509CredentialValidator};
use openssl::{
    bn::BigNumContext,
    ec::PointConversionForm,
    error::ErrorStack,
    pkey::{PKey, Public},
    stack::Stack,
    x509::{
        store::{X509Store, X509StoreBuilder},
        verify::{X509VerifyFlags, X509VerifyParam},
        X509StoreContext, X509VerifyResult, X509,
    },
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum X509Error {
    #[error("empty certificate chain")]
    EmptyCertificateChain,
    #[error("certificate chain validation failure: {0:?}")]
    ChainValidationFailure(String),
    #[error("root ca is not a der encoded x509 certificate")]
    InvalidCertificateData,
    #[error("root ca is not properly self-signed")]
    NonSelfSignedCa,
    #[error(transparent)]
    OpensslError(#[from] ErrorStack),
    #[error(transparent)]
    SystemTimeError(#[from] SystemTimeError),
}

#[derive(Debug, Clone)]
pub struct X509Validator {
    root_ca_list: Vec<DerCertificate>,
    use_system_ca: bool,
}

impl X509Validator {
    pub fn new(root_ca_list: Vec<DerCertificate>) -> Result<Self, X509Error> {
        root_ca_list.iter().try_for_each(|ca| {
            let parsed = X509::from_der(ca).map_err(|_| X509Error::InvalidCertificateData)?;

            if !parsed.verify(parsed.public_key()?.as_ref())? {
                return Err(X509Error::NonSelfSignedCa);
            };

            Ok::<_, X509Error>(())
        })?;

        Ok(X509Validator {
            root_ca_list,
            use_system_ca: false,
        })
    }

    pub fn with_system_ca(self) -> Self {
        Self {
            use_system_ca: true,
            ..self
        }
    }

    fn make_store(
        &self,
        timestamp: Option<aws_mls_core::time::MlsTime>,
    ) -> Result<X509Store, X509Error> {
        let mut builder = X509StoreBuilder::new()?;

        self.root_ca_list
            .iter()
            .try_for_each(|c| builder.add_cert(X509::from_der(c)?))?;

        if self.use_system_ca {
            builder.set_default_paths()?;
        }

        let mut params = X509VerifyParam::new()?;

        if let Some(timestamp) = timestamp {
            params.set_time(timestamp.seconds_since_epoch()? as i64);
        } else {
            params.flags().set(X509VerifyFlags::NO_CHECK_TIME, true);
        }

        builder.set_param(&params)?;

        Ok(builder.build())
    }

    pub fn validate_chain(
        &self,
        chain: &aws_mls_identity_x509::CertificateChain,
        timestamp: Option<aws_mls_core::time::MlsTime>,
    ) -> Result<aws_mls_core::crypto::SignaturePublicKey, X509Error> {
        let store = self.make_store(timestamp)?;

        let mut context = X509StoreContext::new()?;

        let leaf = chain.leaf().ok_or(X509Error::EmptyCertificateChain)?;

        let leaf_certificate = X509::from_der(leaf)?;

        let cert_chain = chain.iter().try_fold(Stack::new()?, |mut stack, cert| {
            stack.push(X509::from_der(cert)?)?;
            Ok::<_, X509Error>(stack)
        })?;

        let verify_res = context.init(&store, &leaf_certificate, &cert_chain, |context| {
            context.verify_cert()?;
            Ok(context.error())
        })?;

        match verify_res {
            X509VerifyResult::OK => {
                let signature_public_key = pub_key_to_uncompressed(leaf_certificate.public_key()?)
                    .map(SignaturePublicKey::from)?;
                Ok(signature_public_key)
            }
            _ => Err(X509Error::ChainValidationFailure(
                verify_res.error_string().to_string(),
            )),
        }
    }
}

pub fn pub_key_to_uncompressed(key: PKey<Public>) -> Result<Vec<u8>, X509Error> {
    if let Ok(ec_key) = key.ec_key() {
        let mut ctx = BigNumContext::new()?;

        ec_key
            .public_key()
            .to_bytes(ec_key.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(Into::into)
    } else {
        key.raw_public_key().map_err(Into::into)
    }
}

impl X509CredentialValidator for X509Validator {
    type Error = X509Error;

    fn validate_chain(
        &self,
        chain: &aws_mls_identity_x509::CertificateChain,
        timestamp: Option<aws_mls_core::time::MlsTime>,
    ) -> Result<SignaturePublicKey, Self::Error> {
        self.validate_chain(chain, timestamp)
    }
}

struct X509SubjectParser;

impl SubjectParser for X509SubjectParser {
    type Error = X509Error;

    fn parse_subject(&self, certificate: &DerCertificate) -> Result<Vec<u8>, Self::Error> {
        X509::from_der(certificate)?
            .subject_name()
            .to_der()
            .map_err(Into::into)
    }
}

#[cfg(test)]
pub mod test_utils {
    use aws_mls_identity_x509::{CertificateChain, DerCertificate};

    pub fn load_test_ca() -> DerCertificate {
        DerCertificate::from(include_bytes!("../test_data/x509/ca.der").to_vec())
    }

    pub fn load_another_ca() -> DerCertificate {
        DerCertificate::from(include_bytes!("../test_data/x509/another_ca.der").to_vec())
    }

    pub fn load_test_cert_chain() -> CertificateChain {
        let entry0 = include_bytes!("../test_data/x509/leaf.der").to_vec();
        let entry1 = include_bytes!("../test_data/x509/intermediate.der").to_vec();
        let entry2 = include_bytes!("../test_data/x509/ca.der").to_vec();

        CertificateChain::from_iter(
            [entry0, entry1, entry2]
                .into_iter()
                .map(DerCertificate::from),
        )
    }

    pub fn load_test_system_cert_chain() -> CertificateChain {
        let entry0 = include_bytes!("../test_data/x509/github_leaf.der").to_vec();
        let entry1 = include_bytes!("../test_data/x509/github_intermediate.der").to_vec();

        CertificateChain::from_iter([entry0, entry1].into_iter().map(DerCertificate::from))
    }

    pub fn load_test_invalid_chain() -> CertificateChain {
        let entry0 = include_bytes!("../test_data/x509/github_leaf.der").to_vec();
        let entry1 = include_bytes!("../test_data/x509/intermediate.der").to_vec();

        CertificateChain::from_iter([entry0, entry1].into_iter().map(DerCertificate::from))
    }

    pub fn load_test_invalid_ca_chain() -> CertificateChain {
        let entry0 = include_bytes!("../test_data/x509/leaf.der").to_vec();
        let entry1 = include_bytes!("../test_data/x509/intermediate.der").to_vec();
        let entry2 = include_bytes!("../test_data/x509/another_ca.der").to_vec();

        CertificateChain::from_iter(
            [entry0, entry1, entry2]
                .into_iter()
                .map(DerCertificate::from),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use assert_matches::assert_matches;
    use aws_mls_core::{crypto::SignaturePublicKey, time::MlsTime};
    use aws_mls_identity_x509::{CertificateChain, SubjectParser};
    use openssl::x509::{X509Name, X509};

    use crate::x509::test_utils::{
        load_another_ca, load_test_invalid_ca_chain, load_test_invalid_chain,
    };

    use super::{
        pub_key_to_uncompressed,
        test_utils::{load_test_ca, load_test_cert_chain, load_test_system_cert_chain},
        X509Error, X509SubjectParser, X509Validator,
    };

    #[test]
    fn can_detect_invalid_ca_certificates() {
        assert_matches!(
            X509Validator::new(vec![vec![0u8; 32].into()]),
            Err(X509Error::InvalidCertificateData)
        )
    }

    #[test]
    fn can_detect_ca_cert_with_invalid_self_signed_signature() {
        let test_cert = load_test_cert_chain()[0].clone();

        assert_matches!(
            X509Validator::new(vec![test_cert]),
            Err(X509Error::NonSelfSignedCa)
        )
    }

    #[test]
    fn can_validate_cert_chain() {
        let chain = load_test_cert_chain();

        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();
        let system_validator = X509Validator::new(vec![]).unwrap().with_system_ca();

        validator
            .validate_chain(&chain, Some(MlsTime::now()))
            .unwrap();

        assert_matches!(
            system_validator.validate_chain(&chain, None),
            Err(X509Error::ChainValidationFailure(_))
        )
    }

    #[test]
    fn will_fail_on_empty_chain() {
        let validator = X509Validator::new(vec![]).unwrap();
        let empty: Vec<Vec<u8>> = Vec::new();

        let res = validator.validate_chain(&CertificateChain::from(empty), Some(MlsTime::now()));

        assert_matches!(res, Err(X509Error::EmptyCertificateChain));
    }

    #[test]
    fn can_validate_against_system_ca_list() {
        let chain = load_test_system_cert_chain();

        let plain_validator = X509Validator::new(vec![load_test_ca()]).unwrap();
        let system_validator = X509Validator::new(vec![]).unwrap().with_system_ca();

        system_validator
            .validate_chain(&chain, Some(MlsTime::now()))
            .unwrap();

        assert_matches!(
            plain_validator.validate_chain(&chain, None),
            Err(X509Error::ChainValidationFailure(_))
        )
    }

    #[test]
    fn will_fail_on_invalid_chain() {
        let chain = load_test_invalid_chain();
        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();

        let res = validator.validate_chain(&chain, Some(MlsTime::now()));

        assert_matches!(res, Err(X509Error::ChainValidationFailure(_)));
    }

    #[test]
    fn will_fail_on_invalid_ca() {
        let chain = load_test_invalid_ca_chain();
        let validator = X509Validator::new(vec![load_another_ca()]).unwrap();
        let res = validator.validate_chain(&chain, Some(MlsTime::now()));

        assert_matches!(res, Err(X509Error::ChainValidationFailure(_)));
    }

    #[test]
    fn can_detect_expired_certs() {
        let chain = load_test_cert_chain();

        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();

        let res = validator.validate_chain(
            &chain,
            Some(MlsTime::from_duration_since_epoch(Duration::from_secs(1798761600)).unwrap()),
        );

        assert_matches!(res, Err(X509Error::ChainValidationFailure(_)));
    }

    #[test]
    fn will_return_public_key_of_leaf() {
        let chain = load_test_cert_chain();

        let expected = pub_key_to_uncompressed(
            X509::from_der(chain.leaf().unwrap())
                .unwrap()
                .public_key()
                .unwrap(),
        )
        .map(SignaturePublicKey::from)
        .unwrap();

        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();

        assert_eq!(validator.validate_chain(&chain, None).unwrap(), expected)
    }

    #[test]
    fn test_subject_parser() {
        let test_cert = load_test_ca();

        let mut expected_name_builder = X509Name::builder().unwrap();

        expected_name_builder
            .append_entry_by_text("CN", "CA")
            .unwrap();

        let expected_name = expected_name_builder.build().to_der().unwrap();

        assert_eq!(
            X509SubjectParser.parse_subject(&test_cert).unwrap(),
            expected_name
        );
    }
}
