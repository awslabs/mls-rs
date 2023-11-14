// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::{net::IpAddr, ops::Deref};

use mls_rs_core::{
    crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey},
    error::IntoAnyError,
    identity::{CertificateChain, SigningIdentity},
};
use mls_rs_identity_x509::{
    CertificateRequestParameters, DerCertificate, DerCertificateRequest, SubjectAltName,
    SubjectComponent, SubjectIdentityExtractor, X509CredentialValidator, X509IdentityProvider,
    X509RequestWriter,
};
use openssl::{
    bn::BigNumContext,
    ec::PointConversionForm,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, PKeyRef, Private, Public},
    stack::{Stack, StackRef},
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectAlternativeName},
        store::{X509Store, X509StoreBuilder},
        verify::{X509VerifyFlags, X509VerifyParam},
        X509Builder, X509Extension, X509Name, X509NameBuilder, X509NameRef, X509Ref,
        X509ReqBuilder, X509StoreContext, X509VerifyResult, X509v3Context, X509,
    },
};
use thiserror::Error;

use crate::ec_signer::{EcSigner, EcSignerError};

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
    #[error("invalid certificate lifetime")]
    InvalidCertificateLifetime,
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
    #[error(transparent)]
    EcSignerError(#[from] EcSignerError),
    #[error(transparent)]
    OpensslError(#[from] ErrorStack),
}

impl IntoAnyError for X509Error {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
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
        timestamp: Option<mls_rs_core::time::MlsTime>,
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
            params.set_time(timestamp.seconds_since_epoch() as i64);
        } else {
            params.flags().set(X509VerifyFlags::NO_CHECK_TIME, true);
        }

        builder.set_param(&params)?;

        Ok(builder.build())
    }

    pub fn validate_chain(
        &self,
        chain: &mls_rs_identity_x509::CertificateChain,
        timestamp: Option<mls_rs_core::time::MlsTime>,
    ) -> Result<mls_rs_core::crypto::SignaturePublicKey, X509Error> {
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
        chain: &mls_rs_identity_x509::CertificateChain,
        timestamp: Option<mls_rs_core::time::MlsTime>,
    ) -> Result<SignaturePublicKey, Self::Error> {
        self.validate_chain(chain, timestamp)
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct X509Reader {}

impl X509Reader {
    pub fn new() -> X509Reader {
        Self {}
    }

    fn parse_certificate(&self, certificate: &DerCertificate) -> Result<X509, ErrorStack> {
        X509::from_der(certificate)
    }
}

impl mls_rs_identity_x509::X509CertificateReader for X509Reader {
    type Error = X509Error;

    fn subject_bytes(&self, certificate: &DerCertificate) -> Result<Vec<u8>, Self::Error> {
        self.parse_certificate(certificate)?
            .subject_name()
            .to_der()
            .map_err(Into::into)
    }

    fn subject_components(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<mls_rs_identity_x509::SubjectComponent>, Self::Error> {
        let subject = self.parse_certificate(certificate)?;

        let components = subject
            .subject_name()
            .entries()
            .filter_map(|e| {
                e.data()
                    .as_utf8()
                    .map(|v| v.to_string())
                    .ok()
                    .and_then(|data| match e.object().nid() {
                        Nid::COMMONNAME => Some(SubjectComponent::CommonName(data)),
                        Nid::SURNAME => Some(SubjectComponent::Surname(data)),
                        Nid::SERIALNUMBER => Some(SubjectComponent::SerialNumber(data)),
                        Nid::COUNTRYNAME => Some(SubjectComponent::CountryName(data)),
                        Nid::LOCALITYNAME => Some(SubjectComponent::Locality(data)),
                        Nid::STATEORPROVINCENAME => Some(SubjectComponent::State(data)),
                        Nid::STREETADDRESS => Some(SubjectComponent::StreetAddress(data)),
                        Nid::ORGANIZATIONNAME => Some(SubjectComponent::OrganizationName(data)),
                        Nid::ORGANIZATIONALUNITNAME => {
                            Some(SubjectComponent::OrganizationalUnit(data))
                        }
                        Nid::TITLE => Some(SubjectComponent::Title(data)),
                        Nid::GIVENNAME => Some(SubjectComponent::GivenName(data)),
                        Nid::PKCS9_EMAILADDRESS => Some(SubjectComponent::EmailAddress(data)),
                        Nid::USERID => Some(SubjectComponent::UserId(data)),
                        Nid::DOMAINCOMPONENT => Some(SubjectComponent::DomainComponent(data)),
                        Nid::INITIALS => Some(SubjectComponent::Initials(data)),
                        Nid::GENERATIONQUALIFIER => {
                            Some(SubjectComponent::GenerationQualifier(data))
                        }
                        Nid::DISTINGUISHEDNAME => {
                            Some(SubjectComponent::DistinguishedNameQualifier(data))
                        }
                        Nid::PSEUDONYM => Some(SubjectComponent::Pseudonym(data)),
                        _ => None,
                    })
            })
            .collect();

        Ok(components)
    }

    fn subject_alt_names(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<mls_rs_identity_x509::SubjectAltName>, Self::Error> {
        let Some(alt_names) = self.parse_certificate(certificate)?.subject_alt_names() else {
            return Ok(vec![]);
        };

        let alt_names = alt_names
            .iter()
            .filter_map(|n| {
                n.email()
                    .map(|e| SubjectAltName::Email(e.to_string()))
                    .or_else(|| n.dnsname().map(|d| SubjectAltName::Dns(d.to_string())))
                    .or_else(|| n.uri().map(|d| SubjectAltName::Uri(d.to_string())))
                    .or_else(|| {
                        n.ipaddress()
                            .and_then(ip_bytes_to_ip_addr)
                            .map(|v| SubjectAltName::Ip(v.to_string()))
                    })
            })
            .collect();

        Ok(alt_names)
    }

    fn public_key(&self, certificate: &DerCertificate) -> Result<SignaturePublicKey, Self::Error> {
        let public_key = self.parse_certificate(certificate)?.public_key()?;
        pub_key_to_uncompressed(public_key).map(Into::into)
    }
}

fn ip_bytes_to_ip_addr(input: &[u8]) -> Option<IpAddr> {
    TryInto::<[u8; 16]>::try_into(input)
        .map(IpAddr::from)
        .or_else(|_| TryInto::<[u8; 4]>::try_into(input).map(IpAddr::from))
        .ok()
}

#[derive(Debug, Clone)]
pub struct CertificateRequestWriter {
    signer: EcSigner,
    signing_key: SignatureSecretKey,
}

impl CertificateRequestWriter {
    pub fn new(
        cipher_suite: CipherSuite,
        signing_key: SignatureSecretKey,
    ) -> Result<Self, X509Error> {
        let signer = EcSigner::new(cipher_suite).ok_or(X509Error::UnsupportedCipherSuite)?;

        Ok(Self {
            signing_key,
            signer,
        })
    }

    pub fn new_generate_key(cipher_suite: CipherSuite) -> Result<Self, X509Error> {
        let signer = EcSigner::new(cipher_suite).ok_or(X509Error::UnsupportedCipherSuite)?;

        let (secret, _) = signer.signature_key_generate()?;

        Ok(Self {
            signer,
            signing_key: secret,
        })
    }

    pub fn signing_key(&self) -> &SignatureSecretKey {
        &self.signing_key
    }
}

fn build_x509_name(components: &[SubjectComponent]) -> Result<X509Name, ErrorStack> {
    let mut builder = X509NameBuilder::new()?;

    components.iter().try_for_each(|c| {
        let (nid, v) = match c {
            SubjectComponent::CommonName(cn) => (Nid::COMMONNAME, cn),
            SubjectComponent::Surname(s) => (Nid::SURNAME, s),
            SubjectComponent::SerialNumber(s) => (Nid::SERIALNUMBER, s),
            SubjectComponent::CountryName(c) => (Nid::COUNTRYNAME, c),
            SubjectComponent::Locality(l) => (Nid::LOCALITYNAME, l),
            SubjectComponent::State(s) => (Nid::STATEORPROVINCENAME, s),
            SubjectComponent::StreetAddress(a) => (Nid::STREETADDRESS, a),
            SubjectComponent::OrganizationName(on) => (Nid::ORGANIZATIONNAME, on),
            SubjectComponent::OrganizationalUnit(ou) => (Nid::ORGANIZATIONALUNITNAME, ou),
            SubjectComponent::Title(t) => (Nid::TITLE, t),
            SubjectComponent::GivenName(gn) => (Nid::GIVENNAME, gn),
            SubjectComponent::EmailAddress(e) => (Nid::PKCS9_EMAILADDRESS, e),
            SubjectComponent::UserId(u) => (Nid::USERID, u),
            SubjectComponent::DomainComponent(dc) => (Nid::DOMAINCOMPONENT, dc),
            SubjectComponent::Initials(i) => (Nid::INITIALS, i),
            SubjectComponent::GenerationQualifier(gq) => (Nid::GENERATIONQUALIFIER, gq),
            SubjectComponent::DistinguishedNameQualifier(dnq) => (Nid::DISTINGUISHEDNAME, dnq),
            SubjectComponent::Pseudonym(p) => (Nid::PSEUDONYM, p),
        };

        builder.append_entry_by_nid(nid, v)
    })?;

    Ok(builder.build())
}

fn build_subject_alt_name(
    alt_name: &SubjectAltName,
    context: &X509v3Context<'_>,
) -> Result<X509Extension, ErrorStack> {
    let mut name = SubjectAlternativeName::new();

    match alt_name {
        SubjectAltName::Email(e) => name.email(e),
        SubjectAltName::Uri(u) => name.uri(u),
        SubjectAltName::Dns(d) => name.dns(d),
        SubjectAltName::Rid(r) => name.rid(r),
        SubjectAltName::Ip(i) => name.ip(i),
    }
    .build(context)
}

trait X509BuilderCommon {
    fn set_pubkey(&mut self, pub_key: &PKeyRef<Public>) -> Result<(), ErrorStack>;
    fn set_subject_name(&mut self, name: &X509NameRef) -> Result<(), ErrorStack>;
    fn add_extensions(&mut self, extensions: &StackRef<X509Extension>) -> Result<(), ErrorStack>;
    fn x509v3_context<'a>(&'a self, issuer: Option<&'a X509Ref>) -> X509v3Context<'a>;
    fn sign(&mut self, key: &PKeyRef<Private>, digest: MessageDigest) -> Result<(), ErrorStack>;

    fn sign_with_ec_signer(
        &mut self,
        signer: &EcSigner,
        signature_key: &SignatureSecretKey,
    ) -> Result<(), X509Error> {
        let signing_key = signer.pkey_from_secret_key(signature_key)?;

        // Sign and use MessageDigest::null if we are using ed25519 or ed448
        self.sign(
            &signing_key,
            signer.message_digest().unwrap_or_else(MessageDigest::null),
        )
        .map_err(Into::into)
    }
}

impl X509BuilderCommon for X509ReqBuilder {
    fn set_pubkey(&mut self, pub_key: &PKeyRef<Public>) -> Result<(), ErrorStack> {
        self.set_pubkey(pub_key)
    }

    fn set_subject_name(&mut self, name: &X509NameRef) -> Result<(), ErrorStack> {
        self.set_subject_name(name)
    }

    fn add_extensions(&mut self, extensions: &StackRef<X509Extension>) -> Result<(), ErrorStack> {
        self.add_extensions(extensions)
    }

    fn x509v3_context<'a>(&'a self, _issuer: Option<&X509Ref>) -> X509v3Context<'a> {
        self.x509v3_context(None)
    }

    fn sign(&mut self, key: &PKeyRef<Private>, digest: MessageDigest) -> Result<(), ErrorStack> {
        self.sign(key, digest)
    }
}

impl X509BuilderCommon for X509Builder {
    fn set_pubkey(&mut self, pub_key: &PKeyRef<Public>) -> Result<(), ErrorStack> {
        self.set_pubkey(pub_key)
    }

    fn set_subject_name(&mut self, name: &X509NameRef) -> Result<(), ErrorStack> {
        self.set_subject_name(name)
    }

    fn add_extensions(&mut self, extensions: &StackRef<X509Extension>) -> Result<(), ErrorStack> {
        extensions
            .into_iter()
            .try_for_each(|ex| self.append_extension2(ex))
    }

    fn x509v3_context<'a>(&'a self, issuer: Option<&'a X509Ref>) -> X509v3Context<'a> {
        self.x509v3_context(issuer, None)
    }

    fn sign(&mut self, key: &PKeyRef<Private>, digest: MessageDigest) -> Result<(), ErrorStack> {
        self.sign(key, digest)
    }
}

impl X509RequestWriter for CertificateRequestWriter {
    type Error = X509Error;

    fn write(
        &self,
        params: CertificateRequestParameters,
    ) -> Result<DerCertificateRequest, Self::Error> {
        let mut builder = X509ReqBuilder::new()?;

        builder.set_subject_name(build_x509_name(&params.subject)?.as_ref())?;

        let ext_context = builder.x509v3_context(None);

        // Add subject alt names
        let mut extensions =
            params
                .subject_alt_names
                .iter()
                .try_fold(Stack::new()?, |mut stack, san| {
                    stack.push(build_subject_alt_name(san, &ext_context)?)?;
                    Ok::<_, ErrorStack>(stack)
                })?;

        // Set basic constraints and key usage depending on whether this is a request for a CA
        if params.is_ca {
            let basic_constraints = BasicConstraints::new().ca().critical().build()?;
            extensions.push(basic_constraints)?;

            let key_usage = KeyUsage::new()
                .key_cert_sign()
                .crl_sign()
                .critical()
                .build()?;

            extensions.push(key_usage)?;
        } else {
            let basic_constraints = BasicConstraints::new().critical().build()?;
            extensions.push(basic_constraints)?;
        }

        builder.add_extensions(&extensions)?;

        let public_key = self.signer.signature_key_derive_public(&self.signing_key)?;

        builder.set_pubkey(self.signer.pkey_from_public_key(&public_key)?.deref())?;
        builder.sign_with_ec_signer(&self.signer, &self.signing_key)?;

        Ok(DerCertificateRequest::new(builder.build().to_der()?))
    }
}

/// Returns a signature secret key from a key in DER or PEM format
pub fn signature_secret_key_from_bytes(data: &[u8]) -> Result<SignatureSecretKey, X509Error> {
    let secret_key = if looks_like_der(data) {
        PKey::private_key_from_der(data)
    } else {
        PKey::private_key_from_pem(data)
    }?;

    Ok(SignatureSecretKey::from(
        if let Ok(ec_key) = secret_key.ec_key() {
            ec_key.private_key().to_vec()
        } else {
            secret_key.raw_private_key()?
        },
    ))
}

/// Returns a signing identity from a certificate in DER or PEM format
pub fn signing_identity_from_certificate(certificate: &[u8]) -> Result<SigningIdentity, X509Error> {
    let certificate = if looks_like_der(certificate) {
        X509::from_der(certificate)
    } else {
        X509::from_pem(certificate)
    }?;

    let public_key = pub_key_to_uncompressed(certificate.public_key()?)?.into();

    Ok(SigningIdentity::new(
        CertificateChain::from(vec![certificate.to_der()?]).into_credential(),
        public_key,
    ))
}

/// Returns a X509 identity provider from a root CA certificate in DER or PEM format
pub fn identity_provider_from_certificate(
    certificate: &[u8],
) -> Result<X509IdentityProvider<SubjectIdentityExtractor<X509Reader>, X509Validator>, X509Error> {
    let certificate = if looks_like_der(certificate) {
        X509::from_der(certificate)
    } else {
        X509::from_pem(certificate)
    }?
    .to_der()?;

    Ok(X509IdentityProvider::new(
        SubjectIdentityExtractor::new(0, X509Reader::new()),
        X509Validator::new(vec![certificate.into()])?,
    ))
}

fn looks_like_der(data: &[u8]) -> bool {
    data.starts_with(&[0x30])
}

#[cfg(test)]
pub(crate) mod test_utils {
    use mls_rs_identity_x509::{CertificateChain, DerCertificate};

    pub fn load_test_ca() -> DerCertificate {
        DerCertificate::from(include_bytes!("../test_data/x509/ca.der").to_vec())
    }

    pub fn load_another_ca() -> DerCertificate {
        DerCertificate::from(include_bytes!("../test_data/x509/another_ca.der").to_vec())
    }

    pub fn load_github_leaf() -> DerCertificate {
        DerCertificate::from(include_bytes!("../test_data/x509/github_leaf.der").to_vec())
    }

    pub fn load_ip_cert() -> DerCertificate {
        DerCertificate::from(include_bytes!("../test_data/x509/cert_ip.der").to_vec())
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
    use mls_rs_core::{
        crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey},
        time::MlsTime,
    };
    use mls_rs_identity_x509::{
        CertificateChain, CertificateRequestParameters, DerCertificateRequest, SubjectAltName,
        SubjectComponent, X509CertificateReader, X509RequestWriter,
    };
    use openssl::{
        pkey::PKey,
        x509::{X509Name, X509Req, X509},
    };

    use crate::{
        ec::private_key_to_bytes,
        x509::{
            test_utils::{load_another_ca, load_test_invalid_ca_chain, load_test_invalid_chain},
            CertificateRequestWriter,
        },
    };

    use super::{
        pub_key_to_uncompressed,
        test_utils::{
            load_github_leaf, load_ip_cert, load_test_ca, load_test_cert_chain,
            load_test_system_cert_chain,
        },
        X509Error, X509Reader, X509Validator,
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

        // Some time in late 2022 (almost 53 years since 1970)
        let cert_valid_time =
            MlsTime::from_duration_since_epoch(Duration::from_secs(53 * 365 * 24 * 3600));

        system_validator
            .validate_chain(&chain, Some(cert_valid_time))
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
            Some(MlsTime::from_duration_since_epoch(Duration::from_secs(
                1798761600,
            ))),
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
    fn subject_parser_bytes() {
        let test_cert = load_test_ca();

        let mut expected_name_builder = X509Name::builder().unwrap();

        expected_name_builder
            .append_entry_by_text("CN", "CA")
            .unwrap();

        let expected_name = expected_name_builder.build().to_der().unwrap();

        assert_eq!(
            X509Reader::new().subject_bytes(&test_cert).unwrap(),
            expected_name
        );
    }

    #[test]
    fn subject_parser_components() {
        let test_cert = load_github_leaf();

        let expected = vec![
            SubjectComponent::CountryName(String::from("US")),
            SubjectComponent::State(String::from("California")),
            SubjectComponent::Locality(String::from("San Francisco")),
            SubjectComponent::OrganizationName(String::from("GitHub, Inc.")),
            SubjectComponent::CommonName(String::from("github.com")),
        ];

        assert_eq!(
            X509Reader::new().subject_components(&test_cert).unwrap(),
            expected
        )
    }

    #[test]
    fn subject_alt_names() {
        let test_cert = load_github_leaf();

        let expected = vec![
            SubjectAltName::Dns(String::from("github.com")),
            SubjectAltName::Dns(String::from("www.github.com")),
        ];

        assert_eq!(
            X509Reader::new().subject_alt_names(&test_cert).unwrap(),
            expected
        )
    }

    #[test]
    fn subject_alt_names_ip() {
        let test_cert = load_ip_cert();

        let expected = vec![
            SubjectAltName::Ip(String::from("97.97.97.254")),
            SubjectAltName::Ip(String::from("97.97.97.253")),
        ];

        assert_eq!(
            X509Reader::new().subject_alt_names(&test_cert).unwrap(),
            expected
        )
    }

    fn test_writing_csr(ca: bool) {
        let subject_seckey = if ca {
            include_bytes!("../test_data/x509/root_ca/key.pem")
        } else {
            include_bytes!("../test_data/x509/leaf/key.pem")
        };

        let subject_seckey = ec_key_from_pem(subject_seckey);

        let writer =
            CertificateRequestWriter::new(CipherSuite::CURVE25519_AES128, subject_seckey).unwrap();

        let expected_csr = if ca {
            include_bytes!("../test_data/x509/root_ca/csr.pem").to_vec()
        } else {
            include_bytes!("../test_data/x509/leaf/csr.pem").to_vec()
        };

        let common_name = if ca { "RootCA" } else { "Leaf" };
        let alt_name = if ca { "rootca.org" } else { "leaf.org" };

        let params = CertificateRequestParameters {
            subject: vec![
                SubjectComponent::CommonName(common_name.to_string()),
                SubjectComponent::CountryName("CH".to_string()),
            ],
            subject_alt_names: vec![SubjectAltName::Dns(alt_name.to_string())],
            is_ca: ca,
        };

        let expected_csr = X509Req::from_pem(&expected_csr).unwrap().to_der().unwrap();

        let built_csr = writer.write(params).unwrap();

        assert_eq!(DerCertificateRequest::new(expected_csr), built_csr);
    }

    #[test]
    fn writing_ca_csr() {
        test_writing_csr(true)
    }

    #[test]
    fn writing_csr() {
        test_writing_csr(false)
    }

    fn ec_key_from_pem(pem_bytes: &[u8]) -> SignatureSecretKey {
        let key = PKey::private_key_from_pem(pem_bytes).unwrap();
        private_key_to_bytes(&key).unwrap().into()
    }
}
