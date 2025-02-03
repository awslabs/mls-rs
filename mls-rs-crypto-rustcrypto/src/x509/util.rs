// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::crypto::CipherSuite;
use mls_rs_identity_x509::{
    CertificateRequestParameters, SubjectAltName as MlsSubjectAltName, SubjectComponent,
};
use std::{net::IpAddr, str::FromStr};

use spki::{
    der::{
        asn1::{Ia5String, OctetString, PrintableString, PrintableStringRef},
        oid::db::{rfc3280, rfc4519, rfc5912::ECDSA_WITH_SHA_256},
        Tag, Tagged,
    },
    ObjectIdentifier,
};

use x509_cert::{
    attr::{Attribute, AttributeTypeAndValue},
    ext::{
        pkix::{
            name::{GeneralName, GeneralNames},
            BasicConstraints, KeyUsage, KeyUsages,
        },
        Extension,
    },
    name::{RdnSequence, RelativeDistinguishedName},
    request::ExtensionReq,
};

use x509_cert::{
    der::{
        asn1::{Any, Ia5StringRef, SetOfVec, Utf8StringRef},
        oid::AssociatedOid,
        Decode, Encode,
    },
    ext::pkix::SubjectAltName,
};

use crate::ec_for_x509::ED25519_OID;

use super::X509Error;

pub(super) fn object_id_for_ciphersuite(
    cipher_suite: CipherSuite,
) -> Result<ObjectIdentifier, X509Error> {
    match cipher_suite {
        CipherSuite::P256_AES128 => Ok(ECDSA_WITH_SHA_256),
        CipherSuite::CURVE25519_AES128 | CipherSuite::CURVE25519_CHACHA => Ok(ED25519_OID),
        _ => Err(X509Error::InvalidSigningKey(cipher_suite)),
    }
}

pub(super) fn extension_req(extensions: Vec<Extension>) -> Result<Attribute, X509Error> {
    let ext_req = ExtensionReq(extensions).to_der()?;

    Ok(Attribute {
        oid: ExtensionReq::OID,
        values: SetOfVec::try_from(vec![Any::from_der(&ext_req)?])?,
    })
}

pub(super) fn subject_alt_name(name: &MlsSubjectAltName) -> Result<Extension, X509Error> {
    let subject_alt_name = match name {
        MlsSubjectAltName::Uri(n) => {
            vec![GeneralName::UniformResourceIdentifier(Ia5String::new(n)?)].to_der()?
        }
        MlsSubjectAltName::Dns(d) => vec![GeneralName::DnsName(Ia5String::new(d)?)].to_der()?,
        MlsSubjectAltName::Rid(r) => {
            vec![GeneralName::RegisteredId(ObjectIdentifier::new(r)?)].to_der()?
        }
        // When the subjectAltName extension contains an Internet mail address,
        // the address MUST be stored in the rfc822Name.
        MlsSubjectAltName::Email(e) => {
            vec![GeneralName::Rfc822Name(Ia5String::new(e)?)].to_der()?
        }
        MlsSubjectAltName::Ip(i) => match IpAddr::from_str(i)? {
            IpAddr::V4(ip) => {
                vec![GeneralName::IpAddress(OctetString::new(ip.octets())?)].to_der()?
            }
            IpAddr::V6(ip) => {
                vec![GeneralName::IpAddress(OctetString::new(ip.octets())?)].to_der()?
            }
        },
    };

    Ok(Extension {
        extn_id: SubjectAltName::OID,
        critical: false,
        extn_value: OctetString::new(subject_alt_name)?,
    })
}

pub(super) fn basic_constraints(is_ca: bool) -> Result<Extension, X509Error> {
    let basic_constraints = BasicConstraints {
        ca: is_ca,
        path_len_constraint: None,
    };

    Ok(Extension {
        extn_id: BasicConstraints::OID,
        critical: true,
        extn_value: OctetString::new(basic_constraints.to_der()?)?,
    })
}

pub(super) fn ca_key_usage() -> Result<Extension, X509Error> {
    Ok(Extension {
        extn_id: KeyUsage::OID,
        critical: true,
        extn_value: OctetString::new(
            KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign).to_der()?,
        )?,
    })
}

pub fn general_names_to_alt_names(
    names: &GeneralNames,
) -> Result<Vec<MlsSubjectAltName>, X509Error> {
    names
        .iter()
        .map(|name| match name {
            GeneralName::UniformResourceIdentifier(u) => Ok(MlsSubjectAltName::Uri(u.to_string())),
            GeneralName::DnsName(d) => Ok(MlsSubjectAltName::Dns(d.to_string())),
            GeneralName::RegisteredId(r) => Ok(MlsSubjectAltName::Rid(r.to_string())),
            GeneralName::Rfc822Name(e) => Ok(MlsSubjectAltName::Email(e.to_string())),
            GeneralName::IpAddress(i) => match i.as_bytes().len() {
                4 => {
                    let octets: [u8; 4] = i.as_bytes().try_into().unwrap();
                    Ok(MlsSubjectAltName::Ip(IpAddr::from(octets).to_string()))
                }
                16 => {
                    let octets: [u8; 16] = i.as_bytes().try_into().unwrap();
                    Ok(MlsSubjectAltName::Ip(IpAddr::from(octets).to_string()))
                }
                _ => Err(X509Error::IncorrectIpOctets(i.as_bytes().len())),
            },
            _ => Err(X509Error::CannotParseAltName(format!("{name:?}"))),
        })
        .collect()
}

pub(crate) fn build_x509_name(components: &[SubjectComponent]) -> Result<RdnSequence, X509Error> {
    let attributes = components
        .iter()
        .map(|c| {
            let (oid, v) = match c {
                SubjectComponent::CommonName(cn) => (rfc4519::COMMON_NAME, cn),
                SubjectComponent::Surname(s) => (rfc4519::SURNAME, s),
                SubjectComponent::SerialNumber(s) => (rfc4519::SERIAL_NUMBER, s),
                SubjectComponent::CountryName(c) => (rfc4519::COUNTRY_NAME, c),
                SubjectComponent::Locality(l) => (rfc4519::LOCALITY_NAME, l),
                SubjectComponent::State(s) => (rfc4519::ST, s),
                SubjectComponent::StreetAddress(a) => (rfc4519::STREET, a),
                SubjectComponent::OrganizationName(on) => (rfc4519::ORGANIZATION_NAME, on),
                SubjectComponent::OrganizationalUnit(ou) => (rfc4519::ORGANIZATIONAL_UNIT, ou),
                SubjectComponent::Title(t) => (rfc4519::TITLE, t),
                SubjectComponent::GivenName(gn) => (rfc4519::GIVEN_NAME, gn),
                SubjectComponent::UserId(u) => (rfc4519::USER_ID, u),
                SubjectComponent::DomainComponent(dc) => (rfc4519::DOMAIN_COMPONENT, dc),
                SubjectComponent::Initials(i) => (rfc4519::INITIALS, i),
                SubjectComponent::GenerationQualifier(gq) => (rfc4519::GENERATION_QUALIFIER, gq),
                SubjectComponent::DistinguishedNameQualifier(dnq) => {
                    (rfc4519::DISTINGUISHED_NAME, dnq)
                }
                SubjectComponent::EmailAddress(e) => (rfc3280::EMAIL, e),
                SubjectComponent::Pseudonym(p) => (rfc3280::PSEUDONYM, p),
            };

            let value = match c {
                SubjectComponent::CountryName(_) => Any::from(PrintableStringRef::new(v)?),
                SubjectComponent::DomainComponent(_) => Any::from(Ia5StringRef::new(v)?),
                _ => Any::from(Utf8StringRef::new(v)?),
            };

            Ok(RelativeDistinguishedName::from(SetOfVec::try_from(vec![
                AttributeTypeAndValue { oid, value },
            ])?))
        })
        .collect::<Result<Vec<_>, X509Error>>()?;

    Ok(attributes.into())
}

pub(super) fn parse_x509_name(rdns: &RdnSequence) -> Result<Vec<SubjectComponent>, X509Error> {
    rdns.0
        .iter()
        .map(|rdn| {
            let type_and_value = rdn.0.get(0).unwrap();

            let value = match type_and_value.value.tag() {
                Tag::PrintableString => {
                    PrintableString::new(&type_and_value.value.value())?.to_string()
                }
                Tag::Ia5String => Ia5String::new(&type_and_value.value.value())?.to_string(),
                Tag::Utf8String => Utf8StringRef::new(type_and_value.value.value())?.to_string(),
                _ => {
                    return Err(X509Error::UnexpectedComponentType(
                        type_and_value.value.tag(),
                    ))
                }
            };

            match type_and_value.oid {
                rfc4519::COMMON_NAME => Ok(SubjectComponent::CommonName(value)),
                rfc4519::SURNAME => Ok(SubjectComponent::Surname(value)),
                rfc4519::COUNTRY_NAME => Ok(SubjectComponent::CountryName(value)),
                rfc4519::LOCALITY_NAME => Ok(SubjectComponent::Locality(value)),
                rfc4519::ST => Ok(SubjectComponent::State(value)),
                rfc4519::STREET => Ok(SubjectComponent::StreetAddress(value)),
                rfc4519::ORGANIZATION_NAME => Ok(SubjectComponent::OrganizationName(value)),
                rfc4519::ORGANIZATIONAL_UNIT => Ok(SubjectComponent::OrganizationalUnit(value)),
                rfc4519::TITLE => Ok(SubjectComponent::Title(value)),
                rfc4519::GIVEN_NAME => Ok(SubjectComponent::GivenName(value)),
                rfc4519::USER_ID => Ok(SubjectComponent::UserId(value)),
                rfc4519::DOMAIN_COMPONENT => Ok(SubjectComponent::DomainComponent(value)),
                rfc4519::INITIALS => Ok(SubjectComponent::Initials(value)),
                rfc4519::GENERATION_QUALIFIER => Ok(SubjectComponent::GenerationQualifier(value)),
                rfc4519::DISTINGUISHED_NAME => {
                    Ok(SubjectComponent::DistinguishedNameQualifier(value))
                }
                rfc3280::EMAIL => Ok(SubjectComponent::EmailAddress(value)),
                rfc3280::PSEUDONYM => Ok(SubjectComponent::Pseudonym(value)),
                rfc4519::SERIAL_NUMBER => Ok(SubjectComponent::SerialNumber(value)),
                _ => Err(X509Error::UnsupportedSubjectComponentOid(
                    type_and_value.oid,
                )),
            }
        })
        .collect()
}

pub(super) fn request_extensions(
    subject_params: &CertificateRequestParameters,
) -> Result<Vec<Extension>, X509Error> {
    let mut extensions =
        subject_params
            .subject_alt_names
            .iter()
            .try_fold(Vec::new(), |mut alt_names, name| {
                alt_names.push(subject_alt_name(name)?);
                Ok::<_, X509Error>(alt_names)
            })?;

    extensions.push(basic_constraints(subject_params.is_ca)?);

    if subject_params.is_ca {
        extensions.push(ca_key_usage()?);
    }

    Ok(extensions)
}

#[cfg(test)]
pub(crate) mod test_utils {
    use mls_rs_identity_x509::{CertificateChain, DerCertificate};

    pub fn load_test_ca() -> DerCertificate {
        DerCertificate::from(include_bytes!("../../test_data/x509/ca.der").to_vec())
    }

    pub fn load_test_p384_ca() -> DerCertificate {
        DerCertificate::from(include_bytes!("../../test_data/x509/p384_ca.der").to_vec())
    }

    pub fn load_test_cert_chain() -> CertificateChain {
        let entry0 = include_bytes!("../../test_data/x509/leaf.der").to_vec();
        let entry1 = include_bytes!("../../test_data/x509/intermediate.der").to_vec();
        let entry2 = include_bytes!("../../test_data/x509/ca.der").to_vec();

        CertificateChain::from_iter(
            [entry0, entry1, entry2]
                .into_iter()
                .map(DerCertificate::from),
        )
    }

    pub fn load_test_invalid_chain() -> CertificateChain {
        let entry0 = include_bytes!("../../test_data/x509/leaf.der").to_vec();
        let entry1 = include_bytes!("../../test_data/x509/ca.der").to_vec();

        CertificateChain::from_iter([entry0, entry1].into_iter().map(DerCertificate::from))
    }

    pub fn load_test_invalid_ca_chain() -> CertificateChain {
        let entry0 = include_bytes!("../../test_data/x509/leaf.der").to_vec();
        let entry1 = include_bytes!("../../test_data/x509/intermediate.der").to_vec();
        let entry2 = include_bytes!("../../test_data/x509/another_ca.der").to_vec();

        CertificateChain::from_iter(
            [entry0, entry1, entry2]
                .into_iter()
                .map(DerCertificate::from),
        )
    }

    pub fn load_another_ca() -> DerCertificate {
        DerCertificate::from(include_bytes!("../../test_data/x509/another_ca.der").to_vec())
    }

    pub fn load_github_leaf() -> DerCertificate {
        DerCertificate::from(include_bytes!("../../test_data/x509/github_leaf.der").to_vec())
    }

    pub fn load_ip_cert() -> DerCertificate {
        DerCertificate::from(include_bytes!("../../test_data/x509/cert_ip.der").to_vec())
    }
}
