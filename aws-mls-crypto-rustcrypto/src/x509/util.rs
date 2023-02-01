use aws_mls_core::crypto::{CipherSuite, CURVE25519_AES128, CURVE25519_CHACHA, P256_AES128};
use aws_mls_identity_x509::{
    CertificateParameters, SubjectAltName as MlsSubjectAltName, SubjectComponent,
};
use sha1::{Digest, Sha1};
use std::{net::IpAddr, str::FromStr};

use spki::{
    der::{
        asn1::PrintableStringRef,
        oid::db::{rfc3280, rfc4519, rfc5912::ECDSA_WITH_SHA_256},
    },
    ObjectIdentifier,
};

use x509_cert::{
    attr::{Attribute, AttributeTypeAndValue, Attributes},
    ext::{
        pkix::{
            name::GeneralName, AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages,
            SubjectKeyIdentifier,
        },
        Extension,
    },
    name::{RdnSequence, RelativeDistinguishedName},
    request::ExtensionReq,
    Certificate,
};

use x509_cert::{
    der::{
        asn1::{Any, Ia5StringRef, OctetStringRef, SetOfVec, Utf8StringRef},
        oid::AssociatedOid,
        AnyRef, Decode, Encode,
    },
    ext::pkix::SubjectAltName,
};

use crate::ec_for_x509::ED25519_OID;

use super::X509Error;

pub(super) fn object_id_for_ciphersuite(
    cipher_suite: CipherSuite,
) -> Result<ObjectIdentifier, X509Error> {
    match cipher_suite {
        P256_AES128 => Ok(ECDSA_WITH_SHA_256),
        CURVE25519_AES128 | CURVE25519_CHACHA => Ok(ED25519_OID),
        _ => Err(X509Error::InvalidSigningKey(cipher_suite)),
    }
}

#[derive(Debug)]
pub(super) struct OwnedAttribute {
    pub(super) oid: ObjectIdentifier,
    pub(super) values: Vec<Any>,
}

impl OwnedAttribute {
    pub(super) fn extension_req(
        extensions: Vec<OwnedExtension>,
    ) -> Result<OwnedAttribute, X509Error> {
        let extensions = extensions.iter().map(From::from).collect();
        let ext_req = ExtensionReq(extensions).to_vec()?;

        Ok(OwnedAttribute {
            oid: ExtensionReq::OID,
            values: vec![Any::from_der(&ext_req)?],
        })
    }
}

impl<'a> TryFrom<&'a OwnedAttribute> for Attributes<'a> {
    type Error = X509Error;

    fn try_from(owned: &'a OwnedAttribute) -> Result<Self, X509Error> {
        let values = SetOfVec::try_from(owned.values.iter().map(AnyRef::from).collect::<Vec<_>>())?;

        Ok(Attributes::try_from([Attribute {
            oid: owned.oid,
            values,
        }])?)
    }
}

#[derive(Debug)]
pub(super) struct OwnedExtension {
    extn_id: ObjectIdentifier,
    critical: bool,
    extn_value: Vec<u8>,
}

impl OwnedExtension {
    pub(super) fn subject_alt_name(name: &MlsSubjectAltName) -> Result<OwnedExtension, X509Error> {
        let subject_alt_name = match name {
            MlsSubjectAltName::Uri(n) => vec![GeneralName::UniformResourceIdentifier(
                Ia5StringRef::new(n)?,
            )]
            .to_vec()?,
            MlsSubjectAltName::Dns(d) => {
                vec![GeneralName::DnsName(Ia5StringRef::new(d)?)].to_vec()?
            }
            MlsSubjectAltName::Rid(r) => {
                vec![GeneralName::RegisteredId(ObjectIdentifier::new(r)?)].to_vec()?
            }
            // When the subjectAltName extension contains an Internet mail address,
            // the address MUST be stored in the rfc822Name.
            MlsSubjectAltName::Email(e) => {
                vec![GeneralName::Rfc822Name(Ia5StringRef::new(e)?)].to_vec()?
            }
            MlsSubjectAltName::Ip(i) => match IpAddr::from_str(i)? {
                IpAddr::V4(ip) => {
                    vec![GeneralName::IpAddress(OctetStringRef::new(&ip.octets())?)].to_vec()?
                }
                IpAddr::V6(ip) => {
                    vec![GeneralName::IpAddress(OctetStringRef::new(&ip.octets())?)].to_vec()?
                }
            },
            _ => return Err(X509Error::UnsupportedSubjectAltName(name.clone())),
        };

        Ok(OwnedExtension {
            extn_id: SubjectAltName::OID,
            critical: false,
            extn_value: subject_alt_name,
        })
    }

    pub(super) fn basic_constraints(is_ca: bool) -> Result<OwnedExtension, X509Error> {
        let basic_constraints = BasicConstraints {
            ca: is_ca,
            path_len_constraint: None,
        };

        Ok(OwnedExtension {
            extn_id: BasicConstraints::OID,
            critical: true,
            extn_value: basic_constraints.to_vec()?,
        })
    }

    pub(super) fn subject_key_id(subject_pubkey: &[u8]) -> Result<OwnedExtension, X509Error> {
        let key_identifier = Sha1::digest(subject_pubkey).to_vec();

        Ok(OwnedExtension {
            extn_id: SubjectKeyIdentifier::OID,
            critical: false,
            extn_value: SubjectKeyIdentifier(OctetStringRef::new(&key_identifier)?).to_vec()?,
        })
    }

    pub(super) fn ca_key_usage() -> Result<OwnedExtension, X509Error> {
        Ok(OwnedExtension {
            extn_id: KeyUsage::OID,
            critical: true,
            extn_value: KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign).to_vec()?,
        })
    }

    pub(super) fn authority_key_id(issuer: &Certificate) -> Result<OwnedExtension, X509Error> {
        let issuer_pubkey = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key;

        let key_identifier = Sha1::digest(issuer_pubkey).to_vec();

        let issuer_serial = issuer.tbs_certificate.serial_number;
        let issuer_name = GeneralName::DirectoryName(issuer.tbs_certificate.subject.clone());

        let extn_value = AuthorityKeyIdentifier {
            key_identifier: Some(OctetStringRef::new(&key_identifier)?),
            authority_cert_issuer: Some(vec![issuer_name]),
            authority_cert_serial_number: Some(issuer_serial),
        };

        Ok(OwnedExtension {
            extn_id: AuthorityKeyIdentifier::OID,
            critical: false,
            extn_value: extn_value.to_vec()?,
        })
    }
}

impl<'a> From<&'a OwnedExtension> for Extension<'a> {
    fn from(ext: &'a OwnedExtension) -> Self {
        Extension {
            extn_id: ext.extn_id,
            critical: ext.critical,
            extn_value: &ext.extn_value,
        }
    }
}

impl<'a> PartialEq<Extension<'a>> for OwnedExtension {
    fn eq(&self, other: &Extension<'a>) -> bool {
        self.extn_id == other.extn_id
            && self.critical == other.critical
            && self.extn_value == other.extn_value
    }
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
                SubjectComponent::CountryName(_) => AnyRef::from(PrintableStringRef::new(v)?),
                SubjectComponent::DomainComponent(_) => AnyRef::from(Ia5StringRef::new(v)?),
                _ => AnyRef::from(Utf8StringRef::new(v)?),
            };

            Ok(RelativeDistinguishedName::from(SetOfVec::try_from(vec![
                AttributeTypeAndValue { oid, value },
            ])?))
        })
        .collect::<Result<Vec<_>, X509Error>>()?;

    Ok(attributes.into())
}

pub(super) fn common_extensions(
    subject_params: &CertificateParameters,
) -> Result<Vec<OwnedExtension>, X509Error> {
    let mut extensions =
        subject_params
            .subject_alt_names
            .iter()
            .try_fold(Vec::new(), |mut alt_names, name| {
                alt_names.push(OwnedExtension::subject_alt_name(name)?);
                Ok::<_, X509Error>(alt_names)
            })?;

    extensions.push(OwnedExtension::basic_constraints(subject_params.is_ca)?);

    if subject_params.is_ca {
        extensions.push(OwnedExtension::ca_key_usage()?);
    }

    Ok(extensions)
}
