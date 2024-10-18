// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use core::slice;
use std::{
    ffi::{c_int, c_void, CString},
    marker::PhantomData,
    net::IpAddr,
    ptr::null_mut,
};

#[cfg(feature = "fips")]
use crate::aws_lc_sys_impl::{
    sk_free as OPENSSL_sk_free, sk_new_null as OPENSSL_sk_new_null, sk_pop as OPENSSL_sk_pop,
    sk_push as OPENSSL_sk_push,
};

#[cfg(not(feature = "fips"))]
use crate::aws_lc_sys_impl::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_pop, OPENSSL_sk_push,
};

use crate::aws_lc_sys_impl::{
    stack_st, ASN1_STRING_data, ASN1_STRING_free, ASN1_STRING_get0_data, ASN1_STRING_length,
    ASN1_STRING_set, ASN1_STRING_type_new, BIO_free, BIO_new, BIO_number_written, BIO_read,
    BIO_s_mem, GENERAL_NAME_free, GENERAL_NAME_get0_value, GENERAL_NAME_new,
    GENERAL_NAME_set0_value, NID_authority_key_identifier, NID_basic_constraints, NID_commonName,
    NID_countryName, NID_distinguishedName, NID_domainComponent, NID_generationQualifier,
    NID_givenName, NID_initials, NID_key_usage, NID_localityName, NID_organizationName,
    NID_organizationalUnitName, NID_pkcs9_emailAddress, NID_pseudonym, NID_serialNumber,
    NID_stateOrProvinceName, NID_streetAddress, NID_subject_alt_name, NID_subject_key_identifier,
    NID_surname, NID_title, NID_userId, OBJ_obj2nid, X509V3_EXT_conf_nid, X509V3_EXT_i2d,
    X509V3_EXT_print, X509_EXTENSION_free, X509_NAME_ENTRY_get_data, X509_NAME_ENTRY_get_object,
    X509_NAME_add_entry_by_NID, X509_NAME_entry_count, X509_NAME_free, X509_NAME_get_entry,
    X509_NAME_new, X509_name_st, ASN1_STRING, GENERAL_NAME, GEN_DNS, GEN_EMAIL, GEN_IPADD, GEN_RID,
    GEN_URI, MBSTRING_UTF8, V_ASN1_IA5STRING, V_ASN1_OCTET_STRING, X509V3_CTX, X509_EXTENSION,
    X509_NAME,
};
use mls_rs_identity_x509::{SubjectAltName, SubjectComponent};

use crate::{check_int_return, check_non_null, check_non_null_const, check_res, AwsLcCryptoError};

use super::Certificate;

pub struct X509Name(pub(crate) *mut X509_name_st);

impl X509Name {
    pub fn new() -> Result<Self, AwsLcCryptoError> {
        unsafe { check_non_null(X509_NAME_new()).map(Self) }
    }

    pub fn add_entry(&mut self, component: &SubjectComponent) -> Result<(), AwsLcCryptoError> {
        let (nid, v) = match component {
            SubjectComponent::CommonName(cn) => (NID_commonName, cn),
            SubjectComponent::Surname(s) => (NID_surname, s),
            SubjectComponent::SerialNumber(s) => (NID_serialNumber, s),
            SubjectComponent::CountryName(c) => (NID_countryName, c),
            SubjectComponent::Locality(l) => (NID_localityName, l),
            SubjectComponent::State(s) => (NID_stateOrProvinceName, s),
            SubjectComponent::StreetAddress(a) => (NID_streetAddress, a),
            SubjectComponent::OrganizationName(on) => (NID_organizationName, on),
            SubjectComponent::OrganizationalUnit(ou) => (NID_organizationalUnitName, ou),
            SubjectComponent::Title(t) => (NID_title, t),
            SubjectComponent::GivenName(gn) => (NID_givenName, gn),
            SubjectComponent::EmailAddress(e) => (NID_pkcs9_emailAddress, e),
            SubjectComponent::UserId(u) => (NID_userId, u),
            SubjectComponent::DomainComponent(dc) => (NID_domainComponent, dc),
            SubjectComponent::Initials(i) => (NID_initials, i),
            SubjectComponent::GenerationQualifier(gq) => (NID_generationQualifier, gq),
            SubjectComponent::DistinguishedNameQualifier(dnq) => (NID_distinguishedName, dnq),
            SubjectComponent::Pseudonym(p) => (NID_pseudonym, p),
        };

        unsafe {
            check_res(X509_NAME_add_entry_by_NID(
                self.0,
                nid,
                MBSTRING_UTF8,
                v.as_ptr() as *mut _,
                v.len()
                    .try_into()
                    .map_err(|_| AwsLcCryptoError::CryptoError)?,
                -1,
                0,
            ))
        }
    }

    pub fn new_components(components: &[SubjectComponent]) -> Result<Self, AwsLcCryptoError> {
        components
            .iter()
            .try_fold(X509Name::new()?, |mut name, component| {
                name.add_entry(component)?;
                Ok(name)
            })
    }

    #[cfg(test)]
    pub fn to_der(&self) -> Result<Vec<u8>, AwsLcCryptoError> {
        use crate::aws_lc_sys_impl::i2d_X509_NAME;

        unsafe {
            let len = check_int_return(i2d_X509_NAME(self.0, null_mut()))?;
            let mut out = vec![0u8; len as usize];
            check_res(i2d_X509_NAME(self.0, &mut out.as_mut_ptr()))?;

            Ok(out)
        }
    }
}

impl Drop for X509Name {
    fn drop(&mut self) {
        unsafe { X509_NAME_free(self.0) }
    }
}

struct Asn1String(*mut ASN1_STRING);

impl Asn1String {
    pub fn new(string_type: i32) -> Result<Self, AwsLcCryptoError> {
        unsafe { check_non_null(ASN1_STRING_type_new(string_type)).map(Self) }
    }

    pub fn new_value(string_type: i32, value: &[u8]) -> Result<Self, AwsLcCryptoError> {
        let mut new_val = Self::new(string_type)?;
        new_val.set_value(value)?;

        Ok(new_val)
    }

    pub fn set_value(&mut self, value: &[u8]) -> Result<(), AwsLcCryptoError> {
        unsafe {
            check_res(ASN1_STRING_set(
                self.0,
                value.as_ptr() as *const c_void,
                value
                    .len()
                    .try_into()
                    .map_err(|_| AwsLcCryptoError::CryptoError)?,
            ))
        }
    }
}

impl From<Asn1String> for *mut c_void {
    fn from(val: Asn1String) -> Self {
        let inner = val.0 as *mut c_void;

        core::mem::forget(val);
        inner
    }
}

impl Drop for Asn1String {
    fn drop(&mut self) {
        unsafe { ASN1_STRING_free(self.0) }
    }
}

pub(super) struct GeneralName(*mut GENERAL_NAME);

impl GeneralName {
    unsafe fn new() -> Result<Self, AwsLcCryptoError> {
        check_non_null(GENERAL_NAME_new()).map(Self)
    }

    fn new_value<T: Into<*mut c_void>>(name_type: i32, value: T) -> Result<Self, AwsLcCryptoError> {
        unsafe {
            let name = Self::new()?;

            GENERAL_NAME_set0_value(name.0, name_type, value.into());

            Ok(name)
        }
    }

    pub fn subject_alt_name(&self) -> Result<SubjectAltName, AwsLcCryptoError> {
        unsafe {
            let mut name_type = c_int::default();

            let value = check_non_null(GENERAL_NAME_get0_value(self.0, &mut name_type))?;

            match name_type {
                GEN_EMAIL => Ok(SubjectAltName::Email(asn1_to_string(value.cast())?)),
                GEN_URI => Ok(SubjectAltName::Uri(asn1_to_string(value.cast())?)),
                GEN_DNS => Ok(SubjectAltName::Dns(asn1_to_string(value.cast())?)),
                // Rid is currently not supported
                GEN_RID => Err(AwsLcCryptoError::CryptoError),
                GEN_IPADD => Ok(SubjectAltName::Ip(asn1_to_ip(value.cast())?)),
                _ => Err(AwsLcCryptoError::CryptoError),
            }
        }
    }

    pub fn email(addr: &str) -> Result<Self, AwsLcCryptoError> {
        Self::new_value(
            GEN_EMAIL,
            Asn1String::new_value(V_ASN1_IA5STRING, addr.as_bytes())?,
        )
    }

    pub fn uri(uri: &str) -> Result<Self, AwsLcCryptoError> {
        Self::new_value(
            GEN_URI,
            Asn1String::new_value(V_ASN1_IA5STRING, uri.as_bytes())?,
        )
    }

    pub fn dns(dns: &str) -> Result<Self, AwsLcCryptoError> {
        Self::new_value(
            GEN_DNS,
            Asn1String::new_value(V_ASN1_IA5STRING, dns.as_bytes())?,
        )
    }

    pub fn ip(ip: &str) -> Result<Self, AwsLcCryptoError> {
        let ip = ip
            .parse::<IpAddr>()
            .map_err(|_| AwsLcCryptoError::CryptoError)?;

        let data = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        Self::new_value(
            GEN_IPADD,
            Asn1String::new_value(V_ASN1_OCTET_STRING, &data)?,
        )
    }
}

impl Drop for GeneralName {
    fn drop(&mut self) {
        unsafe { GENERAL_NAME_free(self.0) }
    }
}

unsafe impl StackItem for GeneralName {
    fn from_raw_pointer(ptr: *mut c_void) -> Self {
        GeneralName(ptr.cast())
    }

    fn into_raw_pointer(self) -> *mut c_void {
        let inner = self.0;
        core::mem::forget(self);
        inner.cast()
    }
}

/// # Safety
///
/// A stack can only hold raw C pointers and does not manage
/// memory for the items it holds.
pub unsafe trait StackItem {
    fn from_raw_pointer(ptr: *mut c_void) -> Self;
    fn into_raw_pointer(self) -> *mut c_void;
}

pub struct Stack<T>
where
    T: StackItem,
{
    pub(crate) inner: *mut stack_st,
    phantom: PhantomData<T>,
}

impl<T> Stack<T>
where
    T: StackItem,
{
    pub fn new() -> Result<Self, AwsLcCryptoError> {
        unsafe {
            check_non_null(OPENSSL_sk_new_null()).map(|v| Self {
                inner: v,
                phantom: Default::default(),
            })
        }
    }

    pub unsafe fn from_raw_pointer(ptr: *mut stack_st) -> Self {
        Self {
            inner: ptr,
            phantom: Default::default(),
        }
    }

    pub fn push(&mut self, val: T) {
        unsafe {
            OPENSSL_sk_push(self.inner, val.into_raw_pointer());
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        unsafe {
            let val = OPENSSL_sk_pop(self.inner);

            if val.is_null() {
                return None;
            }

            Some(T::from_raw_pointer(val))
        }
    }

    pub fn into_vec(mut self) -> Vec<T> {
        let mut res = Vec::new();

        while let Some(item) = self.pop() {
            res.push(item)
        }

        res
    }

    pub fn as_ptr(&self) -> *mut stack_st {
        self.inner
    }
}

impl<T> Drop for Stack<T>
where
    T: StackItem,
{
    fn drop(&mut self) {
        unsafe {
            loop {
                let val = OPENSSL_sk_pop(self.inner);

                if val.is_null() {
                    break;
                }

                let _ = T::from_raw_pointer(val);
            }

            OPENSSL_sk_free(self.inner)
        }
    }
}

pub enum KeyUsage {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

impl KeyUsage {
    pub fn as_str(&self) -> &str {
        match self {
            KeyUsage::DigitalSignature => "digitalSignature",
            KeyUsage::NonRepudiation => "nonRepudiation",
            KeyUsage::KeyEncipherment => "keyEncipherment",
            KeyUsage::DataEncipherment => "dataEncipherment",
            KeyUsage::KeyAgreement => "keyAgreement",
            KeyUsage::KeyCertSign => "keyCertSign",
            KeyUsage::CrlSign => "cRLSign",
            KeyUsage::EncipherOnly => "encipherOnly",
            KeyUsage::DecipherOnly => "decipherOnly",
        }
    }
}

pub struct X509ExtensionContext<'a> {
    pub(crate) inner: X509V3_CTX,
    pub(crate) phantom: PhantomData<&'a Certificate>,
}

impl<'a> X509ExtensionContext<'a> {
    pub fn as_mut_ptr(&mut self) -> *mut X509V3_CTX {
        &mut self.inner
    }
}

#[derive(Debug)]
pub struct X509Extension(pub(crate) *mut X509_EXTENSION);

impl X509Extension {
    pub fn subject_alt_name(alt_names: &[SubjectAltName]) -> Result<Self, AwsLcCryptoError> {
        let stack = alt_names
            .iter()
            .try_fold(Stack::new()?, |mut names, name| {
                let general_name = match name {
                    SubjectAltName::Email(email) => GeneralName::email(email),
                    SubjectAltName::Uri(uri) => GeneralName::uri(uri),
                    SubjectAltName::Dns(dns) => GeneralName::dns(dns),
                    // Rid is currently unsupported
                    SubjectAltName::Rid(_) => Err(AwsLcCryptoError::CryptoError),
                    SubjectAltName::Ip(ip) => GeneralName::ip(ip),
                }?;

                names.push(general_name);

                Ok::<_, AwsLcCryptoError>(names)
            })?;

        unsafe {
            check_non_null(X509V3_EXT_i2d(NID_subject_alt_name, 0, stack.inner.cast())).map(Self)
        }
    }

    pub fn basic_constraints(
        critical: bool,
        ca: bool,
        path_len: Option<u32>,
    ) -> Result<Self, AwsLcCryptoError> {
        let mut basic_constraints = String::new();

        if critical {
            basic_constraints.push_str("critical,");
        }

        if ca {
            basic_constraints.push_str("CA:TRUE");
        } else {
            basic_constraints.push_str("CA:FALSE");
        }

        if let Some(path_len) = path_len {
            basic_constraints.push_str(format!(",pathlen{}", path_len).as_str());
        }

        string_to_ext(basic_constraints, NID_basic_constraints, None)
    }

    pub fn key_usage(critical: bool, usages: &[KeyUsage]) -> Result<Self, AwsLcCryptoError> {
        let mut key_usage = String::new();

        if critical {
            key_usage.push_str("critical");
        }

        usages.iter().for_each(|usage| {
            if !key_usage.is_empty() {
                key_usage.push(',');
            }

            key_usage.push_str(usage.as_str());
        });

        string_to_ext(key_usage, NID_key_usage, None)
    }

    pub fn authority_key_identifier(
        context: &mut X509ExtensionContext,
        critical: bool,
        key_id: bool,
        issuer: bool,
    ) -> Result<Self, AwsLcCryptoError> {
        let mut auth_key_id = String::new();

        if critical {
            auth_key_id.push_str("critical,");
        }

        if key_id {
            auth_key_id.push_str("keyid:always,");
        } else {
            auth_key_id.push_str("keyid,");
        }

        if issuer {
            auth_key_id.push_str("issuer:always");
        } else {
            auth_key_id.push_str("issuer");
        }

        string_to_ext(auth_key_id, NID_authority_key_identifier, Some(context))
    }

    pub fn subject_key_identifier(
        context: &mut X509ExtensionContext,
        critical: bool,
    ) -> Result<Self, AwsLcCryptoError> {
        let mut subject_key_id = String::new();

        if critical {
            subject_key_id.push_str("critical,");
        }

        subject_key_id.push_str("hash");

        string_to_ext(subject_key_id, NID_subject_key_identifier, Some(context))
    }

    pub fn to_string(&self) -> Result<String, AwsLcCryptoError> {
        unsafe {
            let bio_out = check_non_null(BIO_new(BIO_s_mem()))?;

            if 1 != X509V3_EXT_print(bio_out, self.0, 0, 0) {
                BIO_free(bio_out);
                return Err(AwsLcCryptoError::CryptoError);
            }

            #[cfg(feature = "fips")]
            let out_len = BIO_number_written(bio_out);

            #[cfg(not(feature = "fips"))]
            let out_len = match BIO_number_written(bio_out).try_into() {
                Ok(out_len) => out_len,
                Err(e) => {
                    BIO_free(bio_out);
                    return Err(AwsLcCryptoError::from(e));
                }
            };

            let mut out_buffer = vec![0u8; out_len];

            let res = BIO_read(
                bio_out,
                out_buffer.as_mut_ptr().cast(),
                BIO_number_written(bio_out) as c_int,
            );

            BIO_free(bio_out);
            check_res(res)?;

            String::from_utf8(out_buffer).map_err(|_| AwsLcCryptoError::CryptoError)
        }
    }
}

impl PartialEq for X509Extension {
    fn eq(&self, other: &Self) -> bool {
        self.to_string().ok() == other.to_string().ok()
    }
}

unsafe impl StackItem for X509Extension {
    fn from_raw_pointer(ptr: *mut c_void) -> Self {
        X509Extension(ptr.cast())
    }

    fn into_raw_pointer(self) -> *mut c_void {
        let inner = self.0;
        core::mem::forget(self);
        inner.cast()
    }
}

impl Drop for X509Extension {
    fn drop(&mut self) {
        unsafe { X509_EXTENSION_free(self.0) }
    }
}

fn string_to_ext(
    string: String,
    nid: i32,
    context: Option<&mut X509ExtensionContext>,
) -> Result<X509Extension, AwsLcCryptoError> {
    let c_string = CString::new(string).map_err(|_| AwsLcCryptoError::CryptoError)?;

    unsafe {
        check_non_null(X509V3_EXT_conf_nid(
            null_mut(),
            context.map_or_else(null_mut, |v| v.as_mut_ptr()),
            nid,
            c_string.as_ptr(),
        ))
        .map(X509Extension)
    }
}

unsafe fn asn1_to_string(value: *mut ASN1_STRING) -> Result<String, AwsLcCryptoError> {
    unsafe {
        let ptr = check_non_null_const(ASN1_STRING_get0_data(value))?;
        let len = check_int_return(ASN1_STRING_length(value))?;

        let slice = slice::from_raw_parts(ptr, len as usize);

        String::from_utf8(slice.to_vec()).map_err(|_| AwsLcCryptoError::CryptoError)
    }
}

unsafe fn asn1_to_ip(value: *mut ASN1_STRING) -> Result<String, AwsLcCryptoError> {
    unsafe {
        let ptr = check_non_null_const(ASN1_STRING_get0_data(value))?;
        let len = check_int_return(ASN1_STRING_length(value))?;

        let slice = slice::from_raw_parts(ptr, len as usize);

        match len {
            4 => {
                let octets: [u8; 4] = slice.try_into().unwrap();
                Ok(IpAddr::from(octets).to_string())
            }
            16 => {
                let octets: [u8; 16] = slice.try_into().unwrap();
                Ok(IpAddr::from(octets).to_string())
            }
            _ => Err(AwsLcCryptoError::CryptoError),
        }
    }
}

#[allow(non_upper_case_globals)]
pub(super) unsafe fn components_from_name(
    name: *mut X509_NAME,
) -> Result<Vec<SubjectComponent>, AwsLcCryptoError> {
    (0..X509_NAME_entry_count(name)).try_fold(Vec::new(), |mut components, i| {
        let entry = check_non_null(X509_NAME_get_entry(name, i))?;
        let nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry));

        let entry = check_non_null(X509_NAME_ENTRY_get_data(entry))?;

        let len = check_int_return(ASN1_STRING_length(entry))?;
        let data = check_non_null(ASN1_STRING_data(entry))?;

        let slice = core::slice::from_raw_parts(data, len as usize);

        let data = String::from_utf8(slice.to_vec()).map_err(|_| AwsLcCryptoError::CryptoError)?;

        if let Some(component) = match nid {
            NID_commonName => Some(SubjectComponent::CommonName(data)),
            NID_surname => Some(SubjectComponent::Surname(data)),
            NID_serialNumber => Some(SubjectComponent::SerialNumber(data)),
            NID_countryName => Some(SubjectComponent::CountryName(data)),
            NID_localityName => Some(SubjectComponent::Locality(data)),
            NID_stateOrProvinceName => Some(SubjectComponent::State(data)),
            NID_streetAddress => Some(SubjectComponent::StreetAddress(data)),
            NID_organizationName => Some(SubjectComponent::OrganizationName(data)),
            NID_organizationalUnitName => Some(SubjectComponent::OrganizationalUnit(data)),
            NID_title => Some(SubjectComponent::Title(data)),
            NID_givenName => Some(SubjectComponent::GivenName(data)),
            NID_pkcs9_emailAddress => Some(SubjectComponent::EmailAddress(data)),
            NID_userId => Some(SubjectComponent::UserId(data)),
            NID_domainComponent => Some(SubjectComponent::DomainComponent(data)),
            NID_initials => Some(SubjectComponent::Initials(data)),
            NID_generationQualifier => Some(SubjectComponent::GenerationQualifier(data)),
            NID_distinguishedName => Some(SubjectComponent::DistinguishedNameQualifier(data)),
            NID_pseudonym => Some(SubjectComponent::Pseudonym(data)),
            _ => None,
        } {
            components.push(component);
        }

        Ok(components)
    })
}
