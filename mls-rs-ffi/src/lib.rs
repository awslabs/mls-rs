// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#[cfg(all(feature = "openssl", feature = "sqlite", feature = "x509"))]
mod openssl_sqlite {
    use mls_rs::client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider};
    use mls_rs_crypto_openssl::x509::{X509Reader, X509Validator};
    use mls_rs_crypto_openssl::OpensslCryptoProvider;
    use mls_rs_identity_x509::{SubjectIdentityExtractor, X509IdentityProvider};

    pub type OpensslSqlMlsConfig = WithIdentityProvider<
        X509IdentityProvider<SubjectIdentityExtractor<X509Reader>, X509Validator>,
        WithCryptoProvider<OpensslCryptoProvider, BaseConfig>,
    >;

    safer_ffi_gen::specialize!(OpensslSqlMlsClient = mls_rs::client::Client<OpensslSqlMlsConfig>);
    safer_ffi_gen::specialize!(OpensslSqlMlsGroup = mls_rs::group::Group<OpensslSqlMlsConfig>);
}

#[cfg(all(feature = "openssl", feature = "sqlite", feature = "x509"))]
pub use openssl_sqlite::*;
