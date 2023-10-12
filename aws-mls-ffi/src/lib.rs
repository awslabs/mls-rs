// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#[cfg(all(feature = "openssl", feature = "sqlite", feature = "x509"))]
mod openssl_sqlite {
    use aws_mls::client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider};
    use aws_mls_crypto_openssl::{
        x509::{X509Reader, X509Validator},
        OpensslCryptoProvider,
    };
    use aws_mls_identity_x509::{
        NoOpWarningProvider, SubjectIdentityExtractor, X509IdentityProvider,
    };

    pub type OpensslSqlMlsConfig = WithIdentityProvider<
        X509IdentityProvider<
            SubjectIdentityExtractor<X509Reader>,
            X509Validator,
            NoOpWarningProvider,
        >,
        WithCryptoProvider<OpensslCryptoProvider, BaseConfig>,
    >;

    safer_ffi_gen::specialize!(OpensslSqlMlsClient = aws_mls::client::Client<OpensslSqlMlsConfig>);
    safer_ffi_gen::specialize!(OpensslSqlMlsGroup = aws_mls::group::Group<OpensslSqlMlsConfig>);
}

#[cfg(all(feature = "openssl", feature = "sqlite", feature = "x509"))]
pub use openssl_sqlite::*;
