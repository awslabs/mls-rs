use aws_mls::{
    client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider},
    identity::basic::BasicIdentityProvider,
};
use aws_mls_crypto_openssl::OpensslCryptoProvider;

pub type FfiConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<OpensslCryptoProvider, BaseConfig>,
>;

safer_ffi_gen::specialize!(FfiClient = aws_mls::client::Client<FfiConfig>);
safer_ffi_gen::specialize!(FfiGroup = aws_mls::group::Group<FfiConfig>);
