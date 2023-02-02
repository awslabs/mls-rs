#![allow(clippy::enum_variant_names)]
#![allow(clippy::result_large_err)]
#![allow(clippy::nonstandard_macro_braces)]

#[cfg(all(test, target_arch = "wasm32"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg(test)]
macro_rules! hex {
    ($input:literal) => {
        hex::decode($input).expect("invalid hex value")
    };
}

#[cfg(any(test, feature = "benchmark"))]
macro_rules! load_test_cases {
    ($name:ident, $generate:expr) => {
        load_test_cases!($name, $generate, to_vec_pretty)
    };
    ($name:ident, $generate:expr, $to_json:ident) => {{
        #[cfg(target_arch = "wasm32")]
        {
            let _ = async { $generate };
            serde_json::from_slice(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test_data/",
                stringify!($name),
                ".json"
            )))
            .unwrap()
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test_data/",
                stringify!($name),
                ".json"
            );
            if !std::path::Path::new(path).exists() {
                std::fs::write(path, serde_json::$to_json(&$generate).unwrap()).unwrap();
            }
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
        }
    }};
}

pub mod cipher_suite {
    pub use aws_mls_core::crypto::CipherSuite;
}

pub mod client;
mod client_builder;
mod client_config;
pub mod extension;
pub mod external_client;
mod external_client_builder;
mod external_client_config;
pub mod group;
mod hash_reference;
pub mod identity;
pub mod key_package;
pub mod protocol_version;
pub mod provider;
pub mod psk;
mod signer;

pub mod time {
    pub use aws_mls_core::time::*;
}

mod serde_utils {
    pub use aws_mls_core::serde::*;
}

#[cfg(feature = "benchmark")]
pub mod tls {
    pub use aws_mls_core::tls::*;
}

#[cfg(not(feature = "benchmark"))]
mod tls {
    pub use aws_mls_core::tls::*;
}

#[cfg(feature = "benchmark")]
pub mod bench_utils;

#[cfg(feature = "benchmark")]
pub mod tree_kem;

#[cfg(not(feature = "benchmark"))]
mod tree_kem;

pub use tls_codec;

mod private {
    pub trait Sealed {}
}

use private::Sealed;
