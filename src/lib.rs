#![allow(clippy::nonstandard_macro_braces)]
#![allow(clippy::enum_variant_names)]

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
            let _ = $generate;
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
                std::fs::write(path, serde_json::$to_json(&$generate()).unwrap()).unwrap();
            }
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
        }
    }};
}

#[macro_use]
pub mod cipher_suite;
pub mod client;
pub mod client_config;
pub mod credential;
pub mod extension;
pub mod external_client;
pub mod external_client_config;
pub mod group;
pub mod group_state_repo;
mod hash_reference;
pub mod key_package;
pub mod keychain;
mod maybe;
pub mod protocol_version;
pub mod psk;
mod serde_utils;
pub mod signer;
pub mod signing_identity;
mod time;
pub mod x509;

#[cfg(feature = "benchmark")]
pub mod bench_utils;

#[cfg(feature = "benchmark")]
pub mod tls;

#[cfg(feature = "benchmark")]
pub mod tree_kem;

#[cfg(not(feature = "benchmark"))]
mod tls;

#[cfg(not(feature = "benchmark"))]
mod tree_kem;

pub use ferriscrypt;
pub use tls_codec;
pub use x509_cert;
