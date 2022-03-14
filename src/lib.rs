#![allow(clippy::nonstandard_macro_braces)]
#![allow(clippy::enum_variant_names)]

#[cfg(test)]
macro_rules! hex {
    ($input:literal) => {
        hex::decode($input).expect("invalid hex value")
    };
}

#[macro_use]
pub mod cipher_suite;
pub mod client;
pub mod client_config;
pub mod credential;
pub mod extension;
mod group;
mod hash_reference;
pub mod key_package;
mod protocol_version;
mod psk;
pub mod session;
pub mod signer;
mod tree_kem;
pub mod x509;

#[cfg(feature = "benchmark")]
pub mod tls;

#[cfg(not(feature = "benchmark"))]
mod tls;

pub use ferriscrypt;
pub use group::proposal::{AddProposal, Proposal, RemoveProposal, UpdateProposal};
pub use protocol_version::ProtocolVersion;
pub use tls_codec;

pub mod time;
