#[cfg(test)]
macro_rules! hex {
    ($input:literal) => {
        hex::decode($input).expect("invalid hex value")
    };
}

#[macro_use]
pub mod asym;
pub mod kem;
pub mod hpke;
pub mod kdf;
pub mod aead;
pub mod rand;
pub mod credential;
pub mod tree_math;
pub mod key_package;
pub mod protocol_version;
pub mod extension;
pub mod ciphersuite;
pub mod signature;
pub mod hash;
pub mod client;
pub mod ratchet_tree;
pub mod key_schedule;
pub mod hpke_kdf;
pub mod tree_path;
pub mod tree_node;
pub mod secret_tree;
pub mod epoch;
pub mod group;
pub mod framing;
pub mod transcript_hash;
mod tree_hash;
