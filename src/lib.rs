#[cfg(test)]
macro_rules! hex {
    ($input:literal) => {
        hex::decode($input).expect("invalid hex value")
    };
}

#[macro_use]
pub mod ciphersuite;
pub mod client;
mod confirmation_tag;
pub mod credential;
pub mod crypto;
pub mod epoch;
pub mod extension;
pub mod framing;
pub mod group;
pub mod key_package;
pub mod key_schedule;
mod membership_tag;
mod message_signature;
pub mod protocol_version;
pub mod secret_tree;
pub mod transcript_hash;
pub mod tree_kem;
