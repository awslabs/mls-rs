#[cfg(any(feature = "sqlcipher", feature = "sqlcipher-bundled"))]
pub mod cipher;

pub mod connection_strategy;
pub mod group_state;
pub mod key_package;
pub mod keychain;
pub mod psk;

pub mod test_utils {
    use rand::RngCore;
    pub fn gen_rand_bytes(size: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0; size];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }
}
