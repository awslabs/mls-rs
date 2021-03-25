use rand_core::{RngCore, Error};
use rand_core::CryptoRng;
use rand_core::impls;
use std::num::NonZeroU32;

#[derive(Clone, Copy, Debug, Default)]
pub struct OpenSslRng;

impl CryptoRng for OpenSslRng {}

impl RngCore for OpenSslRng {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.try_fill_bytes(dest).is_err()  {
            panic!("OpenSSL RNG critical error!")
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        openssl::rand::rand_bytes(dest)
            .map_err(|_| Error::from(NonZeroU32::new(1).unwrap()))
    }
}

#[cfg(test)]
pub mod test_rng {
    use rand_core::{CryptoRng, RngCore, Error, impls};
    use std::num::NonZeroU32;

    pub struct OneValRng {
        pub val: Vec<u8>
    }

    impl CryptoRng for OneValRng {}

    impl RngCore for OneValRng {
        fn next_u32(&mut self) -> u32 {
            impls::next_u32_via_fill(self)
        }

        fn next_u64(&mut self) -> u64 {
            impls::next_u64_via_fill(self)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            if let Err(_) = self.try_fill_bytes(dest) {
                panic!("OpenSSL RNG critical error!")
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            if dest.len() != self.val.len() {
                println!("Invalid random length called {} expected {}", dest.len(), self.val.len());
                return Err(Error::from(NonZeroU32::new(1).unwrap()));
            } else {
                dest.copy_from_slice(&self.val)
            }
            Ok(())
        }
    }

    pub struct ZerosRng;

    impl CryptoRng for ZerosRng {}

    impl RngCore for ZerosRng {
        fn next_u32(&mut self) -> u32 {
            impls::next_u32_via_fill(self)
        }

        fn next_u64(&mut self) -> u64 {
            impls::next_u64_via_fill(self)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.iter_mut().for_each(|i| *i = 0u8)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[derive(Clone)]
    pub struct RepeatRng {
        pub num: u8
    }

    impl CryptoRng for RepeatRng {}

    impl RngCore for RepeatRng {
        fn next_u32(&mut self) -> u32 {
            impls::next_u32_via_fill(self)
        }

        fn next_u64(&mut self) -> u64 {
            impls::next_u64_via_fill(self)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.iter_mut().for_each(|i| *i = self.num)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rand::OpenSslRng;
    use rand_core::RngCore;

    #[test]
    fn test_os_rng() {
        let x = OpenSslRng.next_u64();
        let y = OpenSslRng.next_u64();
        assert_ne!(x, 0);
        assert_ne!(x, y);
    }

    #[test]
    fn test_construction() {
        let mut rng = OpenSslRng::default();
        assert_ne!(rng.next_u64(), 0);
    }
}
