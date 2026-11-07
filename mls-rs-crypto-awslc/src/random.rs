use mls_rs_crypto_hpke::kem_combiner::SeedRng;

use crate::AwsLcCryptoError;

/// The aws-lc RNG as a [`SeedRng`].
#[derive(Clone, Copy, Debug, Default)]
pub struct AwsLcRandom;

impl SeedRng for AwsLcRandom {
    type Error = AwsLcCryptoError;

    fn fill(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        Ok(aws_lc_rs::rand::fill(out)?)
    }
}
