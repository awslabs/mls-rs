#[macro_use]
macro_rules! hex {
    ($input:literal) => {
        hex::decode($input).expect("invalid hex value")
    };
}

#[inline]
pub fn log2(x: u64) -> u64 {
    (x as f32).log2().floor() as u64
}