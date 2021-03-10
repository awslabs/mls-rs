#[macro_use]
macro_rules! hex {
    ($input:literal) => {
        hex::decode($input).expect("invalid hex value")
    };
}

#[inline]
pub fn log2(x: usize) -> usize {
    (x as f32).log2().floor() as usize
}