#[macro_use]
macro_rules! hex {
    ($input:literal) => {
        hex::decode($input).expect("invalid hex value")
    };
}

