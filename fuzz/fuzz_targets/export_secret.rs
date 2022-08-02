#![no_main]
use libfuzzer_sys::{arbitrary, fuzz_target};

use once_cell::sync::Lazy;

use aws_mls::bench_utils::group_functions::create_group;

use aws_mls::session::Session;

use aws_mls::client_config::InMemoryClientConfig;

use aws_mls::cipher_suite::CipherSuite;

static GLOBAL_DATA: Lazy<Vec<Session<InMemoryClientConfig>>> = Lazy::new(|| {
    let cipher_suite = CipherSuite::Curve25519Aes128;
    let (_, container) = create_group(cipher_suite, 2, false);

    container
});

#[derive(Clone, Debug)]
struct USize(usize);

impl<'a> arbitrary::Arbitrary<'a> for USize {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        let x: usize = u.int_in_range(0..=4_000)?;

        Ok(Self(x))
    }
}

fuzz_target!(|data: (&str, &[u8], USize)| {
    let _ = GLOBAL_DATA[1].export_secret(data.0, data.1, data.2 .0);
});
