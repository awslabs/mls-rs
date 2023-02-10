#![no_main]
use aws_mls::bench_utils::group_functions::TestClientConfig;
use aws_mls::CipherSuite;
use aws_mls::{bench_utils::group_functions::create_group, group::Group};
use libfuzzer_sys::{arbitrary, fuzz_target};
use once_cell::sync::Lazy;

static GLOBAL_DATA: Lazy<Vec<Group<TestClientConfig>>> = Lazy::new(|| {
    let cipher_suite = CipherSuite::CURVE25519_AES128;
    futures::executor::block_on(create_group(cipher_suite, 2))
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
