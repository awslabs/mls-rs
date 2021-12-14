use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ferriscrypt::asym::ec_key::{Curve, SecretKey};
use std::{io, iter};
use tls_codec::Serialize;
use tls_codec_derive::{TlsSerialize, TlsSize};
use wickr_bgm as mls;

#[derive(Debug, TlsSerialize, TlsSize)]
struct KeyRefs<'a>(
    #[tls_codec(with = "mls::tls::Vector::<u32, mls::tls::SecretKeySer>")] &'a [SecretKey],
);

fn serialize_keys(c: &mut Criterion) {
    let keys = iter::repeat_with(|| SecretKey::generate(Curve::Ed25519).unwrap())
        .take(10_000)
        .collect::<Vec<_>>();
    let mut bench_group = c.benchmark_group("serialize_keys");
    let counts = iter::once(0)
        .chain(iter::successors(Some(1), |&n| Some(10 * n)))
        .take_while(|&n| n <= keys.len());
    for n in counts {
        bench_group.throughput(Throughput::Elements(n as u64));
        bench_group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let _ = black_box(KeyRefs(&keys[..n]))
                    .tls_serialize(&mut io::sink())
                    .unwrap();
            });
        });
    }
    bench_group.finish();
}

criterion_group!(benches, serialize_keys);
criterion_main!(benches);
