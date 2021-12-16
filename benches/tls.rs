use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ferriscrypt::asym::ec_key::{Curve, SecretKey};
use std::{collections::HashMap, io, iter};
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use wickr_bgm as mls;

#[derive(Debug, TlsSerialize, TlsSize)]
struct KeyRefs<'a>(
    #[tls_codec(with = "mls::tls::Vector::<u32, mls::tls::SecretKeySer>")] &'a [SecretKey],
);

fn serialize_keys(c: &mut Criterion) {
    let keys = iter::repeat_with(|| SecretKey::generate(Curve::Ed25519).unwrap())
        .take(10_000)
        .collect::<Vec<_>>();
    benchmark(c, "serialize_keys", keys.len(), |n| {
        let _ = black_box(KeyRefs(&keys[..n]))
            .tls_serialize(&mut io::sink())
            .unwrap();
    });
}

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
struct Keys(#[tls_codec(with = "mls::tls::Vector::<u32, mls::tls::SecretKeySer>")] Vec<SecretKey>);

fn deserialize_keys(c: &mut Criterion) {
    let keys = iter::repeat_with(|| SecretKey::generate(Curve::Ed25519).unwrap())
        .take(10_000)
        .collect::<Vec<_>>();
    let serialized_keys = sample_counts(keys.len())
        .map(|n| (n, KeyRefs(&keys[..n]).tls_serialize_detached().unwrap()))
        .collect::<HashMap<_, _>>();
    benchmark(c, "deserialize_keys", keys.len(), |n| {
        let _ = Keys::tls_deserialize(&mut black_box(&*serialized_keys[&n])).unwrap();
    });
}

fn benchmark<F>(c: &mut Criterion, group_name: &str, max_keys: usize, mut f: F)
where
    F: FnMut(usize),
{
    let mut bench_group = c.benchmark_group(group_name);
    let counts = sample_counts(max_keys);
    for n in counts {
        bench_group.throughput(Throughput::Elements(n as u64));
        bench_group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| b.iter(|| f(n)));
    }
    bench_group.finish();
}

fn sample_counts(max: usize) -> impl Iterator<Item = usize> {
    iter::once(0)
        .chain(iter::successors(Some(1), |&n| Some(10 * n)))
        .take_while(move |&n| n <= max)
}

criterion_group!(benches, serialize_keys, deserialize_keys);
criterion_main!(benches);
