use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ferriscrypt::asym::ec_key::{Curve, SecretKey};
use std::{collections::HashMap, io, iter};
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use wickr_bgm as mls;

const KEY_COUNT: usize = 10_000;

#[derive(Debug, TlsSerialize, TlsSize)]
struct KeyRefs<'a>(
    #[tls_codec(with = "mls::tls::Vector::<u32, mls::tls::SecretKeySer>")] &'a [SecretKey],
);

fn serialize_keys(c: &mut Criterion) {
    let keys = make_keys_for_all_curves(KEY_COUNT);
    benchmark(c, "serialize_keys", KEY_COUNT, |curve, n| {
        let _ = black_box(KeyRefs(&keys[&curve][..n]))
            .tls_serialize(&mut io::sink())
            .unwrap();
    });
}

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
struct Keys(#[tls_codec(with = "mls::tls::Vector::<u32, mls::tls::SecretKeySer>")] Vec<SecretKey>);

fn deserialize_keys(c: &mut Criterion) {
    let keys = make_keys_for_all_curves(KEY_COUNT);
    let serialized_keys = keys
        .iter()
        .map(|(curve, keys)| {
            (
                *curve,
                sample_counts(KEY_COUNT)
                    .map(|n| (n, KeyRefs(&keys[..n]).tls_serialize_detached().unwrap()))
                    .collect::<HashMap<_, _>>(),
            )
        })
        .collect::<HashMap<_, _>>();
    benchmark(c, "deserialize_keys", KEY_COUNT, |curve, n| {
        let _ = Keys::tls_deserialize(&mut black_box(&*serialized_keys[&curve][&n])).unwrap();
    });
}

fn benchmark<F>(c: &mut Criterion, group_name: &str, max_keys: usize, mut f: F)
where
    F: FnMut(Curve, usize),
{
    let mut bench_group = c.benchmark_group(group_name);
    let counts = sample_counts(max_keys);
    for n in counts {
        bench_group.throughput(Throughput::Elements(n as u64));
        for curve in Curve::all() {
            bench_group.bench_with_input(
                BenchmarkId::new(format!("{:?}", curve), n),
                &n,
                |b, &n| b.iter(|| f(curve, n)),
            );
        }
    }
    bench_group.finish();
}

fn sample_counts(max: usize) -> impl Iterator<Item = usize> {
    iter::once(0)
        .chain(iter::successors(Some(1), |&n| Some(10 * n)))
        .take_while(move |&n| n <= max)
}

fn make_keys_for_all_curves(n: usize) -> HashMap<Curve, Vec<SecretKey>> {
    Curve::all()
        .map(|curve| {
            (
                curve,
                iter::repeat_with(|| SecretKey::generate(curve).unwrap())
                    .take(n)
                    .collect(),
            )
        })
        .collect()
}

criterion_group!(benches, serialize_keys, deserialize_keys);
criterion_main!(benches);
