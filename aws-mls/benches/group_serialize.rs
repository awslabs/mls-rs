#[cfg(sync)]
use aws_mls::{test_utils::benchmarks::load_group_states, CipherSuite};

#[cfg(sync)]
use criterion::{BenchmarkId, Criterion};

#[cfg(sync)]
fn bench_serialize(c: &mut Criterion) {
    use criterion::BatchSize;

    let cs = CipherSuite::CURVE25519_AES128;
    let group_states = load_group_states(cs);
    let mut bench_group = c.benchmark_group("group_serialize");

    for (i, group_states) in group_states.into_iter().enumerate() {
        bench_group.bench_with_input(BenchmarkId::new(format!("{cs:?}"), i), &i, |b, _| {
            b.iter_batched_ref(
                || group_states.sender.clone(),
                move |sender| sender.write_to_storage().unwrap(),
                BatchSize::SmallInput,
            )
        });
    }

    bench_group.finish();
}

#[cfg(not(sync))]
fn bench_serialize(_c: &mut criterion::Criterion) {}

criterion::criterion_group!(benches, bench_serialize);
criterion::criterion_main!(benches);
