#[cfg(sync)]
use aws_mls::{
    bench_utils::group_functions::load_test_cases, client_builder::MlsConfig, CipherSuite, Group,
};
#[cfg(sync)]
use criterion::{measurement::WallTime, BatchSize, BenchmarkGroup, BenchmarkId, Criterion};

#[cfg(sync)]
fn bench(c: &mut Criterion) {
    let mut group_commit = c.benchmark_group("group_receive_commit");

    let cipher_suite = CipherSuite::CURVE25519_AES128;

    // creates groups of the desired sizes
    let container = load_test_cases(cipher_suite);

    bench_group_commit(&mut group_commit, cipher_suite, container);

    group_commit.finish();
}

// benches the processing of a single commit
#[cfg(sync)]
fn bench_group_commit<C: MlsConfig>(
    bench_group: &mut BenchmarkGroup<WallTime>,
    cipher_suite: CipherSuite,
    mut container: Vec<Vec<Group<C>>>,
) {
    for groups in &mut container {
        bench_group.bench_with_input(
            BenchmarkId::new(format!("{cipher_suite:?}"), groups.len()),
            &groups.len(),
            |b, _| {
                b.iter_batched_ref(
                    || {
                        (
                            groups[0].clone().commit(Vec::new()).unwrap(),
                            groups[1].clone(),
                        )
                    },
                    move |(commit, receiver)| {
                        receiver
                            .process_incoming_message(commit.commit_message.clone())
                            .unwrap();
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

#[cfg(not(sync))]
fn bench(_: &mut criterion::Criterion) {}

criterion::criterion_group!(benches, bench);
criterion::criterion_main!(benches);
