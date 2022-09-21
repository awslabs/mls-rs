use aws_mls::{
    bench_utils::group_functions::{get_snapshot, load_test_cases},
    cipher_suite::CipherSuite,
    client_config::test_utils::TestClientConfig,
    group::Group,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};

fn group_setup(c: &mut Criterion) {
    let mut group_serialize = c.benchmark_group("group_serialize");

    let cipher_suite = CipherSuite::Curve25519Aes128;

    println!("Benchmarking group state serialization for: {cipher_suite:?}");

    let container = load_test_cases();

    bench_group_snapshot(&mut group_serialize, cipher_suite, container);

    group_serialize.finish();
}

// benches JSON serialization of group state
fn bench_group_snapshot(
    bench_group: &mut BenchmarkGroup<WallTime>,
    cipher_suite: CipherSuite,
    container: Vec<Vec<Group<TestClientConfig>>>,
) {
    for groups in container {
        bench_group.bench_with_input(
            BenchmarkId::new(format!("{cipher_suite:?}"), groups.len()),
            &groups.len(),
            |b, _| {
                b.iter(|| {
                    get_snapshot(&groups[0]).unwrap();
                })
            },
        );
    }
}

criterion_group!(benches, group_setup);
criterion_main!(benches);
