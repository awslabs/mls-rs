use aws_mls::bench_utils::group_functions::load_test_cases;
use aws_mls::cipher_suite::CipherSuite;
use aws_mls::group::secret_tree::SecretTree;
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};
use futures::executor::block_on;

fn secret_tree_setup(c: &mut Criterion) {
    let mut secret_tree_group = c.benchmark_group("secret_tree_serialize");

    let cipher_suite = CipherSuite::CURVE25519_AES128;

    println!("Benchmarking secret tree serialization for: {cipher_suite:?}");

    let container = block_on(load_test_cases());

    for groups in container {
        bench_secret_tree_serialize(
            &mut secret_tree_group,
            cipher_suite,
            groups.len(),
            groups[0].secret_tree(),
        );
    }

    secret_tree_group.finish();
}

fn bench_secret_tree_serialize(
    bench_group: &mut BenchmarkGroup<WallTime>,
    cipher_suite: CipherSuite,
    key: usize,
    secret_tree: &SecretTree,
) {
    bench_group.bench_with_input(
        BenchmarkId::new(format!("{cipher_suite:?}"), key),
        &key,
        |b, _| {
            b.iter(|| {
                serde_json::to_vec(secret_tree).unwrap();
            })
        },
    );
}

criterion_group!(benches, secret_tree_setup);
criterion_main!(benches);
