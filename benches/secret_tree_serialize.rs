use aws_mls::bench_utils::group_functions::load_test_cases;

use aws_mls::client_config::ClientConfig;

use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};

use aws_mls::group::secret_tree::SecretTree;

use aws_mls::cipher_suite::CipherSuite;

use aws_mls::epoch::EpochRepository;

fn secret_tree_setup(c: &mut Criterion) {
    let mut secret_tree_group = c.benchmark_group("secret_tree_serialize");
    pub const TEST_GROUP: &[u8] = b"group";

    let cipher_suite = CipherSuite::Curve25519Aes128;

    println!("Benchmarking secret tree serialization for: {cipher_suite:?}");

    let container = load_test_cases();

    for groups in container {
        let group_stats = groups[0].group_stats().unwrap();
        let epoch_id = group_stats.epoch;

        let epoch_repo = groups[0].config.epoch_repo();

        let epoch = epoch_repo.get(TEST_GROUP, epoch_id).unwrap().unwrap();

        let secret_tree = epoch.secret_tree();

        bench_secret_tree_serialize(
            &mut secret_tree_group,
            cipher_suite,
            groups.len(),
            secret_tree,
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
