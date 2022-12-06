use aws_mls::{
    bench_utils::group_functions::{commit_groups, load_test_cases},
    cipher_suite::CipherSuite,
    client::MlsConfig,
    group::Group,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};

fn commit_setup(c: &mut Criterion) {
    let mut group_commit = c.benchmark_group("group_commit");

    let cipher_suite = CipherSuite::Curve25519Aes128;

    println!("Benchmarking group commit for: {cipher_suite:?}");

    // creates groups of the desired sizes
    let mut container = load_test_cases();

    // fills the tree by having everyone commit
    container = commit_groups(container);

    bench_group_commit(&mut group_commit, cipher_suite, container);

    group_commit.finish();
}

// benches a single commit, apply, and receive (process)
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
                b.iter(|| {
                    let commit_output = groups[0].commit(Vec::new()).unwrap();

                    groups[0].apply_pending_commit().unwrap();

                    groups[1]
                        .process_incoming_message(commit_output.commit_message)
                        .unwrap();
                })
            },
        );
    }
}

criterion_group!(benches, commit_setup);
criterion_main!(benches);
