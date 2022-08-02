use std::collections::HashMap;

use aws_mls::bench_utils::group_functions::{commit_groups, create_group};

use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};

use aws_mls::client_config::InMemoryClientConfig;

use aws_mls::session::Session;

use aws_mls::cipher_suite::CipherSuite;

fn commit_setup(c: &mut Criterion) {
    let mut group_commit = c.benchmark_group("group_commit");

    let cipher_suite = CipherSuite::Curve25519Aes128;

    println!("Benchmarking group commit for: {cipher_suite:?}");

    // creates groups of the desired sizes
    let mut container = [10, 50, 100]
        .into_iter()
        .map(|length| (length, create_group(cipher_suite, length, false).1))
        .collect::<HashMap<_, _>>();

    // fills the tree by having everyone commit
    container = commit_groups(container);

    bench_group_commit(&mut group_commit, cipher_suite, container);

    group_commit.finish();
}

// benches a single commit, apply, and receive (process)
fn bench_group_commit(
    bench_group: &mut BenchmarkGroup<WallTime>,
    cipher_suite: CipherSuite,
    container: HashMap<usize, Vec<Session<InMemoryClientConfig>>>,
) {
    for (key, mut value) in container {
        bench_group.bench_with_input(
            BenchmarkId::new(format!("{cipher_suite:?}"), key),
            &key,
            |b, _| {
                b.iter(|| {
                    let commit = value[0].commit(Vec::new(), Vec::new()).unwrap();
                    value[0].apply_pending_commit().unwrap();

                    value[1]
                        .process_incoming_bytes(&commit.commit_packet)
                        .unwrap();
                })
            },
        );
    }
}

criterion_group!(benches, commit_setup);
criterion_main!(benches);
