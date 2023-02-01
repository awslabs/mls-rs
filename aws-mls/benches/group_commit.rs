use aws_mls::{
    bench_utils::group_functions::{commit_groups, load_test_cases},
    cipher_suite::CipherSuite,
    client::MlsConfig,
    group::Group,
};
use aws_mls_core::crypto::CURVE25519_AES128;
use criterion::{
    async_executor::FuturesExecutor, criterion_group, criterion_main, measurement::WallTime,
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion,
};
use futures::executor::block_on;

fn commit_setup(c: &mut Criterion) {
    let mut group_commit = c.benchmark_group("group_commit");

    let cipher_suite = CURVE25519_AES128;

    println!("Benchmarking group commit for: {cipher_suite:?}");

    let container = block_on(async {
        // creates groups of the desired sizes
        let container = load_test_cases().await;
        // fills the tree by having everyone commit
        commit_groups(container).await
    });

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
                b.to_async(FuturesExecutor).iter_batched(
                    || (groups[0].clone(), groups[1].clone()),
                    |(mut sender, mut receiver)| async move {
                        let commit_output = sender.commit(Vec::new()).await.unwrap();

                        sender.apply_pending_commit().await.unwrap();

                        receiver
                            .process_incoming_message(commit_output.commit_message)
                            .await
                            .unwrap();
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

criterion_group!(benches, commit_setup);
criterion_main!(benches);
