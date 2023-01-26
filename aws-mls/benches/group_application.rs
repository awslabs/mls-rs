use aws_mls::cipher_suite::CipherSuite;
use aws_mls::client::MlsConfig;
use aws_mls::group::Group;

use aws_mls::bench_utils::group_functions::{commit_group, load_test_cases};

use criterion::{
    async_executor::FuturesExecutor, criterion_group, criterion_main, measurement::WallTime,
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion, Throughput,
};
use futures::executor::block_on;
use rand::RngCore;

fn application_message_setup(c: &mut Criterion) {
    let mut group_application = c.benchmark_group("group_application_message");

    let cipher_suite = CipherSuite::Curve25519Aes128;

    println!("Benchmarking group application message for: {cipher_suite:?}");

    // creates group of the desired size
    let mut container = block_on(load_test_cases());

    let sessions = container.iter_mut().next().unwrap();

    // fills the tree by having everyone commit
    block_on(commit_group(sessions));

    let mut bytes = vec![0; 1000000];
    rand::thread_rng().fill_bytes(&mut bytes);

    bench_application_message(&mut group_application, cipher_suite, sessions, bytes);

    group_application.finish();
}

// benchmarks the sending and receiving of an applciation message
fn bench_application_message<C: MlsConfig>(
    bench_group: &mut BenchmarkGroup<WallTime>,
    cipher_suite: CipherSuite,
    container: &mut [Group<C>],
    bytes: Vec<u8>,
) {
    let bytes = &bytes;
    let mut n = 100;

    while n <= 1000000 {
        bench_group.throughput(Throughput::Bytes(n as u64));
        bench_group.bench_with_input(
            BenchmarkId::new(format!("{cipher_suite:?}"), n),
            &n,
            |b, _| {
                b.to_async(FuturesExecutor).iter_batched(
                    || (container[0].clone(), container[1].clone()),
                    |(mut sender, mut receiver)| async move {
                        let msg = sender
                            .encrypt_application_message(&bytes[..n], vec![])
                            .await
                            .unwrap();

                        receiver.process_incoming_message(msg).await.unwrap();
                    },
                    BatchSize::SmallInput,
                )
            },
        );

        n *= 10;
    }
}

criterion_group!(benches, application_message_setup);
criterion_main!(benches);
