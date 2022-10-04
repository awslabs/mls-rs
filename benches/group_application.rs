use aws_mls::cipher_suite::CipherSuite;
use aws_mls::client::MlsConfig;
use aws_mls::group::Group;

use ferriscrypt::rand::SecureRng;

use aws_mls::bench_utils::group_functions::{commit_group, load_test_cases};

use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
    Throughput,
};

fn application_message_setup(c: &mut Criterion) {
    let mut group_application = c.benchmark_group("group_application_message");

    let cipher_suite = CipherSuite::Curve25519Aes128;

    println!("Benchmarking group application message for: {cipher_suite:?}");

    // creates group of the desired size
    let mut container = load_test_cases();

    let sessions = container.iter_mut().next().unwrap();

    // fills the tree by having everyone commit
    commit_group(sessions);

    let bytes = SecureRng::gen(1000000).unwrap();

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
    let mut n = 100;

    while n <= 1000000 {
        bench_group.throughput(Throughput::Bytes(n as u64));
        bench_group.bench_with_input(
            BenchmarkId::new(format!("{cipher_suite:?}"), n),
            &n,
            |b, _| {
                b.iter(|| {
                    let msg = container[0]
                        .encrypt_application_message(&bytes[..n], vec![])
                        .unwrap();

                    container[1].process_incoming_message(msg).unwrap();
                })
            },
        );

        n *= 10;
    }
}

criterion_group!(benches, application_message_setup);
criterion_main!(benches);
