use std::collections::HashMap;

use aws_mls::bench_utils::create_group::create_group;

use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};

use aws_mls::cipher_suite::CipherSuite;

use aws_mls::group::GroupState;

fn group_setup(c: &mut Criterion) {
    let mut group_serialize = c.benchmark_group("group_serialize");

    for cipher_suite in CipherSuite::all() {
        println!("Benchmarking group state serialization for: {cipher_suite:?}");

        let container = [10, 100, 1000]
            .into_iter()
            .map(|length| (length, create_group(cipher_suite, length)))
            .collect::<HashMap<_, _>>();

        bench_group_serialize(&mut group_serialize, cipher_suite, container);
    }

    group_serialize.finish();
}

// runs JSON serialization, thoughts?
fn bench_group_serialize(
    bench_group: &mut BenchmarkGroup<WallTime>,
    cipher_suite: CipherSuite,
    container: HashMap<usize, GroupState>,
) {
    for (key, value) in container {
        bench_group.bench_with_input(
            BenchmarkId::new(format!("{cipher_suite:?}"), key),
            &key,
            |b, _| {
                b.iter(|| {
                    serde_json::to_vec(&value).unwrap();
                })
            },
        );
    }
}

criterion_group!(benches, group_setup);
criterion_main!(benches);
