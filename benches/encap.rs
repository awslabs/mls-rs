use std::collections::HashMap;

use aws_mls::bench_utils::create::{create_stage, Tools};

use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};

use aws_mls::cipher_suite::CipherSuite;

use aws_mls::extension::ExtensionList;
use aws_mls::tree_kem::Capabilities;

use aws_mls::tree_kem::kem::TreeKem;
use aws_mls::tree_kem::node::LeafIndex;

fn encap_setup(c: &mut Criterion) {
    let mut encap_group = c.benchmark_group("encap");

    // running benchmark for each cipher suite
    for cipher_suite in CipherSuite::all() {
        println!("Benchmarking encap for: {cipher_suite:?}");

        let trees = create_stage(cipher_suite);

        bench_encap(&mut encap_group, &[], None, None, cipher_suite, trees);
    }

    encap_group.finish();
}

fn bench_encap(
    bench_group: &mut BenchmarkGroup<WallTime>,
    excluding: &[LeafIndex],
    capabilities: Option<Capabilities>,
    extensions: Option<ExtensionList>,
    cipher_suite: CipherSuite,
    map: HashMap<usize, Tools>,
) {
    for (key, mut value) in map {
        bench_group.bench_with_input(
            BenchmarkId::new(format!("{cipher_suite:?}"), key),
            &key,
            |b, _| {
                b.iter(|| {
                    TreeKem::new(&mut value.encap_tree, value.encap_private_key.clone())
                        .encap(
                            b"test_group",
                            b"test_ctx",
                            excluding,
                            &value.encap_signer,
                            capabilities.clone(),
                            extensions.clone(),
                        )
                        .unwrap()
                })
            },
        );
    }
}

criterion_group!(benches, encap_setup);
criterion_main!(benches);
