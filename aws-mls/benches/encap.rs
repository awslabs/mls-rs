use aws_mls::{
    bench_utils::create_empty_tree::{load_test_cases, TestCase},
    extension::ExtensionList,
    provider::{crypto::test_utils::test_cipher_suite_provider, identity::BasicIdentityProvider},
    tree_kem::{
        kem::TreeKem,
        leaf_node::{test_utils::get_test_capabilities, ConfigProperties},
        node::LeafIndex,
        Capabilities,
    },
    CipherSuite,
};
use criterion::{
    async_executor::FuturesExecutor, criterion_group, criterion_main, measurement::WallTime,
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion,
};
use futures::executor::block_on;
use std::collections::HashMap;

fn encap_setup(c: &mut Criterion) {
    let mut encap_group = c.benchmark_group("encap");

    let cipher_suite = CipherSuite::CURVE25519_AES128;

    println!("Benchmarking encap for: {cipher_suite:?}");

    let trees = block_on(load_test_cases());

    bench_encap(&mut encap_group, &[], None, None, cipher_suite, trees);

    encap_group.finish();
}

fn bench_encap(
    bench_group: &mut BenchmarkGroup<WallTime>,
    excluding: &[LeafIndex],
    capabilities: Option<Capabilities>,
    extensions: Option<ExtensionList>,
    cipher_suite: CipherSuite,
    map: HashMap<usize, TestCase>,
) {
    for (key, value) in &map {
        bench_group.bench_with_input(
            BenchmarkId::new(format!("{cipher_suite:?}"), key),
            key,
            |b, _| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        (
                            value.encap_tree.clone(),
                            value.encap_private_key.clone(),
                            value.group_context.clone(),
                            ConfigProperties {
                                capabilities: capabilities
                                    .clone()
                                    .unwrap_or_else(get_test_capabilities),
                                extensions: extensions.clone().unwrap_or_default(),
                            },
                        )
                    },
                    |(
                        mut encap_tree,
                        mut encap_private_key,
                        mut group_context,
                        update_leaf_properties,
                    )| async move {
                        TreeKem::new(&mut encap_tree, &mut encap_private_key)
                            .encap(
                                &mut group_context,
                                excluding,
                                &value.encap_signer,
                                update_leaf_properties,
                                None,
                                BasicIdentityProvider,
                                &test_cipher_suite_provider(cipher_suite),
                            )
                            .await
                            .unwrap()
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

criterion_group!(benches, encap_setup);
criterion_main!(benches);
