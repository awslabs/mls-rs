use aws_mls::{
    bench_utils::create_empty_tree::{load_test_cases, TestCase},
    cipher_suite::CipherSuite,
    extension::ExtensionList,
    provider::{crypto::test_utils::test_cipher_suite_provider, identity::BasicIdentityProvider},
    tree_kem::{
        kem::TreeKem,
        leaf_node::{test_utils::get_test_capabilities, ConfigProperties},
        node::LeafIndex,
        update_path::ValidatedUpdatePath,
        Capabilities,
    },
};
use criterion::{
    async_executor::FuturesExecutor, criterion_group, criterion_main, measurement::WallTime,
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion,
};
use futures::executor::block_on;
use std::collections::HashMap;

fn decap_setup(c: &mut Criterion) {
    let mut decap_group = c.benchmark_group("decap");

    let cipher_suite = CipherSuite::CURVE25519_AES128;

    println!("Benchmarking decap for: {cipher_suite:?}");

    let trees = block_on(load_test_cases());

    // Run Decap Benchmark
    bench_decap(&mut decap_group, cipher_suite, trees, &[], None, None);

    decap_group.finish();
}

fn bench_decap(
    bench_group: &mut BenchmarkGroup<WallTime>,
    cipher_suite: CipherSuite,
    map: HashMap<usize, TestCase>,
    added_leaves: &[LeafIndex],
    capabilities: Option<Capabilities>,
    extensions: Option<ExtensionList>,
) {
    for (key, mut value) in map {
        // Perform the encap function
        let update_leaf_properties = ConfigProperties {
            capabilities: capabilities.clone().unwrap_or_else(get_test_capabilities),
            extensions: extensions.clone().unwrap_or_default(),
        };

        let encap_gen = block_on(
            TreeKem::new(&mut value.encap_tree, &mut value.encap_private_key).encap(
                &mut value.group_context,
                &[],
                &value.encap_signer,
                update_leaf_properties,
                None,
                BasicIdentityProvider,
                &test_cipher_suite_provider(cipher_suite),
            ),
        )
        .unwrap();

        // Apply the update path to the rest of the leaf nodes using the decap function
        let validated_update_path = &ValidatedUpdatePath {
            leaf_node: encap_gen.update_path.leaf_node,
            nodes: encap_gen.update_path.nodes,
        };

        // Create one receiver tree so decap is run once
        let receiver_tree = value.test_tree.clone();
        let private_keys = value.private_keys;

        bench_group.bench_with_input(
            BenchmarkId::new(format!("{cipher_suite:?}"), key),
            &key,
            |b, _| {
                b.to_async(FuturesExecutor).iter_batched(
                    || {
                        (
                            receiver_tree.clone(),
                            private_keys[0].clone(),
                            value.group_context.clone(),
                        )
                    },
                    |(mut receiver_tree, mut private_key, mut group_context)| async move {
                        TreeKem::new(&mut receiver_tree, &mut private_key)
                            .decap(
                                LeafIndex::new(0),
                                validated_update_path,
                                added_leaves,
                                &mut group_context,
                                BasicIdentityProvider,
                                &test_cipher_suite_provider(cipher_suite),
                            )
                            .await
                            .unwrap();
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

criterion_group!(benches, decap_setup);
criterion_main!(benches);
