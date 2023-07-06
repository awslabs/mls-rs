#[cfg(sync)]
use aws_mls::{
    bench_utils::create_empty_tree::{load_test_cases, TestCase},
    tree_kem::{
        kem::TreeKem, leaf_node::ConfigProperties, node::LeafIndex,
        update_path::ValidatedUpdatePath, Capabilities,
    },
    CipherSuite, ExtensionList,
};
#[cfg(sync)]
use aws_mls_codec::MlsEncode;
#[cfg(sync)]
use aws_mls_core::crypto::CryptoProvider;
#[cfg(sync)]
use aws_mls_crypto_openssl::OpensslCryptoProvider;
#[cfg(sync)]
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, BenchmarkId,
    Criterion,
};
#[cfg(sync)]
use std::collections::HashMap;

#[cfg(sync)]
fn decap_setup(c: &mut Criterion) {
    let mut decap_group = c.benchmark_group("decap");

    let cipher_suite = CipherSuite::CURVE25519_AES128;

    let trees = load_test_cases();

    // Run Decap Benchmark
    bench_decap(&mut decap_group, cipher_suite, trees, &[], None, None);

    decap_group.finish();
}

#[cfg(sync)]
fn bench_decap(
    bench_group: &mut BenchmarkGroup<WallTime>,
    cipher_suite: CipherSuite,
    map: HashMap<u32, TestCase>,
    added_leaves: &[LeafIndex],
    capabilities: Option<Capabilities>,
    extensions: Option<ExtensionList>,
) {
    for (key, mut value) in map {
        // Perform the encap function
        let update_leaf_properties = ConfigProperties {
            capabilities: capabilities.clone().unwrap_or_default(),
            extensions: extensions.clone().unwrap_or_default(),
        };

        let encap_gen = TreeKem::new(&mut value.encap_tree, &mut value.encap_private_key)
            .encap(
                &mut value.group_context,
                &[],
                &value.encap_signer,
                update_leaf_properties,
                None,
                &OpensslCryptoProvider::new()
                    .cipher_suite_provider(cipher_suite)
                    .unwrap(),
            )
            .unwrap();

        // Apply the update path to the rest of the leaf nodes using the decap function
        let validated_update_path = &ValidatedUpdatePath {
            leaf_node: encap_gen.update_path.leaf_node,
            nodes: encap_gen.update_path.nodes.into_iter().map(Some).collect(),
        };

        // Create one receiver tree so decap is run once
        let receiver_tree = value.test_tree.clone();
        let private_keys = value.private_keys;

        bench_group.bench_with_input(
            BenchmarkId::new(format!("{cipher_suite:?}"), key),
            &key,
            |b, _| {
                b.iter_batched_ref(
                    || {
                        (
                            receiver_tree.clone(),
                            private_keys[0].clone(),
                            value.group_context.mls_encode_to_vec().unwrap(),
                            OpensslCryptoProvider::new()
                                .cipher_suite_provider(cipher_suite)
                                .unwrap(),
                        )
                    },
                    move |(receiver_tree, private_key, group_context, cs)| {
                        TreeKem::new(receiver_tree, private_key)
                            .decap(
                                LeafIndex::new(0),
                                validated_update_path,
                                added_leaves,
                                &group_context,
                                cs,
                            )
                            .unwrap();
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

#[cfg(not(sync))]
fn decap_setup(_: &mut criterion::Criterion) {}

criterion::criterion_group!(benches, decap_setup);
criterion::criterion_main!(benches);
