use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ferriscrypt::asym::ec_key::{Curve, SecretKey};
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use wickr_bgm as mls;

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
struct Keys(#[tls_codec(with = "mls::tls::Vector::<u32, mls::tls::SecretKeySer>")] Vec<SecretKey>);

fn serialize_keys(c: &mut Criterion) {
    c.bench_function("serialize_keys", |b| {
        b.iter(|| {
            let _ = black_box(Keys(vec![SecretKey::generate(Curve::Ed25519).unwrap()]))
                .tls_serialize_detached()
                .unwrap();
        })
    });
}

criterion_group!(benches, serialize_keys);
criterion_main!(benches);
