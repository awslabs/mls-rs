// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![cfg(all(mls_build_async, target_arch = "wasm32"))]

use mls_rs_core::crypto::{CipherSuite, CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_webcrypto::WebCryptoProvider;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

// Verifies that the WebCrypto provider works inside a `DedicatedWorkerGlobalScope`,
// where `web_sys::window()` returns `None` but `globalThis.crypto.subtle` is defined.
#[wasm_bindgen_test]
async fn provider_works_inside_dedicated_worker() {
    let provider = WebCryptoProvider::default();
    let cs = provider
        .cipher_suite_provider(CipherSuite::P256_AES128)
        .expect("cipher suite must be available in worker context");

    let (_secret, public) = cs
        .signature_key_generate()
        .await
        .expect("signature_key_generate must succeed in worker context");
    assert!(!public.as_ref().is_empty());

    let mut bytes = [0u8; 32];
    cs.random_bytes(&mut bytes)
        .expect("random_bytes must succeed in worker context");
    assert!(bytes.iter().any(|b| *b != 0));
}
