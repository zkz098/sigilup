#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use sigilup_core::{
    ARTIFACT_DESCRIPTOR_PAYLOAD_TYPE, HybridEnvelope, SecretKeyBundle, TrustStore,
    VerificationPolicy,
};

static TRUST_STORE: LazyLock<TrustStore> = LazyLock::new(|| {
    let sk = SecretKeyBundle::from_seeds([0x11; 32], [0x22; 32])
        .expect("deterministic seed key derivation");
    let pk = sk.public_key().clone().with_root(true);
    TrustStore::from_keys([pk])
});

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = serde_json::from_slice::<HybridEnvelope>(data) {
        let _ = env.decode_payload();
        let _ = env.verify(
            ARTIFACT_DESCRIPTOR_PAYLOAD_TYPE,
            &TRUST_STORE,
            VerificationPolicy::strict(),
            0,
        );
        let _ = env.verify_root_signed(
            ARTIFACT_DESCRIPTOR_PAYLOAD_TYPE,
            &TRUST_STORE,
            VerificationPolicy::ClassicalOnly { min_signatures: 1 },
            0,
        );
    }
});
