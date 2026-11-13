#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use sigilup_core::{PublicKeyBundle, SecretKeyBundle, TrustStore, VerificationPolicy};
use sigilup_manifest::SignedManifest;

static ROOT_KEY: LazyLock<PublicKeyBundle> = LazyLock::new(|| {
    let sk = SecretKeyBundle::from_seeds([0x33; 32], [0x44; 32])
        .expect("deterministic seed key derivation");
    sk.public_key().clone().with_root(true)
});

fuzz_target!(|data: &[u8]| {
    if let Ok(signed) = serde_json::from_slice::<SignedManifest>(data) {
        let mut store = TrustStore::from_keys([ROOT_KEY.clone()]);
        let _ = signed.verify_and_decode::<serde_json::Value>(
            &mut store,
            VerificationPolicy::strict(),
            1,
        );
    }
});
