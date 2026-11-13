#![no_main]

use std::str::FromStr;
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use sigilup_core::{ArtifactDigest, KeyId, PublicKeyBundle, SecretKeyBundle};
use sigilup_manifest::KeyPinFile;

static SIGNING_KEY: LazyLock<SecretKeyBundle> = LazyLock::new(|| {
    SecretKeyBundle::from_seeds([0x55; 32], [0x66; 32])
        .expect("deterministic seed key derivation")
});

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = PublicKeyBundle::from_compact_str(s);
        let _ = KeyId::from_str(s);
        if let Ok(pins) = KeyPinFile::from_json_str(s) {
            let _ = pins.to_trust_store();
            let _ = pins.verify_signing_key(&SIGNING_KEY);
        }
    }
    let _ = serde_json::from_slice::<ArtifactDigest>(data);
});
