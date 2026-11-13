#![no_main]

use libfuzzer_sys::fuzz_target;
use sigilup_core::{ArtifactHasher, pae_encode};

fuzz_target!(|data: &[u8]| {
    // Exercise PAE framing on arbitrary split points.
    let split = data.first().map(|b| (*b as usize) % (data.len() + 1)).unwrap_or(0);
    let (lhs, rhs) = data.split_at(split);
    if let Ok(payload_type) = std::str::from_utf8(lhs) {
        let encoded = pae_encode(payload_type, rhs);
        assert!(encoded.starts_with(b"DSSEv1 "));
    }

    // Streaming chunked digest must always equal single-pass digest.
    let oneshot = ArtifactHasher::hash_bytes(data);
    let mut hasher = ArtifactHasher::new();
    let chunk_size = data.first().map(|b| (*b as usize).max(1)).unwrap_or(1);
    for chunk in data.chunks(chunk_size) {
        hasher.update(chunk);
    }
    let chunked = hasher.finalize();
    assert_eq!(oneshot, chunked);
    assert!(oneshot.verify_matches(&chunked).is_ok());
});
