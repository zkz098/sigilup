use std::io::Read;

use sigilup_core::{
    ARTIFACT_DESCRIPTOR_PAYLOAD_TYPE, ArtifactDescriptor, ArtifactDigest, ArtifactHasher,
    HybridEnvelope, TrustStore, VerificationPolicy,
};

/// Errors from streaming artifact hashing, signing, and verification.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// Core cryptographic or envelope verification error.
    #[error(transparent)]
    Core(#[from] sigilup_core::Error),
    /// JSON serialization/deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// Underlying I/O error while reading stream.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

const STREAM_BUF_BYTES: usize = 64 * 1024;

/// Compute [`ArtifactDigest`] (`size`, `BLAKE3`, `SHA-512`) from any `Read` in O(1) memory.
pub fn hash_reader<R: Read>(mut reader: R) -> std::io::Result<ArtifactDigest> {
    let mut hasher = ArtifactHasher::new();
    let mut buf = [0u8; STREAM_BUF_BYTES];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
}

/// Stream `reader` once in O(1) memory and sign its [`ArtifactDescriptor`] into a [`HybridEnvelope`].
#[cfg(feature = "sign")]
pub fn sign_reader<R: Read>(
    reader: R,
    sk: &sigilup_core::SecretKeyBundle,
    name: Option<String>,
    created_at: u64,
) -> Result<HybridEnvelope, StreamError> {
    let digest = hash_reader(reader)?;
    let desc = ArtifactDescriptor::new(name, digest, created_at);
    let payload = serde_json::to_vec(&desc)?;
    Ok(HybridEnvelope::sign(
        sk,
        ARTIFACT_DESCRIPTOR_PAYLOAD_TYPE,
        &payload,
        created_at,
    )?)
}

/// Verify a detached `.hsig` [`HybridEnvelope`] against a streaming `reader` in O(1) memory.
///
/// Envelope signatures are verified **first**; only then is `reader` hashed in a single
/// 64 KiB pass and compared in constant time against the signed descriptor's `size`,
/// `blake3`, and `sha512`.
pub fn verify_reader<R: Read>(
    reader: R,
    envelope: &HybridEnvelope,
    trust_store: &TrustStore,
    policy: VerificationPolicy,
    current_epoch: u64,
) -> Result<ArtifactDescriptor, StreamError> {
    let verified = envelope.verify(
        ARTIFACT_DESCRIPTOR_PAYLOAD_TYPE,
        trust_store,
        policy,
        current_epoch,
    )?;
    let desc: ArtifactDescriptor = serde_json::from_slice(&verified.payload)?;
    if desc.version != 2 {
        return Err(StreamError::Core(sigilup_core::Error::UnsupportedVersion(
            desc.version,
        )));
    }
    let actual = hash_reader(reader)?;
    desc.digest.verify_matches(&actual)?;
    Ok(desc)
}
