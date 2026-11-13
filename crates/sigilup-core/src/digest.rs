use alloc::string::String;
use core::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha512};
use subtle::ConstantTimeEq as _;

use crate::error::{Error, Result};

/// DSSE payload type for detached artifact digest descriptors.
pub const ARTIFACT_DESCRIPTOR_PAYLOAD_TYPE: &str =
    "application/vnd.sigilup.artifact-descriptor+json;v=2";

/// Dual cryptographic digest + exact byte length of an artifact.
///
/// Computed in a single streaming pass over the input bytes:
/// - **BLAKE3** (256-bit): high-throughput SIMD verification and ecosystem interop.
/// - **SHA-512** (512-bit internal state): full 256-bit collision resistance aligned with
///   NIST Level 3 (ML-DSA-65) security.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactDigest {
    /// Exact artifact length in bytes.
    pub size: u64,
    /// Raw 32-byte BLAKE3 digest.
    pub blake3: [u8; 32],
    /// Raw 64-byte SHA-512 digest.
    pub sha512: [u8; 64],
}

impl ArtifactDigest {
    /// Verify that `other` matches `self` in byte length and both digests (constant-time).
    pub fn verify_matches(&self, other: &Self) -> Result<()> {
        if self.size != other.size {
            return Err(Error::DigestMismatch("byte length mismatch"));
        }
        let b3_eq = bool::from(self.blake3.ct_eq(&other.blake3));
        let s512_eq = bool::from(self.sha512.ct_eq(&other.sha512));
        if !b3_eq || !s512_eq {
            return Err(Error::DigestMismatch("hash mismatch"));
        }
        Ok(())
    }

    /// Lowercase hexadecimal representation of the BLAKE3 digest.
    #[must_use]
    pub fn blake3_hex(&self) -> String {
        encode_hex(&self.blake3)
    }

    /// Lowercase hexadecimal representation of the SHA-512 digest.
    #[must_use]
    pub fn sha512_hex(&self) -> String {
        encode_hex(&self.sha512)
    }
}

impl fmt::Debug for ArtifactDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtifactDigest")
            .field("size", &self.size)
            .field("blake3", &self.blake3_hex())
            .field("sha512", &self.sha512_hex())
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactDigestRepr {
    size: u64,
    blake3: String,
    sha512: String,
}

impl Serialize for ArtifactDigest {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        let repr = ArtifactDigestRepr {
            size: self.size,
            blake3: self.blake3_hex(),
            sha512: self.sha512_hex(),
        };
        repr.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ArtifactDigest {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        let repr = ArtifactDigestRepr::deserialize(deserializer)?;
        let blake3 = decode_hex_fixed::<32>(&repr.blake3).map_err(serde::de::Error::custom)?;
        let sha512 = decode_hex_fixed::<64>(&repr.sha512).map_err(serde::de::Error::custom)?;
        Ok(Self {
            size: repr.size,
            blake3,
            sha512,
        })
    }
}

/// Single-pass streaming hasher computing `size`, `BLAKE3`, and `SHA-512` simultaneously.
pub struct ArtifactHasher {
    size: u64,
    blake3: blake3::Hasher,
    sha512: Sha512,
}

impl Default for ArtifactHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactHasher {
    /// Create a fresh streaming hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            size: 0,
            blake3: blake3::Hasher::new(),
            sha512: Sha512::new(),
        }
    }

    /// Feed a chunk of bytes into the hasher.
    pub fn update(&mut self, chunk: &[u8]) {
        self.size = self.size.saturating_add(chunk.len() as u64);
        self.blake3.update(chunk);
        self.sha512.update(chunk);
    }

    /// Current total byte count fed so far.
    #[must_use]
    pub const fn bytes_hashed(&self) -> u64 {
        self.size
    }

    /// Finalize and produce the [`ArtifactDigest`].
    #[must_use]
    pub fn finalize(self) -> ArtifactDigest {
        let b3 = self.blake3.finalize();
        let s512 = self.sha512.finalize();
        let mut blake3 = [0u8; 32];
        blake3.copy_from_slice(b3.as_bytes());
        let mut sha512 = [0u8; 64];
        sha512.copy_from_slice(&s512);
        ArtifactDigest {
            size: self.size,
            blake3,
            sha512,
        }
    }

    /// Convenience one-shot helper for in-memory slices.
    #[must_use]
    pub fn hash_bytes(data: &[u8]) -> ArtifactDigest {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

#[cfg(feature = "std")]
impl std::io::Write for ArtifactHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Canonical descriptor signed inside detached artifact envelopes (`.hsig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactDescriptor {
    /// Descriptor schema version (currently `2`).
    pub version: u32,
    /// Optional artifact filename or label (informational).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Dual digest and byte length of the artifact.
    pub digest: ArtifactDigest,
    /// Unix timestamp (seconds) when signed.
    pub created_at: u64,
}

impl ArtifactDescriptor {
    /// Construct a new v2 descriptor.
    #[must_use]
    pub fn new(name: Option<String>, digest: ArtifactDigest, created_at: u64) -> Self {
        Self {
            version: 2,
            name,
            digest,
            created_at,
        }
    }
}

/// Encode bytes as lowercase hex.
#[must_use]
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a fixed-length hex string into `[u8; N]`.
pub(crate) fn decode_hex_fixed<const N: usize>(hex: &str) -> Result<[u8; N]> {
    let trimmed = hex.trim();
    if trimmed.len() != N * 2 {
        return Err(Error::InvalidEncoding("unexpected hex digest length"));
    }
    let bytes = trimmed.as_bytes();
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = hex_nibble(bytes[2 * i])?;
        let lo = hex_nibble(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::InvalidEncoding("invalid hex character")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn single_pass_matches_chunked_updates() {
        let data = b"sigilup streaming digest check payload".repeat(256);
        let one_shot = ArtifactHasher::hash_bytes(&data);

        let mut chunked = ArtifactHasher::new();
        for chunk in data.chunks(137) {
            chunked.update(chunk);
        }
        let streaming = chunked.finalize();

        assert!(one_shot.verify_matches(&streaming).is_ok());
        assert_eq!(streaming.size, data.len() as u64);
    }

    #[test]
    fn digest_serde_round_trip() {
        let digest = ArtifactHasher::hash_bytes(b"hello");
        let json = serde_json::to_string(&digest).unwrap();
        let parsed: ArtifactDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(digest, parsed);
    }
}
