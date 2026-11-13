//! Sans-I/O cryptographic core for `sigilup`.
//!
//! Provides hybrid **Ed25519 + ML-DSA-65 (FIPS 204)** signatures bound via DSSEv1
//! Pre-Authentication Encoding (`pae`), single-pass streaming **BLAKE3 + SHA-512**
//! artifact digests, explicit [`VerificationPolicy`] enforcement, key rotation
//! statements, and Argon2id + XChaCha20 + BLAKE3-MAC encrypted secret keys.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

/// Single-pass `BLAKE3 + SHA-512` streaming artifact hasher and descriptor types.
pub mod digest;
/// Self-contained hybrid `Ed25519 + ML-DSA-65` DSSEv1 envelope types and verification.
pub mod envelope;
/// Core error types returned across `sigilup`.
pub mod error;
/// Key bundles, encrypted secret-key persistence, trust stores, and key rotation statements.
pub mod keys;
/// DSSEv1 Pre-Authentication Encoding (`PAE`) framing.
pub mod pae;
/// Explicit verification policy and timestamp/threshold enforcement.
pub mod policy;
/// Sans-I/O extension traits (`EpochStore`, `SignerBackend`).
pub mod traits;

pub use digest::{
    ARTIFACT_DESCRIPTOR_PAYLOAD_TYPE, ArtifactDescriptor, ArtifactDigest, ArtifactHasher,
};
pub use envelope::{HybridEnvelope, SignatureEntry, VerifiedEnvelope};
pub use error::{Error, Result};
#[cfg(feature = "sign")]
pub use keys::SecretKeyBundle;
pub use keys::{
    KEY_ROTATION_PAYLOAD_TYPE, KeyId, KeyRotationStatement, ML_DSA_DSSE_CONTEXT, PublicKeyBundle,
    TrustStore,
};
pub use pae::pae_encode;
pub use policy::{VerificationPolicy, VerifyContext};
pub use traits::{EpochStore, SignerBackend};
