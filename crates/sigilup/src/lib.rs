//! Unified facade for `sigilup` — post-quantum hybrid (`Ed25519 + ML-DSA-65`)
//! self-update and artifact signing framework.
//!
//! - [`core`]: Sans-I/O cryptographic primitives (`HybridEnvelope`, `TrustStore`, `ArtifactHasher`).
//! - [`manifest`]: Self-contained `SignedManifest`, `UpdateEvaluator` (SemVer + anti-rollback/freeze),
//!   `UrlPolicy`, and `KeyPinFile`.
//! - [`stream`]: O(1)-memory single-pass streaming sign/verify helpers.
//! - `transport` (`feature = "reqwest"` or `feature = "blocking"`): 1-RTT manifest check & in-flight verified download.
//! - `replace` (`feature = "self-replace"`): cross-platform portable binary replacement.

pub use sigilup_core as core;
pub use sigilup_manifest as manifest;

/// O(1)-memory single-pass `BLAKE3 + SHA-512` streaming signing and verification helpers.
#[cfg(feature = "std")]
pub mod stream;

/// HTTP manifest fetcher and in-flight verified downloader (`reqwest` async and/or `ureq` blocking).
#[cfg(any(feature = "reqwest", feature = "blocking"))]
pub mod transport;

/// Portable binary/archive extraction and atomic `self-replace` installer.
#[cfg(feature = "self-replace")]
pub mod replace;

#[cfg(feature = "sign")]
pub use sigilup_core::SecretKeyBundle;
pub use sigilup_core::{
    ArtifactDescriptor, ArtifactDigest, ArtifactHasher, EpochStore, HybridEnvelope, KeyId,
    KeyRotationStatement, PublicKeyBundle, TrustStore, VerificationPolicy, VerifyContext,
};
pub use sigilup_manifest::{
    AvailableUpdate, KeyPinFile, PlatformAsset, SignedManifest, UpdateDecision, UpdateEvaluator,
    UpdateManifest, UrlPolicy, semver,
};
