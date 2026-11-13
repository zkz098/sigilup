//! Update manifest schema, URL allowlists, key-pinning, and Sans-I/O evaluator for `sigilup`.

/// Sans-I/O update evaluation engine (SemVer, anti-rollback, anti-freeze, key rotation).
pub mod engine;
/// Error types returned by manifest verification and evaluation.
pub mod error;
/// Release manifest schema (`UpdateManifest`, `PlatformAsset`, `SignedManifest`).
pub mod manifest;
/// Key-pinning catalog (`sigilup-pins.json`) for CI guard and runtime policy sync.
pub mod pin;
/// Anti-rollback monotonic `security_epoch` storage backends.
pub mod store;
/// HTTPS / domain / path allowlist policy (`UrlPolicy`) for manifest & artifact URLs.
pub mod url_policy;

pub use engine::{
    AvailableUpdate, UpdateDecision, UpdateEvaluator, asset_key, current_platform_base,
};
pub use error::{Error, Result};
pub use manifest::{MANIFEST_PAYLOAD_TYPE, PlatformAsset, SignedManifest, UpdateManifest};
pub use pin::KeyPinFile;
pub use semver;
#[cfg(feature = "std")]
pub use store::FileEpochStore;
pub use store::MemoryEpochStore;
pub use url_policy::UrlPolicy;
