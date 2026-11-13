use alloc::string::String;

/// Errors returned by `sigilup-core` cryptographic and envelope operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Envelope or key version is unsupported.
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u32),

    /// Input string or binary encoding is malformed.
    #[error("invalid encoding: {0}")]
    InvalidEncoding(&'static str),

    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(base64::DecodeError),

    /// JSON serialization or deserialization failed.
    #[error("json error: {0}")]
    Json(serde_json::Error),

    /// Unexpected payload type in DSSE envelope.
    #[error("unexpected payload type: expected '{expected}', got '{actual}'")]
    PayloadTypeMismatch {
        /// Expected DSSE payload type.
        expected: &'static str,
        /// Actual DSSE payload type found in the envelope.
        actual: String,
    },

    /// Classical Ed25519 signature verification failed.
    #[error("ed25519 signature verification failed for key {0}")]
    InvalidEd25519Signature(String),

    /// Post-quantum ML-DSA-65 signature verification failed.
    #[error("ml-dsa-65 signature verification failed for key {0}")]
    InvalidMlDsaSignature(String),

    /// Missing mandatory post-quantum signature under strict policy.
    #[error("missing required ml-dsa-65 signature for key {0}")]
    MissingMlDsaSignature(String),

    /// Signing key ID is not trusted or has been revoked.
    #[error("untrusted or revoked key {0}")]
    UntrustedKey(String),

    /// Key expired at an earlier security epoch.
    #[error(
        "key {key_id} expired after security epoch {not_after_epoch} (current epoch {current_epoch})"
    )]
    KeyExpired {
        /// Key ID that expired.
        key_id: String,
        /// Last epoch the key was valid for.
        not_after_epoch: u64,
        /// Observed security epoch.
        current_epoch: u64,
    },

    /// Fewer valid signatures were present than required by policy.
    #[error("insufficient valid signatures: required {required}, verified {verified}")]
    InsufficientSignatures {
        /// Minimum signatures required by policy.
        required: usize,
        /// Number of valid signatures found.
        verified: usize,
    },

    /// Artifact digest or byte length did not match the signed descriptor.
    #[error("artifact digest mismatch: {0}")]
    DigestMismatch(&'static str),

    /// Key decryption failed (wrong password or corrupted ciphertext).
    #[error("secret key decryption failed: {0}")]
    DecryptionFailed(&'static str),

    /// Signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(&'static str),

    /// Anti-rollback or anti-freeze policy violation.
    #[error("policy check failed: {0}")]
    PolicyRejected(String),
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Self::Base64(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

/// Convenience result alias for `sigilup-core`.
pub type Result<T> = core::result::Result<T, Error>;
