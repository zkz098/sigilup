/// Errors returned by `sigilup-manifest`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Core cryptographic or envelope verification error.
    #[error(transparent)]
    Core(#[from] sigilup_core::Error),

    /// JSON serialization or deserialization error.
    #[error("manifest json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid URL syntax or policy violation.
    #[error("url policy rejected '{url}': {reason}")]
    UrlRejected {
        /// Rejected URL string.
        url: String,
        /// Reason for rejection.
        reason: &'static str,
    },

    /// Rollback attempt detected (`manifest.security_epoch < min_security_epoch`).
    #[error("rollback rejected: manifest security_epoch {found} < required minimum {required}")]
    RollbackDetected {
        /// Epoch inside the signed manifest.
        found: u64,
        /// Minimum accepted epoch.
        required: u64,
    },

    /// Freeze/stale manifest rejected (`now > expires_at + skew`).
    #[error("manifest expired at unix timestamp {expires_at} (current {now})")]
    ManifestExpired {
        /// Expiration timestamp on the signed manifest.
        expires_at: u64,
        /// Current Unix timestamp.
        now: u64,
    },

    /// Manifest declared a newer version that requires manual upgrade from an older floor.
    #[error("current version {current} is below min_supported_version {min_supported}")]
    BelowMinSupportedVersion {
        /// Running application version.
        current: semver::Version,
        /// Minimum version allowed to auto-update to this release.
        min_supported: semver::Version,
    },

    /// Requested distribution channel is missing while other assets for this OS/arch exist.
    #[error(
        "platform '{platform_base}' exists in release v{version}, but channel key '{requested_key}' is missing"
    )]
    MissingChannelAsset {
        /// Manifest version.
        version: semver::Version,
        /// OS/arch prefix.
        platform_base: String,
        /// Full requested asset key.
        requested_key: String,
    },

    /// Artifact asset failed URL/kind validation or pinning guard.
    #[error("validation error: {0}")]
    Validation(String),

    /// Persistence I/O error (epoch store / pin file).
    #[cfg(feature = "std")]
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience result alias for `sigilup-manifest`.
pub type Result<T> = core::result::Result<T, Error>;
