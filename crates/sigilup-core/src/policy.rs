/// Policy governing which signature algorithms and quorum counts are required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationPolicy {
    /// Require BOTH valid Ed25519 and valid ML-DSA-65 signatures (fail-closed).
    HybridStrict {
        /// Minimum number of distinct trusted keys that must sign the envelope.
        min_signatures: usize,
    },
    /// Require only valid Ed25519; if an ML-DSA-65 signature is present, still verify it
    /// and fail if invalid, but allow missing ML-DSA-65.
    TransitionalAllowMissingPqc {
        /// Minimum number of distinct trusted keys that must sign the envelope.
        min_signatures: usize,
    },
    /// Explicit classical-only verification (still rejects invalid ML-DSA-65 if attached).
    ClassicalOnly {
        /// Minimum number of distinct trusted keys that must sign the envelope.
        min_signatures: usize,
    },
}

impl VerificationPolicy {
    /// Default strict policy requiring 1 hybrid (Ed25519 + ML-DSA-65) signature.
    #[must_use]
    pub const fn strict() -> Self {
        Self::HybridStrict { min_signatures: 1 }
    }

    /// Quorum strict policy requiring `n` distinct hybrid signatures.
    #[must_use]
    pub const fn quorum(min_signatures: usize) -> Self {
        Self::HybridStrict { min_signatures }
    }

    /// Return the configured minimum signature threshold.
    #[must_use]
    pub const fn min_signatures(self) -> usize {
        match self {
            Self::HybridStrict { min_signatures }
            | Self::TransitionalAllowMissingPqc { min_signatures }
            | Self::ClassicalOnly { min_signatures } => min_signatures,
        }
    }
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

/// Runtime context for anti-rollback and anti-freeze checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyContext {
    /// Current Unix timestamp in seconds (`None` skips `expires_at` checks, e.g. offline mode).
    pub now_unix: Option<u64>,
    /// Allowed clock skew in seconds before rejecting an expired manifest.
    pub max_clock_skew_secs: u64,
    /// Minimum acceptable `security_epoch` (anti-rollback floor).
    pub min_security_epoch: u64,
}

impl Default for VerifyContext {
    fn default() -> Self {
        Self {
            now_unix: None,
            max_clock_skew_secs: 300,
            min_security_epoch: 0,
        }
    }
}

impl VerifyContext {
    /// Construct a verification context pinned to `now_unix` (with default 300s clock skew).
    #[must_use]
    pub const fn at_unix(now_unix: u64) -> Self {
        Self {
            now_unix: Some(now_unix),
            max_clock_skew_secs: 300,
            min_security_epoch: 0,
        }
    }

    /// Construct a verification context using the current system clock (`SystemTime::now()`).
    #[cfg(feature = "std")]
    #[must_use]
    pub fn now() -> Self {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self::at_unix(now_unix)
    }

    /// Override the minimum acceptable `security_epoch` (anti-rollback floor).
    #[must_use]
    pub const fn with_min_security_epoch(mut self, min_security_epoch: u64) -> Self {
        self.min_security_epoch = min_security_epoch;
        self
    }

    /// Override the allowed clock skew in seconds before rejecting an expired manifest.
    #[must_use]
    pub const fn with_max_clock_skew_secs(mut self, max_clock_skew_secs: u64) -> Self {
        self.max_clock_skew_secs = max_clock_skew_secs;
        self
    }
}
