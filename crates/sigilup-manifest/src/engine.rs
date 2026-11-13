use sigilup_core::{EpochStore, TrustStore, VerificationPolicy, VerifyContext};

use crate::error::{Error, Result};
use crate::manifest::{PlatformAsset, SignedManifest, UpdateManifest};
use crate::url_policy::UrlPolicy;

/// Returns the canonical `<os>-<arch>` platform base (`windows-x86_64`, `darwin-aarch64`, `linux-x86_64`, etc.).
#[must_use]
pub fn current_platform_base() -> String {
    let os = match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "darwin",
        other => other,
    };
    format!("{os}-{}", std::env::consts::ARCH)
}

/// Returns `<os>-<arch>` or `<os>-<arch>-<channel>` when `channel` is `Some`.
#[must_use]
pub fn asset_key(platform_base: &str, channel: Option<&str>) -> String {
    match channel {
        Some(ch) if !ch.is_empty() => format!("{platform_base}-{ch}"),
        _ => platform_base.to_string(),
    }
}

/// Verified update candidate returned by [`UpdateEvaluator::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableUpdate<M = serde_json::Value> {
    /// New release version.
    pub version: semver::Version,
    /// Security epoch of the manifest.
    pub security_epoch: u64,
    /// Release notes / changelog.
    pub notes: String,
    /// Asset key matched in the manifest.
    pub asset_key: String,
    /// Verified asset metadata (URL + BLAKE3/SHA-512 digest + byte length).
    pub asset: PlatformAsset<M>,
}

/// Outcome of evaluating a [`SignedManifest`] against the running application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateDecision<M = serde_json::Value> {
    /// Already running the newest (or newer) version, or release has no assets for this OS/arch.
    UpToDate,
    /// A newer verified update is available for this platform + channel.
    UpdateAvailable(Box<AvailableUpdate<M>>),
}

/// Sans-I/O evaluator enforcing signature verification, anti-rollback, anti-freeze,
/// SemVer comparison, channel selection, and URL policy.
#[derive(Debug, Clone)]
pub struct UpdateEvaluator {
    /// Trusted public keys and revocation state.
    pub trust_store: TrustStore,
    /// Signature verification policy (default: strict Ed25519 + ML-DSA-65).
    pub verification_policy: VerificationPolicy,
    /// Allowed download URL rules.
    pub url_policy: UrlPolicy,
    /// Currently installed application version.
    pub current_version: semver::Version,
    /// Platform base key (defaults to [`current_platform_base`]).
    pub platform_base: String,
    /// Optional distribution channel suffix (e.g. `Some("portable")` or `None`).
    pub channel: Option<String>,
    /// Optional expected `asset.kind` (e.g. `Some("portable")`).
    pub expected_kind: Option<String>,
}

impl UpdateEvaluator {
    /// Create an evaluator for `current_version` on the current OS/arch.
    #[must_use]
    pub fn new(trust_store: TrustStore, current_version: semver::Version) -> Self {
        Self {
            trust_store,
            verification_policy: VerificationPolicy::strict(),
            url_policy: UrlPolicy::default(),
            current_version,
            platform_base: current_platform_base(),
            channel: None,
            expected_kind: None,
        }
    }

    /// Set verification policy.
    #[must_use]
    pub const fn with_policy(mut self, policy: VerificationPolicy) -> Self {
        self.verification_policy = policy;
        self
    }

    /// Set URL allowlist policy.
    #[must_use]
    pub fn with_url_policy(mut self, url_policy: UrlPolicy) -> Self {
        self.url_policy = url_policy;
        self
    }

    /// Set distribution channel suffix (e.g. `"portable"`).
    #[must_use]
    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = Some(channel.into());
        self
    }

    /// Enforce an expected `asset.kind` value.
    #[must_use]
    pub fn with_expected_kind(mut self, kind: impl Into<String>) -> Self {
        self.expected_kind = Some(kind.into());
        self
    }

    /// Verify `signed_manifest`, enforce anti-rollback / anti-freeze checks, persist
    /// any newly observed `security_epoch`, and decide whether an update applies.
    pub fn evaluate<M, S>(
        &mut self,
        signed_manifest: &SignedManifest,
        epoch_store: &mut S,
        ctx: VerifyContext,
    ) -> Result<UpdateDecision<M>>
    where
        M: serde::de::DeserializeOwned + Clone,
        S: EpochStore,
    {
        let stored_min_epoch = epoch_store.load_min_epoch().map_err(Error::Core)?;
        let min_epoch = stored_min_epoch.max(ctx.min_security_epoch);

        let manifest: UpdateManifest<M> = signed_manifest.verify_and_decode(
            &mut self.trust_store,
            self.verification_policy,
            min_epoch,
        )?;

        if manifest.security_epoch < min_epoch {
            return Err(Error::RollbackDetected {
                found: manifest.security_epoch,
                required: min_epoch,
            });
        }

        if let (Some(now), Some(expires_at)) = (ctx.now_unix, manifest.expires_at)
            && now > expires_at.saturating_add(ctx.max_clock_skew_secs)
        {
            return Err(Error::ManifestExpired { expires_at, now });
        }

        if manifest.security_epoch > stored_min_epoch {
            epoch_store
                .save_min_epoch(manifest.security_epoch)
                .map_err(Error::Core)?;
        }

        if manifest.version <= self.current_version {
            return Ok(UpdateDecision::UpToDate);
        }

        if let Some(min_supported) = &manifest.min_supported_version
            && &self.current_version < min_supported
        {
            return Err(Error::BelowMinSupportedVersion {
                current: self.current_version.clone(),
                min_supported: min_supported.clone(),
            });
        }

        let key = asset_key(&self.platform_base, self.channel.as_deref());
        let asset = match manifest.assets.get(&key) {
            Some(asset) => asset.clone(),
            None => {
                if !manifest.has_assets_for(&self.platform_base) {
                    return Ok(UpdateDecision::UpToDate);
                }
                return Err(Error::MissingChannelAsset {
                    version: manifest.version,
                    platform_base: self.platform_base.clone(),
                    requested_key: key,
                });
            }
        };

        if let Some(expected_kind) = &self.expected_kind
            && &asset.kind != expected_kind
        {
            return Err(Error::Validation(format!(
                "asset '{key}' has kind '{}', expected '{expected_kind}'",
                asset.kind
            )));
        }

        self.url_policy.validate(&asset.url)?;

        Ok(UpdateDecision::UpdateAvailable(Box::new(AvailableUpdate {
            version: manifest.version,
            security_epoch: manifest.security_epoch,
            notes: manifest.notes,
            asset_key: key,
            asset,
        })))
    }
}
