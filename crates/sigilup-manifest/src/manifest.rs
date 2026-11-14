use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sigilup_core::{
    ArtifactDigest, HybridEnvelope, KeyRotationStatement, TrustStore, VerificationPolicy,
};

use crate::error::{Error, Result};

/// DSSE payload type for `sigilup` v2 update manifests.
pub const MANIFEST_PAYLOAD_TYPE: &str = "application/vnd.sigilup.manifest+json;v=2";

fn default_none<T>() -> Option<T> {
    None
}

/// One distributable artifact inside [`UpdateManifest::assets`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformAsset<M = serde_json::Value> {
    /// Distribution kind (e.g. `"portable"`, `"installer"`, `"appimage"`, `"tarball"`).
    pub kind: String,
    /// Download URL (validated against [`crate::UrlPolicy`] before fetching).
    pub url: String,
    /// Optional fallback/mirror download URLs tried in order if [`Self::url`] fails.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_urls: Vec<String>,
    /// Dual digest (`size`, `blake3`, `sha512`) of the exact artifact bytes.
    pub digest: ArtifactDigest,
    /// Optional host-defined metadata (kept extensible across projects).
    #[serde(default = "default_none", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<M>,
}

impl<M> PlatformAsset<M> {
    /// Iterate over [`Self::url`] followed by each entry in [`Self::fallback_urls`].
    pub fn all_urls(&self) -> impl Iterator<Item = &str> {
        core::iter::once(self.url.as_str()).chain(self.fallback_urls.iter().map(String::as_str))
    }
}

/// Self-update release manifest (schema v2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateManifest<M = serde_json::Value> {
    /// Manifest schema version (`2`).
    pub schema_version: u32,
    /// Strict SemVer release version.
    pub version: semver::Version,
    /// Monotonically non-decreasing security epoch (anti-rollback floor).
    pub security_epoch: u64,
    /// Optional minimum installed version permitted to auto-upgrade to this release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_supported_version: Option<semver::Version>,
    /// Unix timestamp (seconds) when the manifest was published.
    pub published_at: u64,
    /// Optional Unix timestamp after which this manifest must be treated as stale (anti-freeze).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Optional release notes / changelog body.
    #[serde(default)]
    pub notes: String,
    /// Map of `<os>-<arch>[-<channel>]` -> [`PlatformAsset`].
    #[serde(default = "BTreeMap::new")]
    pub assets: BTreeMap<String, PlatformAsset<M>>,
    /// Optional root-signed key rotation envelopes bundled with this release.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_rotations: Vec<HybridEnvelope>,
}

impl<M> UpdateManifest<M> {
    /// True when any asset key matches `platform_base` or `<platform_base>-*`.
    #[must_use]
    pub fn has_assets_for(&self, platform_base: &str) -> bool {
        let prefixed = format!("{platform_base}-");
        self.assets
            .keys()
            .any(|k| k == platform_base || k.starts_with(&prefixed))
    }
}

/// Self-contained signed manifest container (1 HTTP fetch contains manifest + all signatures).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedManifest {
    /// DSSEv1 hybrid signature envelope wrapping the serialized [`UpdateManifest`].
    pub envelope: HybridEnvelope,
}

impl SignedManifest {
    /// Serialize and sign an [`UpdateManifest`] into a self-contained [`SignedManifest`].
    #[cfg(feature = "sign")]
    pub fn sign<M: Serialize>(
        manifest: &UpdateManifest<M>,
        sk: &sigilup_core::SecretKeyBundle,
        created_at: u64,
    ) -> Result<Self> {
        let payload = serde_json::to_vec(manifest)?;
        let envelope = HybridEnvelope::sign(sk, MANIFEST_PAYLOAD_TYPE, &payload, created_at)?;
        Ok(Self { envelope })
    }

    /// Add an additional signature (for key-rotation dual signing or multi-party quorum).
    #[cfg(feature = "sign")]
    pub fn add_signature(
        &mut self,
        sk: &sigilup_core::SecretKeyBundle,
        created_at: u64,
    ) -> Result<()> {
        self.envelope.add_signature(sk, created_at)?;
        Ok(())
    }

    /// Verify signatures **before** parsing the JSON payload, applying any bundled
    /// root-signed [`KeyRotationStatement`]s if present.
    pub fn verify_and_decode<M: DeserializeOwned>(
        &self,
        trust_store: &mut TrustStore,
        policy: VerificationPolicy,
        current_epoch: u64,
    ) -> Result<UpdateManifest<M>> {
        let (verified, rotations_already_applied) =
            match self
                .envelope
                .verify(MANIFEST_PAYLOAD_TYPE, trust_store, policy, current_epoch)
            {
                Ok(v) => (v, false),
                Err(first_err) => {
                    // Attempt to extract unverified manifest ONLY to inspect `key_rotations`,
                    // each of which MUST itself be root-signed by an already-trusted root key!
                    let raw = self.envelope.decode_payload()?;
                    let candidate: UpdateManifest<M> = match serde_json::from_slice(&raw) {
                        Ok(parsed) => parsed,
                        Err(_) => return Err(Error::Core(first_err)),
                    };
                    if candidate.key_rotations.is_empty() {
                        return Err(Error::Core(first_err));
                    }
                    for rot_env in &candidate.key_rotations {
                        let rot_verified = rot_env.verify_root_signed(
                            sigilup_core::KEY_ROTATION_PAYLOAD_TYPE,
                            trust_store,
                            policy,
                            current_epoch,
                        )?;
                        let stmt: KeyRotationStatement =
                            serde_json::from_slice(&rot_verified.payload)?;
                        trust_store.apply_rotation(&stmt)?;
                    }
                    let verified = self.envelope.verify(
                        MANIFEST_PAYLOAD_TYPE,
                        trust_store,
                        policy,
                        current_epoch,
                    )?;
                    (verified, true)
                }
            };

        let manifest: UpdateManifest<M> = serde_json::from_slice(&verified.payload)?;
        if manifest.schema_version != 2 {
            return Err(Error::Core(sigilup_core::Error::UnsupportedVersion(
                manifest.schema_version,
            )));
        }
        if !rotations_already_applied && !manifest.key_rotations.is_empty() {
            for rot_env in &manifest.key_rotations {
                let rot_verified = rot_env.verify_root_signed(
                    sigilup_core::KEY_ROTATION_PAYLOAD_TYPE,
                    trust_store,
                    policy,
                    current_epoch,
                )?;
                let stmt: KeyRotationStatement = serde_json::from_slice(&rot_verified.payload)?;
                trust_store.apply_rotation(&stmt)?;
            }
        }
        Ok(manifest)
    }
}
