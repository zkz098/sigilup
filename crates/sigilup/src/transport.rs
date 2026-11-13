use std::path::{Path, PathBuf};

use sigilup_core::{ArtifactHasher, EpochStore, VerifyContext};
use sigilup_manifest::{AvailableUpdate, SignedManifest, UpdateDecision, UpdateEvaluator};
use tokio::io::AsyncWriteExt as _;

/// Errors returned by the `reqwest` streaming update transport.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Manifest evaluation or policy error.
    #[error(transparent)]
    Manifest(#[from] sigilup_manifest::Error),
    /// Core cryptographic or digest error.
    #[error(transparent)]
    Core(#[from] sigilup_core::Error),
    /// HTTP transport error.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    /// JSON decoding error.
    #[error("json decode error: {0}")]
    Json(#[from] serde_json::Error),
    /// Filesystem I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// Payload exceeded configured maximum byte limit.
    #[error("download exceeded maximum allowed size of {max_bytes} bytes")]
    SizeLimitExceeded {
        /// Configured upper limit.
        max_bytes: u64,
    },
}

/// Async updater backed by `reqwest` that performs 1-request manifest checks and
/// single-pass streaming download + verification.
pub struct ReqwestUpdater {
    client: reqwest::Client,
    max_manifest_bytes: u64,
    max_artifact_bytes: u64,
}

impl ReqwestUpdater {
    /// Wrap an application-configured `reqwest::Client` (preserving caller's proxy, UA, and timeouts).
    #[must_use]
    pub const fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            max_manifest_bytes: 4 * 1024 * 1024,
            max_artifact_bytes: 512 * 1024 * 1024,
        }
    }

    /// Override maximum accepted manifest size in bytes (default: 4 MiB).
    #[must_use]
    pub const fn with_max_manifest_bytes(mut self, max_bytes: u64) -> Self {
        self.max_manifest_bytes = max_bytes;
        self
    }

    /// Override maximum accepted artifact size in bytes (default: 512 MiB).
    #[must_use]
    pub const fn with_max_artifact_bytes(mut self, max_bytes: u64) -> Self {
        self.max_artifact_bytes = max_bytes;
        self
    }

    /// Fetch the single self-contained [`SignedManifest`] and evaluate it with `evaluator`.
    pub async fn check_for_update<M, S>(
        &self,
        manifest_url: &str,
        evaluator: &mut UpdateEvaluator,
        epoch_store: &mut S,
        ctx: VerifyContext,
    ) -> Result<UpdateDecision<M>, TransportError>
    where
        M: serde::de::DeserializeOwned + Clone,
        S: EpochStore,
    {
        let resp = self
            .client
            .get(manifest_url)
            .send()
            .await?
            .error_for_status()?;

        if let Some(len) = resp.content_length()
            && len > self.max_manifest_bytes
        {
            return Err(TransportError::SizeLimitExceeded {
                max_bytes: self.max_manifest_bytes,
            });
        }

        let bytes = resp.bytes().await?;
        if bytes.len() as u64 > self.max_manifest_bytes {
            return Err(TransportError::SizeLimitExceeded {
                max_bytes: self.max_manifest_bytes,
            });
        }

        let signed: SignedManifest = serde_json::from_slice(&bytes)?;
        Ok(evaluator.evaluate(&signed, epoch_store, ctx)?)
    }

    /// Stream an update artifact to `dest_dir` while computing `BLAKE3 + SHA-512 + size`
    /// in flight (zero re-reading from disk), deleting the staging file if verification fails.
    pub async fn download_and_verify<M, F>(
        &self,
        update: &AvailableUpdate<M>,
        dest_dir: &Path,
        mut on_progress: F,
    ) -> Result<PathBuf, TransportError>
    where
        F: FnMut(u64, Option<u64>),
    {
        let expected_size = update.asset.digest.size;
        if expected_size > self.max_artifact_bytes {
            return Err(TransportError::SizeLimitExceeded {
                max_bytes: self.max_artifact_bytes,
            });
        }

        tokio::fs::create_dir_all(dest_dir).await?;
        let file_name = update
            .asset
            .url
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("sigilup-update.bin");
        let temp_path = dest_dir.join(format!("{file_name}.part"));
        let final_path = dest_dir.join(file_name);

        let mut resp = self
            .client
            .get(&update.asset.url)
            .send()
            .await?
            .error_for_status()?;

        let total = resp.content_length();
        if let Some(len) = total
            && (len > self.max_artifact_bytes || len != expected_size)
        {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(if len > self.max_artifact_bytes {
                TransportError::SizeLimitExceeded {
                    max_bytes: self.max_artifact_bytes,
                }
            } else {
                TransportError::Core(sigilup_core::Error::DigestMismatch(
                    "content-length differs from signed manifest size",
                ))
            });
        }

        let mut file = tokio::fs::File::create(&temp_path).await?;
        let mut hasher = ArtifactHasher::new();

        while let Some(chunk) = resp.chunk().await? {
            let next_total = hasher.bytes_hashed().saturating_add(chunk.len() as u64);
            if next_total > self.max_artifact_bytes || next_total > expected_size {
                drop(file);
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(if next_total > self.max_artifact_bytes {
                    TransportError::SizeLimitExceeded {
                        max_bytes: self.max_artifact_bytes,
                    }
                } else {
                    TransportError::Core(sigilup_core::Error::DigestMismatch(
                        "stream exceeded signed manifest size",
                    ))
                });
            }
            file.write_all(&chunk).await?;
            hasher.update(&chunk);
            on_progress(hasher.bytes_hashed(), total.or(Some(expected_size)));
        }
        file.flush().await?;
        drop(file);

        let actual_digest = hasher.finalize();
        if let Err(err) = update.asset.digest.verify_matches(&actual_digest) {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(TransportError::Core(err));
        }

        tokio::fs::rename(&temp_path, &final_path).await?;
        Ok(final_path)
    }
}
