use std::path::{Path, PathBuf};

use sigilup_core::{ArtifactHasher, EpochStore, VerifyContext};
use sigilup_manifest::{AvailableUpdate, SignedManifest, UpdateDecision, UpdateEvaluator};

#[cfg(feature = "reqwest")]
use tokio::io::AsyncWriteExt as _;

const DEFAULT_MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(feature = "blocking")]
const STREAM_BUF_BYTES: usize = 64 * 1024;

/// Errors returned by the update transport (`reqwest` async or `ureq` blocking).
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Manifest evaluation or policy error.
    #[error(transparent)]
    Manifest(#[from] sigilup_manifest::Error),
    /// Core cryptographic or digest error.
    #[error(transparent)]
    Core(#[from] sigilup_core::Error),
    /// Async HTTP transport error (`reqwest`).
    #[cfg(feature = "reqwest")]
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    /// Blocking HTTP transport error (`ureq`).
    #[cfg(feature = "blocking")]
    #[error("http error: {0}")]
    BlockingHttp(#[from] Box<ureq::Error>),
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
    /// Caller passed an empty list of manifest URLs.
    #[error("no manifest URLs provided")]
    EmptyUrlList,
}

#[cfg(feature = "blocking")]
impl From<ureq::Error> for TransportError {
    fn from(err: ureq::Error) -> Self {
        Self::BlockingHttp(Box::new(err))
    }
}

fn derive_file_name(url: &str) -> &str {
    url.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("sigilup-update.bin")
}

const fn validate_manifest_len(len: u64, max_bytes: u64) -> Result<(), TransportError> {
    if len > max_bytes {
        return Err(TransportError::SizeLimitExceeded { max_bytes });
    }
    Ok(())
}

fn validate_artifact_content_length(
    len: Option<u64>,
    expected_size: u64,
    max_bytes: u64,
) -> Result<(), TransportError> {
    if let Some(len) = len
        && (len > max_bytes || len != expected_size)
    {
        return Err(if len > max_bytes {
            TransportError::SizeLimitExceeded { max_bytes }
        } else {
            TransportError::Core(sigilup_core::Error::DigestMismatch(
                "content-length differs from signed manifest size",
            ))
        });
    }
    Ok(())
}

fn validate_chunk_bounds(
    next_total: u64,
    expected_size: u64,
    max_bytes: u64,
) -> Result<(), TransportError> {
    if next_total > max_bytes || next_total > expected_size {
        return Err(if next_total > max_bytes {
            TransportError::SizeLimitExceeded { max_bytes }
        } else {
            TransportError::Core(sigilup_core::Error::DigestMismatch(
                "stream exceeded signed manifest size",
            ))
        });
    }
    Ok(())
}

/// Async updater backed by `reqwest` that performs 1-request manifest checks and
/// single-pass streaming download + verification.
#[cfg(feature = "reqwest")]
pub struct ReqwestUpdater {
    client: reqwest::Client,
    max_manifest_bytes: u64,
    max_artifact_bytes: u64,
}

#[cfg(feature = "reqwest")]
impl ReqwestUpdater {
    /// Wrap an application-configured `reqwest::Client` (preserving caller's proxy, UA, and timeouts).
    #[must_use]
    pub const fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            max_manifest_bytes: DEFAULT_MAX_MANIFEST_BYTES,
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
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
        self.check_for_update_any(&[manifest_url], evaluator, epoch_store, ctx)
            .await
    }

    /// Try `manifest_urls` in order (e.g. primary URL followed by mirror URLs) until one
    /// returns a valid [`SignedManifest`] JSON, then evaluate it fail-closed with `evaluator`.
    pub async fn check_for_update_any<M, S>(
        &self,
        manifest_urls: &[&str],
        evaluator: &mut UpdateEvaluator,
        epoch_store: &mut S,
        ctx: VerifyContext,
    ) -> Result<UpdateDecision<M>, TransportError>
    where
        M: serde::de::DeserializeOwned + Clone,
        S: EpochStore,
    {
        if manifest_urls.is_empty() {
            return Err(TransportError::EmptyUrlList);
        }

        let mut last_err = None;
        for &url in manifest_urls {
            match self.fetch_signed_manifest(url).await {
                Ok(signed) => return Ok(evaluator.evaluate(&signed, epoch_store, ctx)?),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or(TransportError::EmptyUrlList))
    }

    async fn fetch_signed_manifest(
        &self,
        manifest_url: &str,
    ) -> Result<SignedManifest, TransportError> {
        let resp = self
            .client
            .get(manifest_url)
            .send()
            .await?
            .error_for_status()?;

        if let Some(len) = resp.content_length() {
            validate_manifest_len(len, self.max_manifest_bytes)?;
        }

        let bytes = resp.bytes().await?;
        validate_manifest_len(bytes.len() as u64, self.max_manifest_bytes)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Stream an update artifact to `dest_dir` while computing `BLAKE3 + SHA-512 + size`
    /// in flight (zero re-reading from disk), automatically falling back through
    /// `update.asset.fallback_urls` on failure and deleting the staging file if verification fails.
    ///
    /// Note: if a fallback URL is tried after a partial download, `on_progress` restarts from `0`.
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
        let file_name = derive_file_name(&update.asset.url);
        let temp_path = dest_dir.join(format!("{file_name}.part"));
        let final_path = dest_dir.join(file_name);

        let mut last_err = None;
        for url in update.asset.all_urls() {
            match self
                .try_download_single(
                    url,
                    expected_size,
                    &update.asset.digest,
                    &temp_path,
                    &mut on_progress,
                )
                .await
            {
                Ok(()) => {
                    tokio::fs::rename(&temp_path, &final_path).await?;
                    return Ok(final_path);
                }
                Err(err) => {
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap_or(TransportError::EmptyUrlList))
    }

    async fn try_download_single<F>(
        &self,
        url: &str,
        expected_size: u64,
        expected_digest: &sigilup_core::ArtifactDigest,
        temp_path: &Path,
        on_progress: &mut F,
    ) -> Result<(), TransportError>
    where
        F: FnMut(u64, Option<u64>),
    {
        let mut resp = self.client.get(url).send().await?.error_for_status()?;
        let total = resp.content_length();
        validate_artifact_content_length(total, expected_size, self.max_artifact_bytes)?;

        let mut file = tokio::fs::File::create(temp_path).await?;
        let mut hasher = ArtifactHasher::new();

        while let Some(chunk) = resp.chunk().await? {
            let next_total = hasher.bytes_hashed().saturating_add(chunk.len() as u64);
            validate_chunk_bounds(next_total, expected_size, self.max_artifact_bytes)?;
            file.write_all(&chunk).await?;
            hasher.update(&chunk);
            on_progress(hasher.bytes_hashed(), total.or(Some(expected_size)));
        }
        file.flush().await?;
        drop(file);

        let actual_digest = hasher.finalize();
        expected_digest.verify_matches(&actual_digest)?;
        Ok(())
    }
}

/// Synchronous blocking updater backed by `ureq` (`rustls`, zero `tokio` dependency) that
/// performs 1-request manifest checks and single-pass streaming download + verification.
#[cfg(feature = "blocking")]
pub struct BlockingUpdater {
    agent: ureq::Agent,
    max_manifest_bytes: u64,
    max_artifact_bytes: u64,
}

#[cfg(feature = "blocking")]
impl Default for BlockingUpdater {
    fn default() -> Self {
        Self::new(ureq::Agent::new_with_defaults())
    }
}

#[cfg(feature = "blocking")]
impl BlockingUpdater {
    /// Wrap a caller-configured `ureq::Agent` (preserving proxy, timeouts, and TLS config).
    #[must_use]
    pub const fn new(agent: ureq::Agent) -> Self {
        Self {
            agent,
            max_manifest_bytes: DEFAULT_MAX_MANIFEST_BYTES,
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
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
    pub fn check_for_update<M, S>(
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
        self.check_for_update_any(&[manifest_url], evaluator, epoch_store, ctx)
    }

    /// Try `manifest_urls` in order (e.g. primary URL followed by mirror URLs) until one
    /// returns a valid [`SignedManifest`] JSON, then evaluate it fail-closed with `evaluator`.
    pub fn check_for_update_any<M, S>(
        &self,
        manifest_urls: &[&str],
        evaluator: &mut UpdateEvaluator,
        epoch_store: &mut S,
        ctx: VerifyContext,
    ) -> Result<UpdateDecision<M>, TransportError>
    where
        M: serde::de::DeserializeOwned + Clone,
        S: EpochStore,
    {
        if manifest_urls.is_empty() {
            return Err(TransportError::EmptyUrlList);
        }

        let mut last_err = None;
        for &url in manifest_urls {
            match self.fetch_signed_manifest(url) {
                Ok(signed) => return Ok(evaluator.evaluate(&signed, epoch_store, ctx)?),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or(TransportError::EmptyUrlList))
    }

    fn fetch_signed_manifest(&self, manifest_url: &str) -> Result<SignedManifest, TransportError> {
        use std::io::Read as _;

        let mut resp = self.agent.get(manifest_url).call()?;
        let content_len = resp
            .headers()
            .get(ureq::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        if let Some(len) = content_len {
            validate_manifest_len(len, self.max_manifest_bytes)?;
        }

        let limit = self.max_manifest_bytes.saturating_add(1);
        let mut reader = resp.body_mut().as_reader().take(limit);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        validate_manifest_len(bytes.len() as u64, self.max_manifest_bytes)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Stream an update artifact to `dest_dir` while computing `BLAKE3 + SHA-512 + size`
    /// in flight (zero re-reading from disk), automatically falling back through
    /// `update.asset.fallback_urls` on failure and deleting the staging file if verification fails.
    ///
    /// Note: if a fallback URL is tried after a partial download, `on_progress` restarts from `0`.
    pub fn download_and_verify<M, F>(
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

        std::fs::create_dir_all(dest_dir)?;
        let file_name = derive_file_name(&update.asset.url);
        let temp_path = dest_dir.join(format!("{file_name}.part"));
        let final_path = dest_dir.join(file_name);

        let mut last_err = None;
        for url in update.asset.all_urls() {
            match self.try_download_single(
                url,
                expected_size,
                &update.asset.digest,
                &temp_path,
                &mut on_progress,
            ) {
                Ok(()) => {
                    std::fs::rename(&temp_path, &final_path)?;
                    return Ok(final_path);
                }
                Err(err) => {
                    let _ = std::fs::remove_file(&temp_path);
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap_or(TransportError::EmptyUrlList))
    }

    fn try_download_single<F>(
        &self,
        url: &str,
        expected_size: u64,
        expected_digest: &sigilup_core::ArtifactDigest,
        temp_path: &Path,
        on_progress: &mut F,
    ) -> Result<(), TransportError>
    where
        F: FnMut(u64, Option<u64>),
    {
        use std::io::{Read as _, Write as _};

        let mut resp = self.agent.get(url).call()?;
        let total = resp
            .headers()
            .get(ureq::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        validate_artifact_content_length(total, expected_size, self.max_artifact_bytes)?;

        let mut file = std::fs::File::create(temp_path)?;
        let mut hasher = ArtifactHasher::new();
        let mut reader = resp.body_mut().as_reader();
        let mut buf = [0u8; STREAM_BUF_BYTES];

        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let next_total = hasher.bytes_hashed().saturating_add(n as u64);
            validate_chunk_bounds(next_total, expected_size, self.max_artifact_bytes)?;
            file.write_all(&buf[..n])?;
            hasher.update(&buf[..n]);
            on_progress(hasher.bytes_hashed(), total.or(Some(expected_size)));
        }
        file.flush()?;
        drop(file);

        let actual_digest = hasher.finalize();
        expected_digest.verify_matches(&actual_digest)?;
        Ok(())
    }
}
