use sigilup_core::{EpochStore, Result};

/// In-memory [`EpochStore`] for tests and stateless/ephemeral runs.
#[derive(Debug, Default, Clone)]
pub struct MemoryEpochStore {
    epoch: u64,
}

impl MemoryEpochStore {
    /// Create an in-memory store seeded with `initial_epoch`.
    #[must_use]
    pub const fn new(initial_epoch: u64) -> Self {
        Self {
            epoch: initial_epoch,
        }
    }
}

impl EpochStore for MemoryEpochStore {
    fn load_min_epoch(&self) -> Result<u64> {
        Ok(self.epoch)
    }

    fn save_min_epoch(&mut self, epoch: u64) -> Result<()> {
        if epoch > self.epoch {
            self.epoch = epoch;
        }
        Ok(())
    }
}

/// Crash-safe file-backed [`EpochStore`] persisting the highest observed `security_epoch`.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct FileEpochStore {
    path: std::path::PathBuf,
}

#[cfg(feature = "std")]
impl FileEpochStore {
    /// Create a store backed by `path` (e.g. `<state_dir>/sigilup-epoch`).
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[cfg(feature = "std")]
impl EpochStore for FileEpochStore {
    fn load_min_epoch(&self) -> Result<u64> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => text
                .trim()
                .parse::<u64>()
                .map_err(|_| sigilup_core::Error::InvalidEncoding("corrupt epoch file")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(sigilup_core::Error::PolicyRejected(format!(
                "read epoch file: {e}"
            ))),
        }
    }

    fn save_min_epoch(&mut self, epoch: u64) -> Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                sigilup_core::Error::PolicyRejected(format!("create epoch dir: {e}"))
            })?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, format!("{epoch}\n")).map_err(|e| {
            sigilup_core::Error::PolicyRejected(format!("write temp epoch file: {e}"))
        })?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| sigilup_core::Error::PolicyRejected(format!("commit epoch file: {e}")))?;
        Ok(())
    }
}
