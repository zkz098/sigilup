use std::fs;
use std::io::{BufReader, Read as _};
use std::path::{Path, PathBuf};

/// Errors during portable archive extraction or executable self-replacement.
#[derive(Debug, thiserror::Error)]
pub enum ReplaceError {
    /// Running inside a read-only mounted AppImage bundle on Linux.
    #[error("running inside an AppImage; in-place self-replacement is not supported")]
    AppImageUnsupported,
    /// No matching executable found inside the archive.
    #[error("archive '{archive}' contains no executable matching '{expected}'")]
    ExecutableNotFound {
        /// Archive path.
        archive: PathBuf,
        /// Target executable filename.
        expected: String,
    },
    /// Extracted payload exceeded safety limit.
    #[error("extracted executable exceeded max allowed size of {0} bytes")]
    OversizedExecutable(u64),
    /// Caller supplied an unsafe executable filename (e.g. path traversal).
    #[error("invalid executable filename '{0}'")]
    InvalidExecutableName(String),
    /// Self-replacement OS error.
    #[error("self-replace failed: {0}")]
    SelfReplace(String),
    /// macOS `codesign` failed after replacing bundle binary.
    #[error("macos ad-hoc codesign failed: {0}")]
    Codesign(String),
    /// Zip archive error.
    #[error("zip archive error: {0}")]
    Zip(#[from] zip::result::ZipError),
    /// Underlying I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Supported portable archive container formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    /// `.zip` archive (searches for `<exe_name>` or first `*.exe`).
    Zip,
    /// `.tar.gz` / `.tgz` archive (searches by `file_name() == exe_name`).
    TarGz,
    /// Plain uncompressed executable binary already on disk.
    RawBinary,
}

impl ArchiveFormat {
    /// Infer archive format from file extension.
    #[must_use]
    pub fn from_path(path: &Path) -> Self {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if name.ends_with(".zip") {
            Self::Zip
        } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            Self::TarGz
        } else {
            Self::RawBinary
        }
    }
}

/// Extract `exe_name` from a verified archive into `staging_dir` and atomically
/// replace the currently running executable via `self-replace`.
///
/// Handles Linux `APPIMAGE` detection, Unix `0o700` permissions, and macOS `.app`
/// bundle ad-hoc re-signing (`codesign --force --sign -`).
pub fn install_portable_update(
    verified_archive: &Path,
    staging_dir: &Path,
    exe_name: &str,
    max_exe_bytes: u64,
) -> Result<(), ReplaceError> {
    validate_exe_name(exe_name)?;

    #[cfg(target_os = "linux")]
    if std::env::var_os("APPIMAGE").is_some() {
        return Err(ReplaceError::AppImageUnsupported);
    }

    fs::create_dir_all(staging_dir)?;
    let format = ArchiveFormat::from_path(verified_archive);
    let extracted = match format {
        ArchiveFormat::RawBinary => verified_archive.to_path_buf(),
        ArchiveFormat::Zip => {
            extract_from_zip(verified_archive, staging_dir, exe_name, max_exe_bytes)?
        }
        ArchiveFormat::TarGz => {
            extract_from_targz(verified_archive, staging_dir, exe_name, max_exe_bytes)?
        }
    };

    self_replace::self_replace(&extracted).map_err(|e| ReplaceError::SelfReplace(e.to_string()))?;

    #[cfg(target_os = "macos")]
    resign_macos_app_bundle()?;

    if format != ArchiveFormat::RawBinary {
        let _ = fs::remove_file(&extracted);
    }
    Ok(())
}

fn extract_from_zip(
    archive_path: &Path,
    staging_dir: &Path,
    exe_name: &str,
    max_exe_bytes: u64,
) -> Result<PathBuf, ReplaceError> {
    let file = fs::File::open(archive_path)?;
    let mut zip = zip::ZipArchive::new(BufReader::new(file))?;
    let mut matched_idx = None;
    for i in 0..zip.len() {
        if let Some(Ok(name)) = zip.name_for_index(i) {
            let candidate = Path::new(name.as_ref())
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if candidate == exe_name {
                matched_idx = Some(i);
                break;
            }
        }
    }
    let idx = matched_idx.ok_or_else(|| ReplaceError::ExecutableNotFound {
        archive: archive_path.to_path_buf(),
        expected: exe_name.to_string(),
    })?;

    let mut entry = zip.by_index(idx)?;
    let out_path = staging_dir.join(exe_name);
    copy_bounded(&mut entry, &out_path, max_exe_bytes)?;
    set_owner_executable(&out_path)?;
    Ok(out_path)
}

fn extract_from_targz(
    archive_path: &Path,
    staging_dir: &Path,
    exe_name: &str,
    max_exe_bytes: u64,
) -> Result<PathBuf, ReplaceError> {
    let file = fs::File::open(archive_path)?;
    let gz = flate2::read::GzDecoder::new(BufReader::new(file));
    let mut tar = tar::Archive::new(gz);
    for entry_res in tar.entries()? {
        let mut entry = entry_res?;
        let path = entry.path()?.into_owned();
        if path.file_name().and_then(|s| s.to_str()) == Some(exe_name) {
            let out_path = staging_dir.join(exe_name);
            copy_bounded(&mut entry, &out_path, max_exe_bytes)?;
            set_owner_executable(&out_path)?;
            return Ok(out_path);
        }
    }
    Err(ReplaceError::ExecutableNotFound {
        archive: archive_path.to_path_buf(),
        expected: exe_name.to_string(),
    })
}

fn copy_bounded<R: std::io::Read>(
    src: &mut R,
    dest: &Path,
    max_bytes: u64,
) -> Result<(), ReplaceError> {
    let mut bounded = src.take(max_bytes.saturating_add(1));
    let mut out = fs::File::create(dest)?;
    let copied = std::io::copy(&mut bounded, &mut out)?;
    if copied > max_bytes {
        drop(out);
        let _ = fs::remove_file(dest);
        return Err(ReplaceError::OversizedExecutable(max_bytes));
    }
    Ok(())
}

#[cfg(unix)]
fn set_owner_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_owner_executable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn resign_macos_app_bundle() -> Result<(), ReplaceError> {
    let exe = std::env::current_exe()?;
    let Some(bundle) = exe
        .ancestors()
        .find(|p| p.extension().is_some_and(|ext| ext == "app"))
    else {
        return Ok(());
    };
    let output = std::process::Command::new("codesign")
        .args(["--force", "--sign", "-"])
        .arg(bundle)
        .output()?;
    if !output.status.success() {
        return Err(ReplaceError::Codesign(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(())
}

fn validate_exe_name(exe_name: &str) -> Result<(), ReplaceError> {
    if exe_name.is_empty()
        || exe_name == "."
        || exe_name == ".."
        || exe_name.contains(['/', '\\', '\0'])
    {
        return Err(ReplaceError::InvalidExecutableName(exe_name.to_string()));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn archive_format_detection() {
        assert_eq!(
            ArchiveFormat::from_path(Path::new("app-linux-x86_64.tar.gz")),
            ArchiveFormat::TarGz
        );
        assert_eq!(
            ArchiveFormat::from_path(Path::new("APP.TGZ")),
            ArchiveFormat::TarGz
        );
        assert_eq!(
            ArchiveFormat::from_path(Path::new("app-win.ZIP")),
            ArchiveFormat::Zip
        );
        assert_eq!(
            ArchiveFormat::from_path(Path::new("app-binary")),
            ArchiveFormat::RawBinary
        );
    }

    #[test]
    fn rejects_unsafe_exe_names() {
        assert!(matches!(
            validate_exe_name("../evil"),
            Err(ReplaceError::InvalidExecutableName(_))
        ));
        assert!(matches!(
            validate_exe_name(""),
            Err(ReplaceError::InvalidExecutableName(_))
        ));
    }

    #[test]
    fn extracts_executable_from_targz_and_enforces_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("release.tar.gz");
        let file = fs::File::create(&archive_path).unwrap();
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar_builder = tar::Builder::new(gz);

        let payload = b"#!/bin/sh\necho new-version\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "bin/my-app", &payload[..])
            .unwrap();
        let gz = tar_builder.into_inner().unwrap();
        gz.finish().unwrap();

        let staging = dir.path().join("stage");
        fs::create_dir_all(&staging).unwrap();

        let extracted = extract_from_targz(&archive_path, &staging, "my-app", 1024).unwrap();
        assert_eq!(fs::read(&extracted).unwrap(), payload);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&extracted).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }

        let oversized = extract_from_targz(&archive_path, &staging, "my-app", 5);
        assert!(matches!(
            oversized,
            Err(ReplaceError::OversizedExecutable(5))
        ));

        let missing = extract_from_targz(&archive_path, &staging, "other", 1024);
        assert!(matches!(
            missing,
            Err(ReplaceError::ExecutableNotFound { .. })
        ));
    }

    #[test]
    fn extracts_executable_from_zip() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("release.zip");
        let file = fs::File::create(&archive_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file(
                "nested/my-app.exe",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        let payload = b"MZ-dummy-binary";
        writer.write_all(payload).unwrap();
        writer.finish().unwrap();

        let staging = dir.path().join("stage-zip");
        fs::create_dir_all(&staging).unwrap();
        let extracted = extract_from_zip(&archive_path, &staging, "my-app.exe", 1024).unwrap();
        assert_eq!(fs::read(&extracted).unwrap(), payload);
    }
}
