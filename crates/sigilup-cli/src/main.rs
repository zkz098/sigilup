//! CLI tool for `sigilup`: key generation, streaming signing/verification,
//! self-contained manifest generation, key rotation, and CI pinning guards.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use sigilup::core::{
    HybridEnvelope, KEY_ROTATION_PAYLOAD_TYPE, KeyId, KeyRotationStatement, PublicKeyBundle,
    SecretKeyBundle, TrustStore, VerificationPolicy,
};
use sigilup::manifest::{KeyPinFile, PlatformAsset, SignedManifest, UpdateManifest};
use sigilup::stream::{hash_reader, sign_reader, verify_reader};

const DEFAULT_KEY_ENV: &str = "SIGILUP_SIGNING_KEY";
const DEFAULT_PASSWORD_ENV: &str = "SIGILUP_SIGNING_KEY_PASSWORD";

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Core(#[from] sigilup::core::Error),
    #[error(transparent)]
    Manifest(#[from] sigilup::manifest::Error),
    #[error(transparent)]
    Stream(#[from] sigilup::stream::StreamError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("semver parse error: {0}")]
    Semver(#[from] semver::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Message(String),
}

type Result<T> = std::result::Result<T, CliError>;

#[derive(Parser)]
#[command(
    name = "sigilup",
    about = "Hybrid Ed25519 + ML-DSA-65 self-update signing, manifest, and guard CLI",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a hybrid Ed25519 + ML-DSA-65 keypair and starter `sigilup-pins.json`.
    Keygen {
        /// Output directory for key files.
        #[arg(long)]
        out_dir: PathBuf,
        /// Base filename prefix.
        #[arg(long, default_value = "sigilup-signing")]
        name: String,
        /// Optional label embedded in public metadata.
        #[arg(long)]
        label: Option<String>,
        /// Mark this key as a root key capable of authorizing key rotations.
        #[arg(long)]
        root: bool,
        /// Optional maximum security epoch this key is valid for.
        #[arg(long)]
        not_after_epoch: Option<u64>,
        /// Password to encrypt `<name>.sk.json`. If omitted, writes unencrypted raw CI seed only when `--unencrypted` is set.
        #[arg(long)]
        password: Option<String>,
        /// Allow writing raw unencrypted `sigilup-sk:v2:` seed file (for CI secret import).
        #[arg(long)]
        unencrypted: bool,
        /// Overwrite existing files.
        #[arg(long)]
        force: bool,
    },
    /// Stream-sign files into unified `<file>.hsig` DSSE envelopes.
    Sign {
        /// Files to sign.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Path to encrypted `.sk.json` or raw `sigilup-sk:v2:` key file / literal string.
        #[arg(long, env = DEFAULT_KEY_ENV)]
        key: String,
        /// Password for encrypted `.sk.json` key.
        #[arg(long, env = DEFAULT_PASSWORD_ENV)]
        password: Option<String>,
    },
    /// Verify detached `<file>.hsig` envelopes in O(1) streaming memory.
    Verify {
        /// Original artifact files (looks for `<file>.hsig`).
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Path to `sigilup-pins.json` pin file.
        #[arg(long)]
        pins: Option<PathBuf>,
        /// Compact `sigilup-pk:v2:...` public key string.
        #[arg(long)]
        pubkey: Option<String>,
        /// Allow signatures missing ML-DSA-65 (transitional mode).
        #[arg(long)]
        allow_missing_pqc: bool,
    },
    /// Build and sign a self-contained v2 update manifest (`latest.hsig.json`).
    Manifest {
        /// SemVer release version (leading `v` is stripped if present).
        #[arg(long)]
        version: String,
        /// Monotonic security epoch (anti-rollback counter).
        #[arg(long)]
        epoch: u64,
        /// Optional manifest validity window in days from now (sets `expiresAt`).
        #[arg(long)]
        expires_in_days: Option<u64>,
        /// Optional minimum installed version permitted to auto-update.
        #[arg(long)]
        min_supported_version: Option<String>,
        /// Input asset map JSON: `{ "linux-x86_64": { "kind": "portable", "path": "...", "url": "...", "fallbackUrls": [...] } }`.
        #[arg(long, required_unless_present = "assets")]
        assets_json: Option<PathBuf>,
        /// Inline asset specification: `<KEY>=<KIND>:<PATH>:<URL>` (repeatable).
        #[arg(
            long = "asset",
            value_name = "KEY=KIND:PATH:URL",
            required_unless_present = "assets_json"
        )]
        assets: Vec<String>,
        /// Release notes string.
        #[arg(long, default_value = "", conflicts_with = "notes_file")]
        notes: String,
        /// Path to release notes file (e.g. `RELEASE_NOTES.md`).
        #[arg(long, conflicts_with = "notes")]
        notes_file: Option<PathBuf>,
        /// Output path for the signed manifest JSON.
        #[arg(long)]
        out_file: PathBuf,
        /// Signing key (file path or `sigilup-sk:v2:` string).
        #[arg(long, env = DEFAULT_KEY_ENV)]
        key: String,
        /// Password for encrypted `.sk.json` key.
        #[arg(long, env = DEFAULT_PASSWORD_ENV)]
        password: Option<String>,
    },
    /// Release guard: verify signing secret matches `sigilup-pins.json` and re-verify artifacts/manifest.
    Guard {
        /// Path to `sigilup-pins.json`.
        #[arg(long)]
        pins: PathBuf,
        /// Optional signed manifest JSON to verify.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Artifact files whose `.hsig` envelopes must verify.
        #[arg(required = false)]
        files: Vec<PathBuf>,
        /// Signing key (file path or `sigilup-sk:v2:` string).
        #[arg(long, env = DEFAULT_KEY_ENV)]
        key: String,
        /// Password for encrypted `.sk.json` key.
        #[arg(long, env = DEFAULT_PASSWORD_ENV)]
        password: Option<String>,
    },
    /// Issue a root-signed key rotation statement envelope.
    RotateKey {
        /// Rotation epoch (strictly increasing).
        #[arg(long)]
        rotation_epoch: u64,
        /// Root signing key (file path or `sigilup-sk:v2:` string).
        #[arg(long, env = DEFAULT_KEY_ENV)]
        root_key: String,
        /// Password for encrypted root key.
        #[arg(long, env = DEFAULT_PASSWORD_ENV)]
        password: Option<String>,
        /// New public key JSON files (`<name>.pk.json`) to add.
        #[arg(long = "add-pubkey-file")]
        add_pubkey_files: Vec<PathBuf>,
        /// Key IDs (16-char hex) to revoke.
        #[arg(long = "revoke")]
        revoke_ids: Vec<String>,
        /// Output path for signed rotation envelope JSON.
        #[arg(long)]
        out_file: PathBuf,
    },
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct InputAssetSpec {
    kind: String,
    path: PathBuf,
    url: String,
    #[serde(default)]
    fallback_urls: Vec<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen {
            out_dir,
            name,
            label,
            root,
            not_after_epoch,
            password,
            unencrypted,
            force,
        } => cmd_keygen(
            &out_dir,
            &name,
            label,
            root,
            not_after_epoch,
            password,
            unencrypted,
            force,
        ),
        Command::Sign {
            files,
            key,
            password,
        } => cmd_sign(&files, &key, password.as_deref()),
        Command::Verify {
            files,
            pins,
            pubkey,
            allow_missing_pqc,
        } => cmd_verify(
            &files,
            pins.as_deref(),
            pubkey.as_deref(),
            allow_missing_pqc,
        ),
        Command::Manifest {
            version,
            epoch,
            expires_in_days,
            min_supported_version,
            assets_json,
            assets,
            notes,
            notes_file,
            out_file,
            key,
            password,
        } => cmd_manifest(
            &version,
            epoch,
            expires_in_days,
            min_supported_version.as_deref(),
            assets_json.as_deref(),
            &assets,
            &notes,
            notes_file.as_deref(),
            &out_file,
            &key,
            password.as_deref(),
        ),
        Command::Guard {
            pins,
            manifest,
            files,
            key,
            password,
        } => cmd_guard(
            &pins,
            manifest.as_deref(),
            &files,
            &key,
            password.as_deref(),
        ),
        Command::RotateKey {
            rotation_epoch,
            root_key,
            password,
            add_pubkey_files,
            revoke_ids,
            out_file,
        } => cmd_rotate_key(
            rotation_epoch,
            &root_key,
            password.as_deref(),
            &add_pubkey_files,
            &revoke_ids,
            &out_file,
        ),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn cmd_keygen(
    out_dir: &Path,
    name: &str,
    label: Option<String>,
    root: bool,
    not_after_epoch: Option<u64>,
    password: Option<String>,
    unencrypted: bool,
    force: bool,
) -> Result<()> {
    if password.is_none() && !unencrypted {
        return Err(CliError::Message(
            "pass --password <pw> for encrypted key storage, or --unencrypted for raw CI seed output"
                .to_string(),
        ));
    }

    let mut sk = SecretKeyBundle::generate()?.with_root(root);
    if let Some(lbl) = label {
        sk = sk.with_label(lbl);
    }
    if let Some(epoch) = not_after_epoch {
        sk = sk.with_not_after_epoch(epoch);
    }

    let pk_json_path = out_dir.join(format!("{name}.pk.json"));
    let pins_path = out_dir.join("sigilup-pins.json");
    let sk_enc_path = out_dir.join(format!("{name}.sk.json"));
    let sk_raw_path = out_dir.join(format!("{name}.sk.raw"));

    let mut check_paths = vec![&pk_json_path, &pins_path];
    if password.is_some() {
        check_paths.push(&sk_enc_path);
    }
    if unencrypted {
        check_paths.push(&sk_raw_path);
    }
    if !force && check_paths.iter().any(|p| p.exists()) {
        return Err(CliError::Message(format!(
            "output files already exist in {}; pass --force to overwrite",
            out_dir.display()
        )));
    }
    fs::create_dir_all(out_dir)?;

    let pk_json = serde_json::to_string_pretty(sk.public_key())?;
    fs::write(&pk_json_path, format!("{pk_json}\n"))?;

    let pins = KeyPinFile::new(vec![sk.public_key().clone()]);
    fs::write(
        &pins_path,
        format!("{}\n", serde_json::to_string_pretty(&pins)?),
    )?;

    if let Some(pw) = password {
        let enc = sk.to_encrypted_json(pw.as_bytes())?;
        fs::write(&sk_enc_path, format!("{enc}\n"))?;
        restrict_permissions(&sk_enc_path)?;
        println!("wrote encrypted key: {}", sk_enc_path.display());
    }
    if unencrypted {
        let raw = sk.to_raw_seed_str();
        fs::write(&sk_raw_path, raw.as_bytes())?;
        restrict_permissions(&sk_raw_path)?;
        println!("wrote raw seed key: {}", sk_raw_path.display());
    }

    println!("key_id: {}", sk.public_key().key_id);
    println!("compact_pk: {}", sk.public_key().to_compact_str());
    println!("wrote pins: {}", pins_path.display());
    Ok(())
}

fn cmd_sign(files: &[PathBuf], key_spec: &str, password: Option<&str>) -> Result<()> {
    let sk = load_secret_key(key_spec, password)?;
    let now = unix_now();
    println!("signing with key {}", sk.public_key().key_id);
    for file in files {
        let f = fs::File::open(file)?;
        let file_name = file
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::to_string);
        let env = sign_reader(f, &sk, file_name, now)?;
        let sig_path = hsig_path(file);
        fs::write(
            &sig_path,
            format!("{}\n", serde_json::to_string_pretty(&env)?),
        )?;
        println!("signed {} -> {}", file.display(), sig_path.display());
    }
    Ok(())
}

fn cmd_verify(
    files: &[PathBuf],
    pins_path: Option<&Path>,
    pubkey_str: Option<&str>,
    allow_missing_pqc: bool,
) -> Result<()> {
    let store = resolve_trust_store(pins_path, pubkey_str)?;
    let policy = if allow_missing_pqc {
        VerificationPolicy::TransitionalAllowMissingPqc { min_signatures: 1 }
    } else {
        VerificationPolicy::strict()
    };

    for file in files {
        let sig_path = hsig_path(file);
        let env_text = fs::read_to_string(&sig_path)?;
        let env: HybridEnvelope = serde_json::from_str(&env_text)?;
        let f = fs::File::open(file)?;
        let desc = verify_reader(f, &env, &store, policy, 0)?;
        println!(
            "verified {} (size={}, blake3={})",
            file.display(),
            desc.digest.size,
            desc.digest.blake3_hex()
        );
    }
    Ok(())
}

fn parse_asset_arg(raw: &str) -> Result<(String, InputAssetSpec)> {
    let Some((key, rest)) = raw.split_once('=') else {
        return Err(CliError::Message(format!(
            "invalid --asset '{raw}': expected <KEY>=<KIND>:<PATH>:<URL>"
        )));
    };
    if key.is_empty() {
        return Err(CliError::Message(format!(
            "invalid --asset '{raw}': empty asset key"
        )));
    }
    let Some((kind, path_and_url)) = rest.split_once(':') else {
        return Err(CliError::Message(format!(
            "invalid --asset '{raw}': expected <KEY>=<KIND>:<PATH>:<URL>"
        )));
    };
    if kind.is_empty() {
        return Err(CliError::Message(format!(
            "invalid --asset '{raw}': empty asset kind"
        )));
    }

    let url_split = path_and_url
        .find(":https://")
        .or_else(|| path_and_url.find(":http://"));
    let Some(split_idx) = url_split else {
        return Err(CliError::Message(format!(
            "invalid --asset '{raw}': URL must start with http:// or https://"
        )));
    };

    let path = &path_and_url[..split_idx];
    let url = &path_and_url[split_idx + 1..];
    if path.is_empty() {
        return Err(CliError::Message(format!(
            "invalid --asset '{raw}': empty artifact path"
        )));
    }

    Ok((
        key.to_string(),
        InputAssetSpec {
            kind: kind.to_string(),
            path: PathBuf::from(path),
            url: url.to_string(),
            fallback_urls: Vec::new(),
            metadata: None,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
fn cmd_manifest(
    version_str: &str,
    epoch: u64,
    expires_in_days: Option<u64>,
    min_supported: Option<&str>,
    assets_json: Option<&Path>,
    asset_args: &[String],
    notes: &str,
    notes_file: Option<&Path>,
    out_file: &Path,
    key_spec: &str,
    password: Option<&str>,
) -> Result<()> {
    let sk = load_secret_key(key_spec, password)?;
    let version: semver::Version = version_str.trim().trim_start_matches(['v', 'V']).parse()?;
    let min_supported_version = match min_supported {
        Some(v) => Some(v.trim().trim_start_matches(['v', 'V']).parse()?),
        None => None,
    };

    let mut specs: BTreeMap<String, InputAssetSpec> = match assets_json {
        Some(path) => {
            let raw_assets = fs::read_to_string(path)?;
            serde_json::from_str(&raw_assets)?
        }
        None => BTreeMap::new(),
    };
    for raw in asset_args {
        let (key, spec) = parse_asset_arg(raw)?;
        if specs.insert(key.clone(), spec).is_some() {
            return Err(CliError::Message(format!(
                "duplicate asset key '{key}' in --asset / --assets-json"
            )));
        }
    }
    if specs.is_empty() {
        return Err(CliError::Message("assets map is empty".to_string()));
    }

    let resolved_notes = match notes_file {
        Some(path) => fs::read_to_string(path)?,
        None => notes.to_string(),
    };

    let mut assets = BTreeMap::new();
    for (key, spec) in specs {
        let f = fs::File::open(&spec.path)?;
        let digest = hash_reader(f)?;
        assets.insert(
            key,
            PlatformAsset {
                kind: spec.kind,
                url: spec.url,
                fallback_urls: spec.fallback_urls,
                digest,
                metadata: spec.metadata,
            },
        );
    }

    let now = unix_now();
    let expires_at = expires_in_days.map(|days| now.saturating_add(days.saturating_mul(86_400)));

    let manifest = UpdateManifest {
        schema_version: 2,
        version,
        security_epoch: epoch,
        min_supported_version,
        published_at: now,
        expires_at,
        notes: resolved_notes,
        assets,
        key_rotations: Vec::new(),
    };

    let signed = SignedManifest::sign(&manifest, &sk, now)?;
    if let Some(parent) = out_file.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        out_file,
        format!("{}\n", serde_json::to_string_pretty(&signed)?),
    )?;
    println!(
        "wrote signed manifest {} (key {}, epoch {})",
        out_file.display(),
        sk.public_key().key_id,
        epoch
    );
    Ok(())
}

fn cmd_guard(
    pins_path: &Path,
    manifest_path: Option<&Path>,
    files: &[PathBuf],
    key_spec: &str,
    password: Option<&str>,
) -> Result<()> {
    let sk = load_secret_key(key_spec, password)?;
    let pins = KeyPinFile::from_json_str(&fs::read_to_string(pins_path)?)?;
    pins.verify_signing_key(&sk)?;
    println!(
        "guard: signing key {} matches {}",
        sk.public_key().key_id,
        pins_path.display()
    );

    let mut store = pins.to_trust_store();
    if let Some(mpath) = manifest_path {
        let signed: SignedManifest = serde_json::from_str(&fs::read_to_string(mpath)?)?;
        let decoded: UpdateManifest<serde_json::Value> = signed.verify_and_decode(
            &mut store,
            VerificationPolicy::strict(),
            pins.min_security_epoch,
        )?;
        println!(
            "guard: verified manifest {} (v{}, epoch {}, {} assets)",
            mpath.display(),
            decoded.version,
            decoded.security_epoch,
            decoded.assets.len()
        );
    }

    for file in files {
        let sig_path = hsig_path(file);
        let env: HybridEnvelope = serde_json::from_str(&fs::read_to_string(&sig_path)?)?;
        verify_reader(
            fs::File::open(file)?,
            &env,
            &store,
            VerificationPolicy::strict(),
            pins.min_security_epoch,
        )?;
        println!("guard: verified {}", file.display());
    }
    Ok(())
}

fn cmd_rotate_key(
    rotation_epoch: u64,
    root_key_spec: &str,
    password: Option<&str>,
    add_pubkey_files: &[PathBuf],
    revoke_ids: &[String],
    out_file: &Path,
) -> Result<()> {
    let root_sk = load_secret_key(root_key_spec, password)?;
    let mut add_keys = Vec::with_capacity(add_pubkey_files.len());
    for p in add_pubkey_files {
        let pk: PublicKeyBundle = serde_json::from_str(&fs::read_to_string(p)?)?;
        add_keys.push(pk);
    }
    let mut revoke_keys = Vec::with_capacity(revoke_ids.len());
    for id_str in revoke_ids {
        revoke_keys.push(id_str.parse::<KeyId>()?);
    }

    let now = unix_now();
    let stmt = KeyRotationStatement {
        version: 2,
        rotation_epoch,
        issued_at: now,
        add_keys,
        revoke_keys,
    };
    let payload = serde_json::to_vec(&stmt)?;
    let env = HybridEnvelope::sign(&root_sk, KEY_ROTATION_PAYLOAD_TYPE, &payload, now)?;
    fs::write(
        out_file,
        format!("{}\n", serde_json::to_string_pretty(&env)?),
    )?;
    println!(
        "wrote key rotation statement {} (epoch {}, signed by root {})",
        out_file.display(),
        rotation_epoch,
        root_sk.public_key().key_id
    );
    Ok(())
}

fn load_secret_key(key_spec: &str, password: Option<&str>) -> Result<SecretKeyBundle> {
    let trimmed = key_spec.trim();
    let raw_text = if Path::new(trimmed).is_file() {
        fs::read_to_string(trimmed)?
    } else {
        trimmed.to_string()
    };

    let content = raw_text.trim();
    if content.starts_with("sigilup-sk:v2:") {
        return Ok(SecretKeyBundle::from_raw_seed_str(content)?);
    }
    if content.starts_with('{') {
        let pw = password.ok_or_else(|| {
            CliError::Message(
                "encrypted .sk.json key requires --password or SIGILUP_SIGNING_KEY_PASSWORD"
                    .to_string(),
            )
        })?;
        return Ok(SecretKeyBundle::from_encrypted_json(
            content,
            pw.as_bytes(),
        )?);
    }
    Err(CliError::Message(
        "unrecognized signing key format (expected path to .sk.json/.sk.raw or sigilup-sk:v2:...)"
            .to_string(),
    ))
}

fn resolve_trust_store(pins_path: Option<&Path>, pubkey_str: Option<&str>) -> Result<TrustStore> {
    if let Some(p) = pins_path {
        let pins = KeyPinFile::from_json_str(&fs::read_to_string(p)?)?;
        return Ok(pins.to_trust_store());
    }
    if let Some(pk) = pubkey_str {
        let bundle = PublicKeyBundle::from_compact_str(pk)?;
        return Ok(TrustStore::from_keys([bundle]));
    }
    Err(CliError::Message(
        "provide either --pins <sigilup-pins.json> or --pubkey <sigilup-pk:v2:...>".to_string(),
    ))
}

fn hsig_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_os_string();
    name.push(".hsig");
    PathBuf::from(name)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_asset_arg_handles_unix_and_windows_paths() {
        let (k1, s1) = parse_asset_arg(
            "linux-x86_64=portable:dist/app.tar.gz:https://github.com/org/repo/releases/download/v1.0.0/app.tar.gz",
        )
        .unwrap();
        assert_eq!(k1, "linux-x86_64");
        assert_eq!(s1.kind, "portable");
        assert_eq!(s1.path, PathBuf::from("dist/app.tar.gz"));
        assert_eq!(
            s1.url,
            "https://github.com/org/repo/releases/download/v1.0.0/app.tar.gz"
        );

        let (k2, s2) =
            parse_asset_arg(r"windows-x86_64=portable:C:\dist\app.zip:https://example.com/app.zip")
                .unwrap();
        assert_eq!(k2, "windows-x86_64");
        assert_eq!(s2.kind, "portable");
        assert_eq!(s2.path, PathBuf::from(r"C:\dist\app.zip"));
        assert_eq!(s2.url, "https://example.com/app.zip");

        assert!(parse_asset_arg("missing-equals").is_err());
        assert!(parse_asset_arg("k=portable:dist/a.zip:ftp://example.com/a.zip").is_err());
        assert!(parse_asset_arg("k=portable::https://example.com/a.zip").is_err());
    }
}
