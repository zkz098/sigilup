# sigilup

Post-quantum hybrid (**Ed25519 + ML-DSA-65 / NIST FIPS 204**) self-update and artifact signing toolkit with **single-pass BLAKE3 + SHA-512** streaming verification, **DSSEv1** domain-separated envelopes, **anti-rollback / anti-freeze** enforcement, and **root-signed key rotation**.

## Workspace Crates

| Crate | Purpose |
| --- | --- |
| [`sigilup-core`](crates/sigilup-core) | `#![no_std]` + `alloc` cryptographic primitives: `HybridEnvelope` (DSSEv1 PAE), `ArtifactHasher` / `ArtifactDigest` (single-pass `size` + `BLAKE3` + `SHA-512`), `TrustStore` & `KeyRotationStatement`, `VerificationPolicy`, and `SecretKeyBundle` (`sign` feature, `ZeroizeOnDrop`, Argon2id + XChaCha20 + BLAKE3-MAC). |
| [`sigilup-manifest`](crates/sigilup-manifest) | `UpdateManifest<M>` & `SignedManifest`, `UpdateEvaluator` (SemVer, `security_epoch` anti-rollback, `expires_at` anti-freeze, `UrlPolicy`), `KeyPinFile` (`sigilup-pins.json`), and `FileEpochStore` / `MemoryEpochStore`. |
| [`sigilup`](crates/sigilup) | Unified facade re-exporting `core` and `manifest`, plus `stream` (O(1) 64 KiB streaming `hash_reader` / `sign_reader` / `verify_reader`), `transport` (`reqwest` feature: 1-RTT manifest fetch & in-flight verified download), and `replace` (`self-replace` feature: portable archive extraction, `self_replace`, macOS ad-hoc `codesign`, Linux `APPIMAGE` guard). |
| [`sigilup-cli`](crates/sigilup-cli) | `sigilup` CLI binary: `keygen`, `sign`, `verify`, `manifest`, `guard`, `rotate-key`. |

## Installation

### Library

```toml
[dependencies]
sigilup = { version = "0.1.2", features = ["reqwest", "self-replace"] }
```

Available feature flags on `sigilup`:

- `std` *(default)*: standard library support.
- `sign`: enables `SecretKeyBundle` key generation, encrypted `.sk.json` storage, and signing.
- `reqwest`: enables `sigilup::transport::ReqwestUpdater` (pure-Rust `rustls` + `tokio`).
- `self-replace`: enables `sigilup::replace::install_portable_update` (`.tar.gz`, `.zip`, or raw binary).

### CLI

```bash
cargo install sigilup-cli
```

## CLI Quickstart

### 1. Generate keys & pin file

```bash
# Encrypted release signing key + public key + starter sigilup-pins.json
sigilup keygen --out-dir ./keys --name release --password "$SIGILUP_SIGNING_KEY_PASSWORD"

# Root key for authorizing future key rotations
sigilup keygen --out-dir ./keys --name root --root --password "$ROOT_PASSWORD"
```

For CI secret injection, `--unencrypted` writes a raw `sigilup-sk:v2:...` seed file when `--password` is omitted.

### 2. Sign & verify standalone artifacts

```bash
# Produces <artifact>.hsig detached DSSEv1 envelopes in O(1) streaming memory
sigilup sign --key ./keys/release.sk.json dist/myapp-linux-x86_64.tar.gz

# Verify against sigilup-pins.json (or --pubkey sigilup-pk:v2:...)
sigilup verify --pins ./keys/sigilup-pins.json dist/myapp-linux-x86_64.tar.gz
```

### 3. Build a signed self-update manifest (`latest.hsig.json`)

Prepare `assets.json`:

```json
{
  "linux-x86_64": {
    "kind": "portable",
    "path": "dist/myapp-linux-x86_64.tar.gz",
    "url": "https://github.com/example/myapp/releases/download/v1.2.0/myapp-linux-x86_64.tar.gz"
  }
}
```

Generate and sign the manifest:

```bash
sigilup manifest \
  --version 1.2.0 \
  --epoch 12 \
  --expires-in-days 30 \
  --assets-json assets.json \
  --out-file dist/latest.hsig.json \
  --key ./keys/release.sk.json
```

### 4. CI release guard

Verify that the active signing secret matches `sigilup-pins.json` and that both `latest.hsig.json` and release artifacts verify cleanly before publishing:

```bash
sigilup guard \
  --pins ./keys/sigilup-pins.json \
  --manifest dist/latest.hsig.json \
  --key "$SIGILUP_SIGNING_KEY" \
  dist/myapp-linux-x86_64.tar.gz
```

### 5. Root-signed key rotation

```bash
sigilup rotate-key \
  --rotation-epoch 2 \
  --root-key ./keys/root.sk.json \
  --add-pubkey-file ./keys/release-v2.pk.json \
  --revoke <16-char-old-key-id> \
  --out-file ./keys/rotation-2.hsig.json
```

## Library Quickstart (Client Self-Update)

```rust,no_run
use std::path::Path;
use sigilup::{
    TrustStore, UpdateDecision, UpdateEvaluator, UrlPolicy, VerificationPolicy, VerifyContext,
    manifest::{FileEpochStore, semver},
    replace::install_portable_update,
    transport::ReqwestUpdater,
};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let trust_store = TrustStore::from_json_str(include_str!("sigilup-pins.json"))?;
let current_version = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;

let mut evaluator = UpdateEvaluator::new(trust_store, current_version)
    .with_url_policy(UrlPolicy::with_prefixes(["https://github.com/example/myapp/releases/"]))
    .with_expected_kind("portable");

let mut epoch_store = FileEpochStore::new(Path::new("/var/lib/myapp/epoch.json"))?;
let updater = ReqwestUpdater::new(reqwest::Client::new());
let ctx = VerifyContext::new(VerificationPolicy::HybridStrict, 1_760_000_000);

match updater
    .check_for_update::<serde_json::Value, _>(
        "https://github.com/example/myapp/releases/latest/download/latest.hsig.json",
        &mut evaluator,
        &mut epoch_store,
        ctx,
    )
    .await?
{
    UpdateDecision::UpdateAvailable(update) => {
        let staging = tempfile::tempdir()?;
        let archive = updater
            .download_and_verify(&update, staging.path(), |_downloaded, _total| {})
            .await?;
        install_portable_update(&archive, staging.path(), "myapp", 256 * 1024 * 1024)?;
    }
    UpdateDecision::UpToDate | UpdateDecision::ChannelNotFound { .. } => {}
}
# Ok(())
# }
```

## Security Model & Cryptography

- **Hybrid Signatures (`Ed25519 + ML-DSA-65`)**: Every signature binds classical Ed25519 and post-quantum NIST FIPS 204 ML-DSA-65 over DSSEv1 Pre-Authentication Encoding (`pae`) with domain separation (`ML_DSA_DSSE_CONTEXT`).
- **Dual-Hash Streaming Digests**: `ArtifactHasher` computes `size`, `BLAKE3`, and `SHA-512` in a single pass with O(1) memory; downloads that fail size or digest verification are deleted before extraction.
- **Anti-Rollback & Anti-Freeze**: `UpdateEvaluator` enforces monotonic `security_epoch` persistence via `EpochStore`, SemVer progression, `min_supported_version`, and `expires_at` expiration checks.
- **URL Allowlisting**: `UrlPolicy` restricts download URLs to HTTPS and explicit prefix allowlists.
- **Zero-Unsafe & Encrypted Keys**: `#![forbid(unsafe_code)]` across the workspace; `.sk.json` files use Argon2id + XChaCha20 + BLAKE3-MAC with `ZeroizeOnDrop` and redacted `Debug`.

## License

Licensed under the [MIT License](LICENSE).
