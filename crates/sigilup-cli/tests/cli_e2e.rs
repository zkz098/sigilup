//! End-to-end integration tests for the `sigilup` CLI binary.
#![allow(clippy::unwrap_used, missing_docs)]

use std::fs;
use std::process::Command;

fn sigilup_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sigilup")
}

#[test]
fn cli_full_release_lifecycle_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let keys_dir = dir.path().join("keys");
    let next_dir = dir.path().join("next");
    let dist_dir = dir.path().join("dist");
    fs::create_dir_all(&dist_dir).unwrap();

    // 1. Keygen (encrypted root key)
    let status = Command::new(sigilup_bin())
        .args([
            "keygen",
            "--out-dir",
            keys_dir.to_str().unwrap(),
            "--name",
            "release",
            "--label",
            "ci-root",
            "--root",
            "--password",
            "test-passphrase-123",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "keygen root failed");

    let sk_enc = keys_dir.join("release.sk.json");
    let pk_json = keys_dir.join("release.pk.json");
    let pins_json = keys_dir.join("sigilup-pins.json");
    assert!(sk_enc.exists());
    assert!(pk_json.exists());
    assert!(pins_json.exists());

    // 2. Secondary keygen (unencrypted raw CI seed)
    let status = Command::new(sigilup_bin())
        .args([
            "keygen",
            "--out-dir",
            next_dir.to_str().unwrap(),
            "--name",
            "next",
            "--unencrypted",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "keygen next failed");
    assert!(next_dir.join("next.sk.raw").exists());
    assert!(next_dir.join("next.pk.json").exists());

    // 3. Sign artifact using encrypted key
    let artifact_path = dist_dir.join("demo-linux-x86_64.tar.gz");
    fs::write(&artifact_path, b"deterministic-release-tarball-bytes").unwrap();

    let status = Command::new(sigilup_bin())
        .args([
            "sign",
            artifact_path.to_str().unwrap(),
            "--key",
            sk_enc.to_str().unwrap(),
            "--password",
            "test-passphrase-123",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "sign failed");
    let hsig_path = dist_dir.join("demo-linux-x86_64.tar.gz.hsig");
    assert!(hsig_path.exists());

    // 4. Verify artifact with sigilup-pins.json
    let status = Command::new(sigilup_bin())
        .args([
            "verify",
            artifact_path.to_str().unwrap(),
            "--pins",
            pins_json.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "verify failed");

    // 5. Generate self-contained manifest
    let assets_json_path = dir.path().join("assets.json");
    let manifest_out = dist_dir.join("latest.hsig.json");
    let assets_doc = serde_json::json!({
        "linux-x86_64": {
            "kind": "portable",
            "path": artifact_path,
            "url": "https://github.com/zkz098/demo/releases/download/v2.0.0/demo-linux-x86_64.tar.gz"
        }
    });
    fs::write(&assets_json_path, serde_json::to_vec(&assets_doc).unwrap()).unwrap();

    let status = Command::new(sigilup_bin())
        .args([
            "manifest",
            "--version",
            "v2.0.0",
            "--epoch",
            "1",
            "--expires-in-days",
            "30",
            "--assets-json",
            assets_json_path.to_str().unwrap(),
            "--notes",
            "Release v2.0.0",
            "--out-file",
            manifest_out.to_str().unwrap(),
            "--key",
            sk_enc.to_str().unwrap(),
            "--password",
            "test-passphrase-123",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "manifest failed");
    assert!(manifest_out.exists());

    // 6. Guard succeeds with matching key + pins + manifest + artifact
    let status = Command::new(sigilup_bin())
        .args([
            "guard",
            "--pins",
            pins_json.to_str().unwrap(),
            "--manifest",
            manifest_out.to_str().unwrap(),
            artifact_path.to_str().unwrap(),
            "--key",
            sk_enc.to_str().unwrap(),
            "--password",
            "test-passphrase-123",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "guard failed");

    // 7. Guard rejects mismatched secret key!
    let status = Command::new(sigilup_bin())
        .args([
            "guard",
            "--pins",
            pins_json.to_str().unwrap(),
            "--key",
            next_dir.join("next.sk.raw").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!status.success(), "guard should reject mismatched key");

    // 8. Root-signed key rotation statement
    let pk_val: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&pk_json).unwrap()).unwrap();
    let root_key_id = pk_val["keyId"].as_str().unwrap();
    let rot_out = dist_dir.join("rotation.hsig.json");

    let status = Command::new(sigilup_bin())
        .args([
            "rotate-key",
            "--rotation-epoch",
            "1",
            "--root-key",
            sk_enc.to_str().unwrap(),
            "--password",
            "test-passphrase-123",
            "--add-pubkey-file",
            next_dir.join("next.pk.json").to_str().unwrap(),
            "--revoke",
            root_key_id,
            "--out-file",
            rot_out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "rotate-key failed");
    assert!(rot_out.exists());

    // 9. Verify fails cleanly when artifact is tampered
    fs::write(&artifact_path, b"corrupted-release-bytes").unwrap();
    let status = Command::new(sigilup_bin())
        .args([
            "verify",
            artifact_path.to_str().unwrap(),
            "--pins",
            pins_json.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!status.success(), "verify must fail on tampered artifact");
}

#[test]
fn cli_manifest_supports_inline_asset_notes_file_and_fallback_urls() {
    let dir = tempfile::tempdir().unwrap();
    let keys_dir = dir.path().join("keys");
    let dist_dir = dir.path().join("dist");
    fs::create_dir_all(&dist_dir).unwrap();

    let status = Command::new(sigilup_bin())
        .args([
            "keygen",
            "--out-dir",
            keys_dir.to_str().unwrap(),
            "--name",
            "ci",
            "--unencrypted",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let sk_raw = keys_dir.join("ci.sk.raw");
    let pins_json = keys_dir.join("sigilup-pins.json");

    let artifact_a = dist_dir.join("app-win.zip");
    fs::write(&artifact_a, b"windows-zip-bytes").unwrap();
    let artifact_b = dist_dir.join("app-linux.tar.gz");
    fs::write(&artifact_b, b"linux-tar-bytes").unwrap();

    let notes_path = dir.path().join("RELEASE_NOTES.md");
    fs::write(&notes_path, "# Release v1.2.3\n\n- Line 1\n- Line 2\n").unwrap();

    // 1. Inline --asset + --notes-file (no assets.json needed)
    let inline_manifest = dist_dir.join("inline.hsig.json");
    let status = Command::new(sigilup_bin())
        .args([
            "manifest",
            "--version",
            "v1.2.3",
            "--epoch",
            "2",
            "--asset",
            &format!(
                "windows-x86_64=portable:{}:https://example.com/app-win.zip",
                artifact_a.display()
            ),
            "--notes-file",
            notes_path.to_str().unwrap(),
            "--out-file",
            inline_manifest.to_str().unwrap(),
            "--key",
            sk_raw.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(
        status.success(),
        "manifest with --asset and --notes-file failed"
    );

    let pins =
        sigilup::manifest::KeyPinFile::from_json_str(&fs::read_to_string(&pins_json).unwrap())
            .unwrap();
    let mut store = pins.to_trust_store();
    let signed: sigilup::manifest::SignedManifest =
        serde_json::from_str(&fs::read_to_string(&inline_manifest).unwrap()).unwrap();
    let decoded: sigilup::manifest::UpdateManifest<serde_json::Value> = signed
        .verify_and_decode(&mut store, sigilup::VerificationPolicy::strict(), 2)
        .unwrap();
    assert_eq!(decoded.notes, "# Release v1.2.3\n\n- Line 1\n- Line 2\n");
    assert!(decoded.assets.contains_key("windows-x86_64"));

    // 2. assets.json with fallbackUrls
    let assets_json = dir.path().join("assets.json");
    fs::write(
        &assets_json,
        serde_json::json!({
            "linux-x86_64": {
                "kind": "portable",
                "path": artifact_b,
                "url": "https://github.com/org/repo/releases/download/v1.2.3/app-linux.tar.gz",
                "fallbackUrls": [
                    "https://gh-proxy.com/https://github.com/org/repo/releases/download/v1.2.3/app-linux.tar.gz"
                ]
            }
        })
        .to_string(),
    )
    .unwrap();

    let fallback_manifest = dist_dir.join("fallback.hsig.json");
    let status = Command::new(sigilup_bin())
        .args([
            "manifest",
            "--version",
            "1.2.3",
            "--epoch",
            "2",
            "--assets-json",
            assets_json.to_str().unwrap(),
            "--out-file",
            fallback_manifest.to_str().unwrap(),
            "--key",
            sk_raw.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "manifest with fallbackUrls failed");

    let signed2: sigilup::manifest::SignedManifest =
        serde_json::from_str(&fs::read_to_string(&fallback_manifest).unwrap()).unwrap();
    let decoded2: sigilup::manifest::UpdateManifest<serde_json::Value> = signed2
        .verify_and_decode(&mut store, sigilup::VerificationPolicy::strict(), 2)
        .unwrap();
    assert_eq!(
        decoded2.assets["linux-x86_64"].fallback_urls,
        vec![
            "https://gh-proxy.com/https://github.com/org/repo/releases/download/v1.2.3/app-linux.tar.gz"
        ]
    );
}
