//! Integration tests for [`sigilup_manifest::UpdateEvaluator`] and [`sigilup_manifest::KeyPinFile`].
#![allow(clippy::unwrap_used, missing_docs)]

#[cfg(feature = "sign")]
mod signed_tests {
    use std::collections::BTreeMap;

    use sigilup_core::{
        ArtifactHasher, EpochStore, HybridEnvelope, KEY_ROTATION_PAYLOAD_TYPE,
        KeyRotationStatement, SecretKeyBundle, VerifyContext,
    };
    use sigilup_manifest::{
        Error, FileEpochStore, KeyPinFile, MemoryEpochStore, PlatformAsset, SignedManifest,
        UpdateDecision, UpdateEvaluator, UpdateManifest, UrlPolicy,
    };

    fn sample_manifest(version: &str, epoch: u64, expires_at: Option<u64>) -> UpdateManifest<()> {
        let mut assets = BTreeMap::new();
        assets.insert(
            "linux-x86_64-portable".to_string(),
            PlatformAsset {
                kind: "portable".to_string(),
                url: "https://github.com/zkz098/demo/releases/download/v2.0.0/demo-linux-x86_64.tar.gz".to_string(),
                fallback_urls: Vec::new(),
                digest: ArtifactHasher::hash_bytes(b"portable-tarball-payload"),
                metadata: None,
            },
        );
        assets.insert(
            "linux-x86_64-deb".to_string(),
            PlatformAsset {
                kind: "deb".to_string(),
                url: "https://github.com/zkz098/demo/releases/download/v2.0.0/demo.deb".to_string(),
                fallback_urls: Vec::new(),
                digest: ArtifactHasher::hash_bytes(b"deb-payload"),
                metadata: None,
            },
        );
        UpdateManifest {
            schema_version: 2,
            version: semver::Version::parse(version).unwrap(),
            security_epoch: epoch,
            min_supported_version: None,
            published_at: 1_780_000_000,
            expires_at,
            notes: "Release notes".to_string(),
            assets,
            key_rotations: Vec::new(),
        }
    }

    fn github_url_policy() -> UrlPolicy {
        UrlPolicy::with_prefixes(["https://github.com/zkz098/demo/releases/"])
    }

    #[test]
    fn evaluates_upgrade_channel_semver_and_url_policy() {
        let sk = SecretKeyBundle::from_seeds([1u8; 32], [2u8; 32]).unwrap();
        let pins = KeyPinFile::new(vec![sk.public_key().clone()]);
        let signed = SignedManifest::sign(
            &sample_manifest("2.0.0", 5, Some(1_800_000_000)),
            &sk,
            1_780_000_000,
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let mut epoch_store = FileEpochStore::new(dir.path().join("epoch"));
        let mut eval = UpdateEvaluator::new(pins.to_trust_store(), semver::Version::new(1, 5, 0))
            .with_url_policy(github_url_policy())
            .with_channel("portable")
            .with_expected_kind("portable");
        eval.platform_base = "linux-x86_64".to_string();

        let decision: UpdateDecision<()> = eval
            .evaluate(
                &signed,
                &mut epoch_store,
                VerifyContext::at_unix(1_790_000_000),
            )
            .unwrap();
        match decision {
            UpdateDecision::UpdateAvailable(up) => {
                assert_eq!(up.version, semver::Version::new(2, 0, 0));
                assert_eq!(up.security_epoch, 5);
                assert_eq!(up.asset_key, "linux-x86_64-portable");
            }
            UpdateDecision::UpToDate => panic!("expected update"),
        }
        assert_eq!(epoch_store.load_min_epoch().unwrap(), 5);

        // Same version -> UpToDate
        let mut eval_same =
            UpdateEvaluator::new(pins.to_trust_store(), semver::Version::new(2, 0, 0))
                .with_url_policy(github_url_policy())
                .with_channel("portable");
        eval_same.platform_base = "linux-x86_64".to_string();
        assert_eq!(
            eval_same
                .evaluate::<(), _>(
                    &signed,
                    &mut epoch_store,
                    VerifyContext::at_unix(1_790_000_000)
                )
                .unwrap(),
            UpdateDecision::UpToDate
        );

        // Missing channel on supported OS returns MissingChannelAsset, unsupported OS -> UpToDate
        let mut eval_missing_ch =
            UpdateEvaluator::new(pins.to_trust_store(), semver::Version::new(1, 0, 0))
                .with_url_policy(github_url_policy())
                .with_channel("appimage");
        eval_missing_ch.platform_base = "linux-x86_64".to_string();
        assert!(matches!(
            eval_missing_ch.evaluate::<(), _>(
                &signed,
                &mut epoch_store,
                VerifyContext::at_unix(1_790_000_000)
            ),
            Err(Error::MissingChannelAsset { .. })
        ));

        let mut eval_other_os =
            UpdateEvaluator::new(pins.to_trust_store(), semver::Version::new(1, 0, 0))
                .with_url_policy(github_url_policy())
                .with_channel("portable");
        eval_other_os.platform_base = "freebsd-riscv64".to_string();
        assert_eq!(
            eval_other_os
                .evaluate::<(), _>(
                    &signed,
                    &mut epoch_store,
                    VerifyContext::at_unix(1_790_000_000)
                )
                .unwrap(),
            UpdateDecision::UpToDate
        );
    }

    #[test]
    fn enforces_anti_rollback_anti_freeze_and_min_supported_version() {
        let sk = SecretKeyBundle::from_seeds([3u8; 32], [4u8; 32]).unwrap();
        let pins = KeyPinFile::new(vec![sk.public_key().clone()]);

        // Anti-rollback
        let signed_epoch_4 =
            SignedManifest::sign(&sample_manifest("2.1.0", 4, None), &sk, 1_780_000_000).unwrap();
        let mut store = MemoryEpochStore::new(5);
        let mut eval = UpdateEvaluator::new(pins.to_trust_store(), semver::Version::new(1, 0, 0))
            .with_url_policy(github_url_policy())
            .with_channel("portable");
        eval.platform_base = "linux-x86_64".to_string();

        assert!(matches!(
            eval.evaluate::<(), _>(&signed_epoch_4, &mut store, VerifyContext::default()),
            Err(Error::RollbackDetected {
                found: 4,
                required: 5
            })
        ));

        // Anti-freeze with clock skew tolerance
        let signed_expiring = SignedManifest::sign(
            &sample_manifest("2.1.0", 6, Some(1_780_000_100)),
            &sk,
            1_780_000_000,
        )
        .unwrap();
        // Within 300s default skew -> OK
        assert!(matches!(
            eval.evaluate::<(), _>(
                &signed_expiring,
                &mut store,
                VerifyContext::at_unix(1_780_000_350)
            ),
            Ok(UpdateDecision::UpdateAvailable(_))
        ));
        // Past skew -> ManifestExpired
        assert!(matches!(
            eval.evaluate::<(), _>(
                &signed_expiring,
                &mut store,
                VerifyContext::at_unix(1_780_000_500)
            ),
            Err(Error::ManifestExpired { .. })
        ));

        // min_supported_version rejection
        let mut gated = sample_manifest("3.0.0", 7, None);
        gated.min_supported_version = Some(semver::Version::new(2, 0, 0));
        let signed_gated = SignedManifest::sign(&gated, &sk, 1_780_000_000).unwrap();
        assert!(matches!(
            eval.evaluate::<(), _>(&signed_gated, &mut store, VerifyContext::default()),
            Err(Error::BelowMinSupportedVersion { .. })
        ));
    }

    #[test]
    fn bundled_root_signed_rotation_adds_new_key_and_revokes_old_release_key() {
        let root_sk = SecretKeyBundle::from_seeds([10u8; 32], [11u8; 32])
            .unwrap()
            .with_root(true);
        let old_release_sk = SecretKeyBundle::from_seeds([12u8; 32], [13u8; 32]).unwrap();
        let new_release_sk = SecretKeyBundle::from_seeds([14u8; 32], [15u8; 32]).unwrap();

        let pins = KeyPinFile::new(vec![
            root_sk.public_key().clone(),
            old_release_sk.public_key().clone(),
        ]);

        let rotation = KeyRotationStatement {
            version: 2,
            rotation_epoch: 1,
            issued_at: 1_780_000_000,
            add_keys: vec![new_release_sk.public_key().clone()],
            revoke_keys: vec![old_release_sk.public_key().key_id],
        };
        let rot_env = HybridEnvelope::sign(
            &root_sk,
            KEY_ROTATION_PAYLOAD_TYPE,
            &serde_json::to_vec(&rotation).unwrap(),
            1_780_000_000,
        )
        .unwrap();

        let mut manifest = sample_manifest("2.2.0", 10, None);
        manifest.key_rotations.push(rot_env);

        // Manifest is signed ONLY by the brand-new release key!
        let signed = SignedManifest::sign(&manifest, &new_release_sk, 1_780_000_000).unwrap();

        let mut store = MemoryEpochStore::new(0);
        let mut eval = UpdateEvaluator::new(pins.to_trust_store(), semver::Version::new(1, 0, 0))
            .with_url_policy(github_url_policy())
            .with_channel("portable");
        eval.platform_base = "linux-x86_64".to_string();

        let decision = eval
            .evaluate::<(), _>(&signed, &mut store, VerifyContext::default())
            .unwrap();
        assert!(matches!(decision, UpdateDecision::UpdateAvailable(_)));

        // TrustStore inside evaluator has now revoked old_release_sk!
        assert!(
            eval.trust_store
                .get_active(old_release_sk.public_key().key_id, 10)
                .is_err()
        );
        assert!(
            eval.trust_store
                .get_active(new_release_sk.public_key().key_id, 10)
                .is_ok()
        );

        // PinFile signing guard checks
        assert!(pins.verify_signing_key(&old_release_sk).is_ok());
        assert!(pins.verify_signing_key(&new_release_sk).is_err());
    }

    #[test]
    fn validates_fallback_urls_against_url_policy_and_preserves_backward_compat() {
        let sk = SecretKeyBundle::from_seeds([16u8; 32], [17u8; 32]).unwrap();
        let pins = KeyPinFile::new(vec![sk.public_key().clone()]);

        // Backward-compat: JSON without `fallbackUrls` deserializes cleanly.
        let legacy_json = serde_json::json!({
            "kind": "portable",
            "url": "https://github.com/zkz098/demo/releases/download/v2.0.0/demo.bin",
            "digest": ArtifactHasher::hash_bytes(b"abc"),
        });
        let legacy_asset: PlatformAsset<()> = serde_json::from_value(legacy_json).unwrap();
        assert!(legacy_asset.fallback_urls.is_empty());

        let mut manifest = sample_manifest("2.1.0", 6, None);
        manifest
            .assets
            .get_mut("linux-x86_64-portable")
            .unwrap()
            .fallback_urls = vec![
            "https://gh-proxy.com/https://github.com/zkz098/demo/releases/download/v2.0.0/demo-linux-x86_64.tar.gz".to_string(),
        ];
        let signed = SignedManifest::sign(&manifest, &sk, 1_780_000_000).unwrap();

        // Policy that only allows github.com rejects the mirror fallback URL.
        let mut store = MemoryEpochStore::new(0);
        let mut strict_eval =
            UpdateEvaluator::new(pins.to_trust_store(), semver::Version::new(1, 0, 0))
                .with_url_policy(github_url_policy())
                .with_channel("portable");
        strict_eval.platform_base = "linux-x86_64".to_string();
        assert!(matches!(
            strict_eval.evaluate::<(), _>(&signed, &mut store, VerifyContext::default()),
            Err(Error::UrlRejected { .. })
        ));

        // Policy that allows both prefixes accepts it.
        let mut mirror_eval =
            UpdateEvaluator::new(pins.to_trust_store(), semver::Version::new(1, 0, 0))
                .with_url_policy(UrlPolicy::with_prefixes([
                    "https://github.com/zkz098/demo/releases/",
                    "https://gh-proxy.com/https://github.com/zkz098/demo/releases/",
                ]))
                .with_channel("portable");
        mirror_eval.platform_base = "linux-x86_64".to_string();
        assert!(matches!(
            mirror_eval.evaluate::<(), _>(
                &signed,
                &mut MemoryEpochStore::new(0),
                VerifyContext::default()
            ),
            Ok(UpdateDecision::UpdateAvailable(_))
        ));
    }
}
