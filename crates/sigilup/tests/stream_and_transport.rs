//! Integration tests for streaming signing/verification and `reqwest` updater transport.
#![allow(clippy::unwrap_used, missing_docs)]

#[cfg(feature = "sign")]
mod stream_tests {
    use sigilup::{SecretKeyBundle, TrustStore, VerificationPolicy, stream};

    #[test]
    fn stream_sign_and_verify_detects_tampering() {
        let sk = SecretKeyBundle::from_seeds([21u8; 32], [22u8; 32]).unwrap();
        let trust = TrustStore::from_keys([sk.public_key().clone()]);

        let payload = vec![0xA5u8; 256 * 1024 + 17];
        let env = stream::sign_reader(
            payload.as_slice(),
            &sk,
            Some("artifact.bin".to_string()),
            1_780_000_000,
        )
        .unwrap();

        let desc = stream::verify_reader(
            payload.as_slice(),
            &env,
            &trust,
            VerificationPolicy::strict(),
            0,
        )
        .unwrap();
        assert_eq!(desc.digest.size, payload.len() as u64);
        assert_eq!(desc.name.as_deref(), Some("artifact.bin"));

        let mut tampered = payload.clone();
        tampered[131_072] ^= 0x01;
        assert!(
            stream::verify_reader(
                tampered.as_slice(),
                &env,
                &trust,
                VerificationPolicy::strict(),
                0,
            )
            .is_err()
        );
    }
}

#[cfg(all(feature = "sign", feature = "reqwest"))]
mod transport_tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

    use sigilup::core::{ArtifactHasher, SecretKeyBundle, TrustStore, VerifyContext};
    use sigilup::manifest::{
        MemoryEpochStore, PlatformAsset, SignedManifest, UpdateDecision, UpdateEvaluator,
        UpdateManifest, UrlPolicy, current_platform_base,
    };
    use sigilup::transport::{ReqwestUpdater, TransportError};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn reqwest_updater_checks_manifest_and_verifies_in_flight_download() {
        let sk = SecretKeyBundle::from_seeds([31u8; 32], [32u8; 32]).unwrap();
        let trust = TrustStore::from_keys([sk.public_key().clone()]);

        let good_payload = b"sigilup-verified-binary-bytes-0123456789".to_vec();
        let bad_payload = b"sigilup-TAMPERED-binary-bytes-0123456789".to_vec();

        // Reserve listener address by spawning after constructing routes? Better: spawn server with a mutable shared map!
        let routes = Arc::new(std::sync::RwLock::new(HashMap::<String, Vec<u8>>::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let routes_srv = Arc::clone(&routes);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let routes_srv = Arc::clone(&routes_srv);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let body_opt = routes_srv.read().unwrap().get(path).cloned();
                    if let Some(body) = body_opt {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = socket.write_all(header.as_bytes()).await;
                        let _ = socket.write_all(&body).await;
                    } else {
                        let _ = socket
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                    }
                    let _ = socket.shutdown().await;
                });
            }
        });

        let mut assets = BTreeMap::new();
        assets.insert(
            current_platform_base(),
            PlatformAsset {
                kind: "portable".to_string(),
                url: format!("{base_url}/releases/demo.bin"),
                fallback_urls: Vec::new(),
                digest: ArtifactHasher::hash_bytes(&good_payload),
                metadata: None,
            },
        );
        let manifest = UpdateManifest::<()> {
            schema_version: 2,
            version: sigilup::semver::Version::new(2, 0, 0),
            security_epoch: 3,
            min_supported_version: None,
            published_at: 1_780_000_000,
            expires_at: None,
            notes: "ok".to_string(),
            assets,
            key_rotations: Vec::new(),
        };
        let signed_manifest = SignedManifest::sign(&manifest, &sk, 1_780_000_000).unwrap();

        {
            let mut w = routes.write().unwrap();
            w.insert(
                "/latest.hsig.json".to_string(),
                serde_json::to_vec(&signed_manifest).unwrap(),
            );
            w.insert("/releases/demo.bin".to_string(), good_payload.clone());
        }

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let updater = ReqwestUpdater::new(client);
        let mut eval = UpdateEvaluator::new(trust, sigilup::semver::Version::new(1, 0, 0))
            .with_url_policy(UrlPolicy {
                require_https: false,
                allowed_prefixes: vec![format!("{base_url}/releases/")],
                ..UrlPolicy::default()
            });
        let mut epoch_store = MemoryEpochStore::new(0);

        let decision: UpdateDecision<()> = updater
            .check_for_update(
                &format!("{base_url}/latest.hsig.json"),
                &mut eval,
                &mut epoch_store,
                VerifyContext::default(),
            )
            .await
            .unwrap();
        let UpdateDecision::UpdateAvailable(available) = decision else {
            panic!("expected update");
        };

        let dir = tempfile::tempdir().unwrap();
        let mut progress = Vec::new();
        let downloaded = updater
            .download_and_verify(&available, dir.path(), |got, total| {
                progress.push((got, total));
            })
            .await
            .unwrap();
        assert_eq!(std::fs::read(&downloaded).unwrap(), good_payload);
        assert!(!progress.is_empty());

        // Now serve tampered bytes of equal length: download_and_verify must reject & clean `.part`
        routes
            .write()
            .unwrap()
            .insert("/releases/demo.bin".to_string(), bad_payload);
        let dir2 = tempfile::tempdir().unwrap();
        let err = updater
            .download_and_verify(&available, dir2.path(), |_, _| {})
            .await
            .unwrap_err();
        assert!(matches!(err, TransportError::Core(_)));
        assert!(!dir2.path().join("demo.bin").exists());
        assert!(!dir2.path().join("demo.bin.part").exists());
    }

    #[tokio::test]
    async fn reqwest_updater_falls_back_to_mirror_for_manifest_and_tampered_primary_artifact() {
        let sk = SecretKeyBundle::from_seeds([41u8; 32], [42u8; 32]).unwrap();
        let trust = TrustStore::from_keys([sk.public_key().clone()]);

        let good_payload = b"mirror-verified-binary-bytes-0123456789".to_vec();
        let bad_payload = b"mirror-TAMPERED-binary-bytes-0123456789".to_vec();

        let routes = Arc::new(std::sync::RwLock::new(HashMap::<String, Vec<u8>>::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let routes_srv = Arc::clone(&routes);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let routes_srv = Arc::clone(&routes_srv);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let body_opt = routes_srv.read().unwrap().get(path).cloned();
                    if let Some(body) = body_opt {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = socket.write_all(header.as_bytes()).await;
                        let _ = socket.write_all(&body).await;
                    } else {
                        let _ = socket
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                    }
                    let _ = socket.shutdown().await;
                });
            }
        });

        let mut assets = BTreeMap::new();
        assets.insert(
            current_platform_base(),
            PlatformAsset {
                kind: "portable".to_string(),
                url: format!("{base_url}/primary/demo.bin"),
                fallback_urls: vec![format!("{base_url}/mirror/demo.bin")],
                digest: ArtifactHasher::hash_bytes(&good_payload),
                metadata: None,
            },
        );
        let manifest = UpdateManifest::<()> {
            schema_version: 2,
            version: sigilup::semver::Version::new(2, 1, 0),
            security_epoch: 4,
            min_supported_version: None,
            published_at: 1_780_000_000,
            expires_at: None,
            notes: "mirror".to_string(),
            assets,
            key_rotations: Vec::new(),
        };
        let signed_manifest = SignedManifest::sign(&manifest, &sk, 1_780_000_000).unwrap();

        {
            let mut w = routes.write().unwrap();
            // Primary manifest 404s; mirror manifest succeeds.
            w.insert(
                "/mirror/latest.hsig.json".to_string(),
                serde_json::to_vec(&signed_manifest).unwrap(),
            );
            // Primary artifact serves tampered bytes; mirror artifact serves good bytes.
            w.insert("/primary/demo.bin".to_string(), bad_payload);
            w.insert("/mirror/demo.bin".to_string(), good_payload.clone());
        }

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let updater = ReqwestUpdater::new(client);
        let mut eval = UpdateEvaluator::new(trust, sigilup::semver::Version::new(1, 0, 0))
            .with_url_policy(UrlPolicy {
                require_https: false,
                allowed_prefixes: vec![
                    format!("{base_url}/primary/"),
                    format!("{base_url}/mirror/"),
                ],
                ..UrlPolicy::default()
            });
        let mut epoch_store = MemoryEpochStore::new(0);

        let decision: UpdateDecision<()> = updater
            .check_for_update_any(
                &[
                    &format!("{base_url}/primary/latest.hsig.json"),
                    &format!("{base_url}/mirror/latest.hsig.json"),
                ],
                &mut eval,
                &mut epoch_store,
                VerifyContext::now(),
            )
            .await
            .unwrap();
        let UpdateDecision::UpdateAvailable(available) = decision else {
            panic!("expected update");
        };

        let dir = tempfile::tempdir().unwrap();
        let downloaded = updater
            .download_and_verify(&available, dir.path(), |_, _| {})
            .await
            .unwrap();
        assert_eq!(std::fs::read(&downloaded).unwrap(), good_payload);
        assert!(!dir.path().join("demo.bin.part").exists());
    }
}

#[cfg(all(feature = "sign", feature = "blocking"))]
mod blocking_transport_tests {
    use std::collections::{BTreeMap, HashMap};
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::Arc;

    use sigilup::core::{ArtifactHasher, SecretKeyBundle, TrustStore, VerifyContext};
    use sigilup::manifest::{
        MemoryEpochStore, PlatformAsset, SignedManifest, UpdateDecision, UpdateEvaluator,
        UpdateManifest, UrlPolicy, current_platform_base,
    };
    use sigilup::transport::BlockingUpdater;

    #[test]
    fn blocking_updater_checks_manifest_any_and_downloads_with_fallback() {
        let sk = SecretKeyBundle::from_seeds([51u8; 32], [52u8; 32]).unwrap();
        let trust = TrustStore::from_keys([sk.public_key().clone()]);

        let good_payload = b"blocking-verified-binary-bytes-0123456789".to_vec();
        let routes = Arc::new(std::sync::RwLock::new(HashMap::<String, Vec<u8>>::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let routes_srv = Arc::clone(&routes);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let routes_srv = Arc::clone(&routes_srv);
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let body_opt = routes_srv.read().unwrap().get(path).cloned();
                    if let Some(body) = body_opt {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.write_all(&body);
                    } else {
                        let _ = stream.write_all(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                });
            }
        });

        let mut assets = BTreeMap::new();
        assets.insert(
            current_platform_base(),
            PlatformAsset {
                kind: "portable".to_string(),
                url: format!("{base_url}/missing/demo.bin"),
                fallback_urls: vec![format!("{base_url}/mirror/demo.bin")],
                digest: ArtifactHasher::hash_bytes(&good_payload),
                metadata: None,
            },
        );
        let manifest = UpdateManifest::<()> {
            schema_version: 2,
            version: sigilup::semver::Version::new(3, 0, 0),
            security_epoch: 5,
            min_supported_version: None,
            published_at: 1_780_000_000,
            expires_at: None,
            notes: "blocking".to_string(),
            assets,
            key_rotations: Vec::new(),
        };
        let signed_manifest = SignedManifest::sign(&manifest, &sk, 1_780_000_000).unwrap();

        {
            let mut w = routes.write().unwrap();
            w.insert(
                "/mirror/latest.hsig.json".to_string(),
                serde_json::to_vec(&signed_manifest).unwrap(),
            );
            w.insert("/mirror/demo.bin".to_string(), good_payload.clone());
        }

        let updater = BlockingUpdater::default();
        let mut eval = UpdateEvaluator::new(trust, sigilup::semver::Version::new(1, 0, 0))
            .with_url_policy(UrlPolicy {
                require_https: false,
                allowed_prefixes: vec![
                    format!("{base_url}/missing/"),
                    format!("{base_url}/mirror/"),
                ],
                ..UrlPolicy::default()
            });
        let mut epoch_store = MemoryEpochStore::new(0);

        let decision: UpdateDecision<()> = updater
            .check_for_update_any(
                &[
                    &format!("{base_url}/missing/latest.hsig.json"),
                    &format!("{base_url}/mirror/latest.hsig.json"),
                ],
                &mut eval,
                &mut epoch_store,
                VerifyContext::now(),
            )
            .unwrap();
        let UpdateDecision::UpdateAvailable(available) = decision else {
            panic!("expected update");
        };

        let dir = tempfile::tempdir().unwrap();
        let mut progress = Vec::new();
        let downloaded = updater
            .download_and_verify(&available, dir.path(), |got, total| {
                progress.push((got, total));
            })
            .unwrap();
        assert_eq!(std::fs::read(&downloaded).unwrap(), good_payload);
        assert!(!progress.is_empty());
        assert!(!dir.path().join("demo.bin.part").exists());
    }
}
