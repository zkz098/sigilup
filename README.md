# sigilup

Post-quantum hybrid (**Ed25519 + ML-DSA-65 / NIST FIPS 204**) self-update and artifact signing toolkit with **single-pass BLAKE3 + SHA-512** streaming verification, **DSSEv1** domain-separated envelopes, **anti-rollback / anti-freeze** enforcement, and **root-signed key rotation**.

## Workspace Crates

- `sigilup-core` (`#![no_std]` + `alloc`):
  - `HybridEnvelope` (DSSEv1 PAE domain separation over raw payload bytes)
  - `ArtifactHasher` & `ArtifactDigest` (single-pass streaming `size` + `BLAKE3` + `SHA-512`)
  - `TrustStore` & `KeyRotationStatement` (zero-downtime key rotation & revocation)
  - `VerificationPolicy` (`HybridStrict`, `TransitionalAllowMissingPqc`, `ClassicalOnly`)
  - `SecretKeyBundle` (`sign` feature): `ZeroizeOnDrop`, redacted `Debug`, Argon2id + XChaCha20 + BLAKE3-MAC encrypted key files (no `scrypt`, no `rpassword` TTY blocking)
- `sigilup-manifest`:
  - `UpdateManifest<M>` & `SignedManifest` (1-request self-contained signed JSON manifest)
  - `UpdateEvaluator` (SemVer comparison, `security_epoch` anti-rollback, `expires_at` anti-freeze, `UrlPolicy`)
  - `KeyPinFile` (`sigilup-pins.json` declarative key pinning for CI guards)
  - `FileEpochStore` / `MemoryEpochStore`
- `sigilup`:
  - Facade re-exporting `core` and `manifest`
  - `stream` (O(1) 64 KiB streaming `hash_reader`, `sign_reader`, `verify_reader`)
  - `transport` (`reqwest` feature): 1-RTT manifest fetch & in-flight verified download
  - `replace` (`self-replace` feature): portable archive extraction + `self_replace` + macOS ad-hoc `codesign` + Linux `APPIMAGE` guard
- `sigilup-cli` (`sigilup` binary):
  - `keygen`, `sign`, `verify`, `manifest`, `guard`, `rotate-key`

## License

Licensed under the `MIT` license.
