use serde::{Deserialize, Serialize};
use sigilup_core::{KeyId, PublicKeyBundle, TrustStore};

use crate::error::{Error, Result};

/// Declarative key-pinning bundle (`sigilup-pins.json`).
///
/// Serves as the Single Source of Truth shared between the client build
/// (e.g. `include_str!("sigilup-pins.json")`) and the release CI `guard` step,
/// replacing fragile regex scraping of source files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPinFile {
    /// Pin file schema version (`2`).
    pub version: u32,
    /// Minimum baseline `security_epoch` pinned in this build.
    #[serde(default)]
    pub min_security_epoch: u64,
    /// Trusted public key bundles embedded in the client.
    pub trusted_keys: Vec<PublicKeyBundle>,
    /// Explicitly revoked key IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_keys: Vec<KeyId>,
}

impl KeyPinFile {
    /// Create a new pin file from trusted keys.
    #[must_use]
    pub fn new(trusted_keys: Vec<PublicKeyBundle>) -> Self {
        Self {
            version: 2,
            min_security_epoch: 0,
            trusted_keys,
            revoked_keys: Vec::new(),
        }
    }

    /// Parse a `sigilup-pins.json` string.
    pub fn from_json_str(s: &str) -> Result<Self> {
        let pins: Self = serde_json::from_str(s)?;
        if pins.version != 2 {
            return Err(Error::Core(sigilup_core::Error::UnsupportedVersion(
                pins.version,
            )));
        }
        Ok(pins)
    }

    /// Convert this pin file into an active [`TrustStore`].
    #[must_use]
    pub fn to_trust_store(&self) -> TrustStore {
        let mut store = TrustStore::from_keys(self.trusted_keys.iter().cloned());
        for &revoked in &self.revoked_keys {
            store.revoke(revoked);
        }
        store
    }

    /// Verify that a signing key matches an active, non-revoked entry in this pin file.
    #[cfg(feature = "sign")]
    pub fn verify_signing_key(&self, sk: &sigilup_core::SecretKeyBundle) -> Result<()> {
        let pk = sk.public_key();
        if self.revoked_keys.contains(&pk.key_id) {
            return Err(Error::Validation(format!(
                "signing key {} is revoked in pin file",
                pk.key_id
            )));
        }
        let matched = self.trusted_keys.iter().find(|k| k.key_id == pk.key_id);
        match matched {
            Some(pinned) if pinned.ed25519 == pk.ed25519 && pinned.ml_dsa_65 == pk.ml_dsa_65 => {
                Ok(())
            }
            Some(_) => Err(Error::Validation(format!(
                "key_id {} matched in pin file, but raw public key bytes differ",
                pk.key_id
            ))),
            None => Err(Error::Validation(format!(
                "signing key {} is not present in pin file",
                pk.key_id
            ))),
        }
    }
}
