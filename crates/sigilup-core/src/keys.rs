use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
#[cfg(feature = "sign")]
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey as EdVerifyingKey;
use ml_dsa::{EncodedVerifyingKey, KeyInit as _, MlDsa65, VerifyingKey as MlVerifyingKey};
#[cfg(feature = "sign")]
use ml_dsa::{KeyExport as _, Keypair as _};
use serde::{Deserialize, Serialize};
#[cfg(feature = "sign")]
use subtle::ConstantTimeEq as _;
#[cfg(feature = "sign")]
use zeroize::{Zeroize, Zeroizing};

use crate::digest::{decode_hex_fixed, encode_hex};
use crate::error::{Error, Result};

/// DSSE payload type for signed key-rotation statements.
pub const KEY_ROTATION_PAYLOAD_TYPE: &str = "application/vnd.sigilup.key-rotation+json;v=2";

/// ML-DSA-65 FIPS 204 context string for all `sigilup` v2 DSSE signatures.
pub const ML_DSA_DSSE_CONTEXT: &[u8] = b"sigilup-v2-dsse";

const PK_STRING_PREFIX: &str = "sigilup-pk:v2:";
#[cfg(feature = "sign")]
const SK_RAW_STRING_PREFIX: &str = "sigilup-sk:v2:";

/// Compact 64-bit key identifier derived from `BLAKE3("sigilup-keyid-v2" || ed25519 || ml_dsa_65)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(pub [u8; 8]);

impl KeyId {
    /// Derive the canonical [`KeyId`] from raw Ed25519 and ML-DSA-65 public key bytes.
    #[must_use]
    pub fn derive(ed25519_pk: &[u8; 32], ml_dsa_65_pk: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"sigilup-keyid-v2");
        hasher.update(ed25519_pk);
        hasher.update(ml_dsa_65_pk);
        let hash = hasher.finalize();
        let mut id = [0u8; 8];
        id.copy_from_slice(&hash.as_bytes()[..8]);
        Self(id)
    }

    /// Uppercase 16-character hexadecimal identifier.
    #[must_use]
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0).to_ascii_uppercase()
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.to_hex())
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for KeyId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self(decode_hex_fixed::<8>(s)?))
    }
}

impl Serialize for KeyId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A hybrid classical + post-quantum public key bundle (Ed25519 + ML-DSA-65).
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKeyBundle {
    /// Key identifier derived deterministically from both public keys.
    pub key_id: KeyId,
    /// Raw 32-byte Ed25519 verifying key.
    pub ed25519: [u8; 32],
    /// Raw 1952-byte FIPS 204 ML-DSA-65 verifying key.
    pub ml_dsa_65: Vec<u8>,
    /// Optional human-readable label (not security-critical).
    pub label: Option<String>,
    /// Optional maximum security epoch for which this key remains valid.
    pub not_after_epoch: Option<u64>,
    /// Whether this key is permitted to authorize [`KeyRotationStatement`]s.
    pub is_root: bool,
}

impl PublicKeyBundle {
    /// Construct and validate a [`PublicKeyBundle`] from raw Ed25519 (32B) and ML-DSA-65 (1952B) bytes.
    pub fn from_raw(ed25519: [u8; 32], ml_dsa_65: Vec<u8>) -> Result<Self> {
        // Validate Ed25519 curve point / encoding upfront.
        let _ = EdVerifyingKey::from_bytes(&ed25519)
            .map_err(|_| Error::InvalidEncoding("invalid ed25519 public key"))?;
        // Validate ML-DSA-65 key length upfront.
        let encoded_pqc = EncodedVerifyingKey::<MlDsa65>::try_from(ml_dsa_65.as_slice())
            .map_err(|_| Error::InvalidEncoding("invalid ml-dsa-65 public key length"))?;
        let _ = MlVerifyingKey::<MlDsa65>::new(&encoded_pqc);

        let key_id = KeyId::derive(&ed25519, &ml_dsa_65);
        Ok(Self {
            key_id,
            ed25519,
            ml_dsa_65,
            label: None,
            not_after_epoch: None,
            is_root: false,
        })
    }

    /// Parse a compact `sigilup-pk:v2:<base64url>` public key string.
    pub fn from_compact_str(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        let b64 = trimmed
            .strip_prefix(PK_STRING_PREFIX)
            .ok_or(Error::InvalidEncoding("missing 'sigilup-pk:v2:' prefix"))?;
        let raw = URL_SAFE_NO_PAD.decode(b64)?;
        if raw.len() < 32 {
            return Err(Error::InvalidEncoding("public key payload too short"));
        }
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&raw[..32]);
        let pqc = raw[32..].to_vec();
        Self::from_raw(ed, pqc)
    }

    /// Encode this bundle as a compact `sigilup-pk:v2:<base64url>` string for embedding.
    #[must_use]
    pub fn to_compact_str(&self) -> String {
        let mut raw = Vec::with_capacity(32 + self.ml_dsa_65.len());
        raw.extend_from_slice(&self.ed25519);
        raw.extend_from_slice(&self.ml_dsa_65);
        alloc::format!("{PK_STRING_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw))
    }

    /// Return the parsed `ed25519_dalek` verifying key.
    pub(crate) fn ed_verifying_key(&self) -> Result<EdVerifyingKey> {
        EdVerifyingKey::from_bytes(&self.ed25519)
            .map_err(|_| Error::InvalidEncoding("invalid ed25519 public key"))
    }

    /// Return the parsed `ml_dsa` verifying key.
    pub(crate) fn ml_verifying_key(&self) -> Result<MlVerifyingKey<MlDsa65>> {
        let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(self.ml_dsa_65.as_slice())
            .map_err(|_| Error::InvalidEncoding("invalid ml-dsa-65 public key length"))?;
        Ok(MlVerifyingKey::<MlDsa65>::new(&encoded))
    }

    /// Attach a descriptive label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Mark whether this key acts as a root key capable of signing key rotations.
    #[must_use]
    pub const fn with_root(mut self, is_root: bool) -> Self {
        self.is_root = is_root;
        self
    }

    /// Set the maximum security epoch this key is valid for.
    #[must_use]
    pub const fn with_not_after_epoch(mut self, epoch: u64) -> Self {
        self.not_after_epoch = Some(epoch);
        self
    }
}

impl fmt::Debug for PublicKeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKeyBundle")
            .field("key_id", &self.key_id)
            .field("label", &self.label)
            .field("not_after_epoch", &self.not_after_epoch)
            .field("is_root", &self.is_root)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyBundleRepr {
    version: u32,
    key_id: KeyId,
    public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    not_after_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "is_false")]
    is_root: bool,
}

const fn is_false(b: &bool) -> bool {
    !*b
}

impl Serialize for PublicKeyBundle {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        let repr = PublicKeyBundleRepr {
            version: 2,
            key_id: self.key_id,
            public_key: self.to_compact_str(),
            label: self.label.clone(),
            not_after_epoch: self.not_after_epoch,
            is_root: self.is_root,
        };
        repr.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKeyBundle {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        let repr = PublicKeyBundleRepr::deserialize(deserializer)?;
        if repr.version != 2 {
            return Err(serde::de::Error::custom(alloc::format!(
                "unsupported public key version {}",
                repr.version
            )));
        }
        let mut bundle =
            Self::from_compact_str(&repr.public_key).map_err(serde::de::Error::custom)?;
        if bundle.key_id != repr.key_id {
            return Err(serde::de::Error::custom("keyId does not match publicKey"));
        }
        bundle.label = repr.label;
        bundle.not_after_epoch = repr.not_after_epoch;
        bundle.is_root = repr.is_root;
        Ok(bundle)
    }
}

/// Set of trusted public keys, revocation state, and applied rotation epoch.
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    keys: BTreeMap<KeyId, PublicKeyBundle>,
    revoked: BTreeSet<KeyId>,
    rotation_epoch: u64,
}

impl TrustStore {
    /// Create an empty trust store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a trust store from an initial iterator of trusted keys.
    #[must_use]
    pub fn from_keys(keys: impl IntoIterator<Item = PublicKeyBundle>) -> Self {
        let mut store = Self::new();
        for key in keys {
            store.insert(key);
        }
        store
    }

    /// Insert or update a trusted public key (unless already revoked).
    pub fn insert(&mut self, key: PublicKeyBundle) {
        if !self.revoked.contains(&key.key_id) {
            self.keys.insert(key.key_id, key);
        }
    }

    /// Revoke a key ID and remove it from the active set.
    pub fn revoke(&mut self, key_id: KeyId) {
        self.keys.remove(&key_id);
        self.revoked.insert(key_id);
    }

    /// Look up an active, non-revoked key, checking epoch expiration if provided.
    pub fn get_active(&self, key_id: KeyId, current_epoch: u64) -> Result<&PublicKeyBundle> {
        if self.revoked.contains(&key_id) {
            return Err(Error::UntrustedKey(key_id.to_hex()));
        }
        let key = self
            .keys
            .get(&key_id)
            .ok_or_else(|| Error::UntrustedKey(key_id.to_hex()))?;
        if let Some(not_after) = key.not_after_epoch
            && current_epoch > not_after
        {
            return Err(Error::KeyExpired {
                key_id: key_id.to_hex(),
                not_after_epoch: not_after,
                current_epoch,
            });
        }
        Ok(key)
    }

    /// Return all active keys currently in the store.
    pub fn active_keys(&self) -> impl Iterator<Item = &PublicKeyBundle> {
        self.keys.values()
    }

    /// Current rotation epoch applied to this trust store.
    #[must_use]
    pub const fn rotation_epoch(&self) -> u64 {
        self.rotation_epoch
    }

    /// Return the set of revoked key IDs.
    pub fn revoked_keys(&self) -> impl Iterator<Item = &KeyId> {
        self.revoked.iter()
    }

    /// Apply a verified [`KeyRotationStatement`] signed by at least one active root key.
    pub fn apply_rotation(&mut self, statement: &KeyRotationStatement) -> Result<()> {
        if statement.rotation_epoch <= self.rotation_epoch {
            return Err(Error::PolicyRejected(alloc::format!(
                "stale key rotation epoch {} (current {})",
                statement.rotation_epoch,
                self.rotation_epoch
            )));
        }
        for revoked in &statement.revoke_keys {
            self.revoke(*revoked);
        }
        for added in &statement.add_keys {
            if !self.revoked.contains(&added.key_id) {
                self.keys.insert(added.key_id, added.clone());
            }
        }
        self.rotation_epoch = statement.rotation_epoch;
        Ok(())
    }
}

/// Root-signed statement authorizing new keys and/or revoking compromised keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRotationStatement {
    /// Statement schema version (`2`).
    pub version: u32,
    /// Strictly increasing rotation epoch.
    pub rotation_epoch: u64,
    /// Unix timestamp when the rotation statement was issued.
    pub issued_at: u64,
    /// New keys added to the trust store.
    #[serde(default)]
    pub add_keys: Vec<PublicKeyBundle>,
    /// Key IDs permanently revoked by this statement.
    #[serde(default)]
    pub revoke_keys: Vec<KeyId>,
}

/// Zeroizing hybrid secret key pair (Ed25519 seed + ML-DSA-65 seed).
///
/// Unlike legacy `minisign`:
/// - `Debug` is explicitly redacted and never leaks key bytes.
/// - Seeds are held in `Zeroizing<[u8; 32]>` and wiped on drop.
/// - Encrypted storage uses Argon2id + XChaCha20 + BLAKE3 keyed MAC (Encrypt-then-MAC)
///   with constant-time MAC verification and zero terminal/TTY side effects.
#[cfg(feature = "sign")]
#[derive(Clone)]
pub struct SecretKeyBundle {
    ed25519_seed: Zeroizing<[u8; 32]>,
    ml_dsa_seed: Zeroizing<[u8; 32]>,
    public: PublicKeyBundle,
}

#[cfg(feature = "sign")]
impl fmt::Debug for SecretKeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKeyBundle")
            .field("key_id", &self.public.key_id)
            .field("label", &self.public.label)
            .field("is_root", &self.public.is_root)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "sign")]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedSecretKeyFile {
    version: u32,
    key_id: KeyId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    is_root: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    not_after_epoch: Option<u64>,
    kdf: String,
    cipher: String,
    salt: String,
    nonce: String,
    ciphertext: String,
    mac: String,
}

#[cfg(feature = "sign")]
impl SecretKeyBundle {
    /// Generate a fresh random hybrid keypair using OS entropy (`getrandom`).
    pub fn generate() -> Result<Self> {
        let mut ed_seed = Zeroizing::new([0u8; 32]);
        let mut pqc_seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *ed_seed).map_err(|_| Error::SigningFailed("getrandom failed"))?;
        getrandom::fill(&mut *pqc_seed).map_err(|_| Error::SigningFailed("getrandom failed"))?;
        Self::from_seeds(*ed_seed, *pqc_seed)
    }

    /// Deterministically derive a hybrid keypair from 32-byte Ed25519 and ML-DSA-65 seeds.
    pub fn from_seeds(ed25519_seed: [u8; 32], ml_dsa_seed: [u8; 32]) -> Result<Self> {
        let ed_seed = Zeroizing::new(ed25519_seed);
        let pqc_seed = Zeroizing::new(ml_dsa_seed);

        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&ed_seed);
        let ed_pk = ed_sk.verifying_key().to_bytes();

        let ml_seed = ml_dsa::Seed::from(*pqc_seed);
        let ml_sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&ml_seed);
        let ml_pk = ml_sk.verifying_key().to_bytes().to_vec();

        let public = PublicKeyBundle::from_raw(ed_pk, ml_pk)?;
        Ok(Self {
            ed25519_seed: ed_seed,
            ml_dsa_seed: pqc_seed,
            public,
        })
    }

    /// Parse a compact unencrypted CI seed string (`sigilup-sk:v2:<base64url>`).
    pub fn from_raw_seed_str(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        let b64 = trimmed
            .strip_prefix(SK_RAW_STRING_PREFIX)
            .ok_or(Error::InvalidEncoding("missing 'sigilup-sk:v2:' prefix"))?;
        let mut raw = Zeroizing::new(URL_SAFE_NO_PAD.decode(b64)?);
        if raw.len() != 64 {
            return Err(Error::InvalidEncoding("raw secret key must be 64 bytes"));
        }
        let mut ed = Zeroizing::new([0u8; 32]);
        let mut pqc = Zeroizing::new([0u8; 32]);
        ed.copy_from_slice(&raw[..32]);
        pqc.copy_from_slice(&raw[32..64]);
        raw.zeroize();
        Self::from_seeds(*ed, *pqc)
    }

    /// Encode the unencrypted 64-byte seed pair (`sigilup-sk:v2:<base64url>`).
    ///
    /// Suitable for secret managers (e.g. GitHub Actions Secrets / KMS).
    #[must_use]
    pub fn to_raw_seed_str(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new([0u8; 64]);
        raw[..32].copy_from_slice(&*self.ed25519_seed);
        raw[32..64].copy_from_slice(&*self.ml_dsa_seed);
        Zeroizing::new(alloc::format!(
            "{SK_RAW_STRING_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(*raw)
        ))
    }

    /// Encrypt this secret key using Argon2id + XChaCha20 + BLAKE3 keyed MAC.
    pub fn to_encrypted_json(&self, password: &[u8]) -> Result<String> {
        use chacha20::XChaCha20;
        use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut salt).map_err(|_| Error::SigningFailed("getrandom salt failed"))?;
        getrandom::fill(&mut nonce).map_err(|_| Error::SigningFailed("getrandom nonce failed"))?;

        let mut derived = Zeroizing::new([0u8; 64]);
        argon2::Argon2::default()
            .hash_password_into(password, &salt, &mut *derived)
            .map_err(|_| Error::SigningFailed("argon2id key derivation failed"))?;

        let mut enc_key = Zeroizing::new([0u8; 32]);
        let mut mac_key = Zeroizing::new([0u8; 32]);
        enc_key.copy_from_slice(&derived[..32]);
        mac_key.copy_from_slice(&derived[32..64]);

        let mut buf = Zeroizing::new([0u8; 64]);
        buf[..32].copy_from_slice(&*self.ed25519_seed);
        buf[32..64].copy_from_slice(&*self.ml_dsa_seed);

        let mut cipher = XChaCha20::new((&*enc_key).into(), (&nonce).into());
        cipher.apply_keystream(&mut *buf);

        let mac = compute_sk_mac(&mac_key, self.public.key_id, &salt, &nonce, &*buf);

        let file = EncryptedSecretKeyFile {
            version: 2,
            key_id: self.public.key_id,
            label: self.public.label.clone(),
            is_root: self.public.is_root,
            not_after_epoch: self.public.not_after_epoch,
            kdf: "argon2id".to_string(),
            cipher: "xchacha20-blake3mac".to_string(),
            salt: URL_SAFE_NO_PAD.encode(salt),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(*buf),
            mac: URL_SAFE_NO_PAD.encode(mac),
        };
        Ok(serde_json::to_string_pretty(&file)?)
    }

    /// Decrypt a secret key JSON file produced by [`Self::to_encrypted_json`].
    pub fn from_encrypted_json(json_text: &str, password: &[u8]) -> Result<Self> {
        use chacha20::XChaCha20;
        use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};

        let file: EncryptedSecretKeyFile = serde_json::from_str(json_text)?;
        if file.version != 2 {
            return Err(Error::UnsupportedVersion(file.version));
        }
        if file.kdf != "argon2id" || file.cipher != "xchacha20-blake3mac" {
            return Err(Error::InvalidEncoding("unsupported key encryption suite"));
        }

        let salt = URL_SAFE_NO_PAD.decode(&file.salt)?;
        let nonce_vec = URL_SAFE_NO_PAD.decode(&file.nonce)?;
        let mut ct = Zeroizing::new(URL_SAFE_NO_PAD.decode(&file.ciphertext)?);
        let mac_vec = URL_SAFE_NO_PAD.decode(&file.mac)?;

        if salt.len() != 16 || nonce_vec.len() != 24 || ct.len() != 64 || mac_vec.len() != 32 {
            return Err(Error::InvalidEncoding("malformed encrypted key fields"));
        }

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_vec);

        let mut derived = Zeroizing::new([0u8; 64]);
        argon2::Argon2::default()
            .hash_password_into(password, &salt, &mut *derived)
            .map_err(|_| Error::DecryptionFailed("argon2id derivation failed"))?;

        let mut enc_key = Zeroizing::new([0u8; 32]);
        let mut mac_key = Zeroizing::new([0u8; 32]);
        enc_key.copy_from_slice(&derived[..32]);
        mac_key.copy_from_slice(&derived[32..64]);

        let expected_mac = compute_sk_mac(&mac_key, file.key_id, &salt, &nonce, &ct);
        if !bool::from(expected_mac.ct_eq(mac_vec.as_slice())) {
            return Err(Error::DecryptionFailed(
                "wrong password or tampered key file",
            ));
        }

        let mut cipher = XChaCha20::new((&*enc_key).into(), (&nonce).into());
        cipher.apply_keystream(&mut ct);

        let mut ed = Zeroizing::new([0u8; 32]);
        let mut pqc = Zeroizing::new([0u8; 32]);
        ed.copy_from_slice(&ct[..32]);
        pqc.copy_from_slice(&ct[32..64]);

        let mut sk = Self::from_seeds(*ed, *pqc)?;
        if sk.public.key_id != file.key_id {
            return Err(Error::DecryptionFailed("keyId mismatch after decryption"));
        }
        sk.public.label = file.label;
        sk.public.is_root = file.is_root;
        sk.public.not_after_epoch = file.not_after_epoch;
        Ok(sk)
    }

    /// Borrow the corresponding [`PublicKeyBundle`].
    #[must_use]
    pub const fn public_key(&self) -> &PublicKeyBundle {
        &self.public
    }

    /// Attach metadata label to the derived public key.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.public.label = Some(label.into());
        self
    }

    /// Mark whether this key acts as a root key.
    #[must_use]
    pub const fn with_root(mut self, is_root: bool) -> Self {
        self.public.is_root = is_root;
        self
    }

    /// Set the maximum security epoch for the derived public key.
    #[must_use]
    pub const fn with_not_after_epoch(mut self, epoch: u64) -> Self {
        self.public.not_after_epoch = Some(epoch);
        self
    }

    pub(crate) fn ed_signing_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.ed25519_seed)
    }

    pub(crate) fn ml_signing_key(&self) -> ml_dsa::SigningKey<MlDsa65> {
        ml_dsa::SigningKey::<MlDsa65>::from_seed(&ml_dsa::Seed::from(*self.ml_dsa_seed))
    }
}

#[cfg(feature = "sign")]
fn compute_sk_mac(
    mac_key: &[u8; 32],
    key_id: KeyId,
    salt: &[u8],
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(b"sigilup-sk-v2");
    hasher.update(&key_id.0);
    hasher.update(salt);
    hasher.update(nonce);
    hasher.update(ciphertext);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[cfg(feature = "sign")]
    #[test]
    fn encrypted_secret_key_round_trips_and_rejects_wrong_password() {
        let sk = SecretKeyBundle::generate()
            .unwrap()
            .with_label("release-2026")
            .with_root(true);
        let json = sk
            .to_encrypted_json(b"correct-horse-battery-staple")
            .unwrap();

        let loaded =
            SecretKeyBundle::from_encrypted_json(&json, b"correct-horse-battery-staple").unwrap();
        assert_eq!(loaded.public_key(), sk.public_key());

        let err = SecretKeyBundle::from_encrypted_json(&json, b"wrong-password").unwrap_err();
        assert!(matches!(err, Error::DecryptionFailed(_)));

        // Debug must never leak seed bytes
        let debug = alloc::format!("{loaded:?}");
        assert!(debug.contains(&loaded.public_key().key_id.to_hex()));
        assert!(!debug.contains("ed25519_seed"));
    }

    #[cfg(feature = "sign")]
    #[test]
    fn compact_public_and_raw_secret_round_trip() {
        let sk = SecretKeyBundle::from_seeds([0x11; 32], [0x22; 32]).unwrap();
        let raw_sk = sk.to_raw_seed_str();
        let loaded = SecretKeyBundle::from_raw_seed_str(&raw_sk).unwrap();
        assert_eq!(loaded.public_key().key_id, sk.public_key().key_id);

        let pk_str = sk.public_key().to_compact_str();
        let parsed_pk = PublicKeyBundle::from_compact_str(&pk_str).unwrap();
        assert_eq!(parsed_pk.key_id, sk.public_key().key_id);
        assert_eq!(parsed_pk.ed25519, sk.public_key().ed25519);
        assert_eq!(parsed_pk.ml_dsa_65, sk.public_key().ml_dsa_65);
    }
}
