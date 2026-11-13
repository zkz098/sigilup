use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::Signature as EdSignature;
use ml_dsa::{MlDsa65, Signature as MlSignature};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::keys::{KeyId, ML_DSA_DSSE_CONTEXT, PublicKeyBundle, TrustStore};
use crate::pae::pae_encode;
use crate::policy::VerificationPolicy;

/// A single hybrid signature attached to a [`HybridEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureEntry {
    /// Key identifier used to produce this signature.
    pub key_id: KeyId,
    /// Base64-encoded 64-byte Ed25519 signature over the DSSE PAE bytes.
    pub ed25519: String,
    /// Base64-encoded FIPS 204 ML-DSA-65 signature over the DSSE PAE bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_dsa_65: Option<String>,
    /// Unix timestamp (seconds) when this signature was created.
    pub created_at: u64,
}

/// Self-contained DSSEv1 hybrid signature envelope (`Ed25519` + `ML-DSA-65`).
///
/// The signed payload bytes are stored verbatim in base64url (`payload`), so
/// whitespace/formatting differences in outer JSON containers never break
/// verification. All signatures sign `pae_encode(payload_type, raw_payload)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HybridEnvelope {
    /// Envelope schema version (`2`).
    pub version: u32,
    /// Media-type / domain identifier bound by DSSE PAE.
    pub payload_type: String,
    /// Base64url (unpadded) raw signed payload bytes.
    pub payload: String,
    /// One or more hybrid signatures over the PAE encoding of `(payload_type, payload)`.
    pub signatures: Vec<SignatureEntry>,
}

/// Outcome returned after successfully verifying a [`HybridEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEnvelope {
    /// Raw verified payload bytes (decoded from `payload`).
    pub payload: Vec<u8>,
    /// Key IDs of the signatures that passed verification.
    pub verified_keys: Vec<KeyId>,
    /// True if every counted signature passed ML-DSA-65 post-quantum verification.
    pub all_pqc_verified: bool,
}

impl HybridEnvelope {
    /// Construct an unsigned envelope from a `payload_type` and raw `payload` bytes.
    #[must_use]
    pub fn new(payload_type: impl Into<String>, payload: &[u8]) -> Self {
        Self {
            version: 2,
            payload_type: payload_type.into(),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signatures: Vec::new(),
        }
    }

    /// Sign a payload with a [`crate::keys::SecretKeyBundle`] and return a signed [`HybridEnvelope`].
    #[cfg(feature = "sign")]
    pub fn sign(
        sk: &crate::keys::SecretKeyBundle,
        payload_type: impl Into<String>,
        payload: &[u8],
        created_at: u64,
    ) -> Result<Self> {
        let mut env = Self::new(payload_type, payload);
        env.add_signature(sk, created_at)?;
        Ok(env)
    }

    /// Append an additional signature to an existing envelope (for multi-sig or key rotation).
    #[cfg(feature = "sign")]
    pub fn add_signature(
        &mut self,
        sk: &crate::keys::SecretKeyBundle,
        created_at: u64,
    ) -> Result<()> {
        let raw_payload = self.decode_payload()?;
        let pae = pae_encode(&self.payload_type, &raw_payload);
        let entry = sign_pae_entry(sk, &pae, created_at)?;
        self.signatures.push(entry);
        Ok(())
    }

    /// Decode raw payload bytes *without* verifying signatures.
    ///
    /// Prefer [`Self::verify`] so untrusted payload bytes are authenticated before parsing.
    pub fn decode_payload(&self) -> Result<Vec<u8>> {
        if self.version != 2 {
            return Err(Error::UnsupportedVersion(self.version));
        }
        Ok(URL_SAFE_NO_PAD.decode(self.payload.trim())?)
    }

    /// Verify this envelope against `expected_payload_type`, `trust_store`, `policy`, and `current_epoch`.
    ///
    /// Rejects untrusted keys, expired keys, invalid classical/PQC signatures, and duplicate
    /// signatures from the same key ID. Returns the authenticated payload bytes only on success.
    pub fn verify(
        &self,
        expected_payload_type: &str,
        trust_store: &TrustStore,
        policy: VerificationPolicy,
        current_epoch: u64,
    ) -> Result<VerifiedEnvelope> {
        self.verify_inner(
            expected_payload_type,
            trust_store,
            policy,
            current_epoch,
            false,
        )
    }

    /// Same as [`Self::verify`], but additionally requires at least one root key signature.
    pub fn verify_root_signed(
        &self,
        expected_payload_type: &str,
        trust_store: &TrustStore,
        policy: VerificationPolicy,
        current_epoch: u64,
    ) -> Result<VerifiedEnvelope> {
        self.verify_inner(
            expected_payload_type,
            trust_store,
            policy,
            current_epoch,
            true,
        )
    }

    fn verify_inner(
        &self,
        expected_payload_type: &str,
        trust_store: &TrustStore,
        policy: VerificationPolicy,
        current_epoch: u64,
        require_root: bool,
    ) -> Result<VerifiedEnvelope> {
        if self.version != 2 {
            return Err(Error::UnsupportedVersion(self.version));
        }
        if self.payload_type != expected_payload_type {
            return Err(Error::PayloadTypeMismatch {
                expected: leak_or_static_hint(expected_payload_type),
                actual: self.payload_type.clone(),
            });
        }
        let raw_payload = self.decode_payload()?;
        let pae = pae_encode(&self.payload_type, &raw_payload);

        let required = policy.min_signatures().max(1);
        let mut seen_keys = BTreeSet::new();
        let mut verified_keys = Vec::new();
        let mut all_pqc_verified = true;

        for sig in &self.signatures {
            if !seen_keys.insert(sig.key_id) {
                continue;
            }
            let key = match trust_store.get_active(sig.key_id, current_epoch) {
                Ok(k) => k,
                Err(Error::UntrustedKey(_)) => continue,
                Err(e) => return Err(e),
            };
            if require_root && !key.is_root {
                continue;
            }
            let pqc_ok = verify_single_signature(key, &pae, sig, policy)?;
            all_pqc_verified &= pqc_ok;
            verified_keys.push(sig.key_id);
        }

        if verified_keys.len() < required {
            return Err(Error::InsufficientSignatures {
                required,
                verified: verified_keys.len(),
            });
        }

        Ok(VerifiedEnvelope {
            payload: raw_payload,
            verified_keys,
            all_pqc_verified,
        })
    }
}

/// Produce a [`SignatureEntry`] over DSSE PAE bytes using `sk`.
#[cfg(feature = "sign")]
pub(crate) fn sign_pae_entry(
    sk: &crate::keys::SecretKeyBundle,
    pae: &[u8],
    created_at: u64,
) -> Result<SignatureEntry> {
    use ed25519_dalek::Signer as _;
    use ml_dsa::SignatureEncoding as _;

    let ed_sk = sk.ed_signing_key();
    let ed_sig = ed_sk.sign(pae);

    let ml_sk = sk.ml_signing_key();
    let mut rng_bytes = [0u8; 32];
    getrandom::fill(&mut rng_bytes).map_err(|_| Error::SigningFailed("getrandom failed"))?;
    let mut rng = FixedOrOsRng;
    let ml_sig = ml_sk
        .expanded_key()
        .sign_randomized(pae, ML_DSA_DSSE_CONTEXT, &mut rng)
        .map_err(|_| Error::SigningFailed("ml-dsa-65 signing failed"))?;

    Ok(SignatureEntry {
        key_id: sk.public_key().key_id,
        ed25519: STANDARD.encode(ed_sig.to_bytes()),
        ml_dsa_65: Some(STANDARD.encode(ml_sig.to_bytes())),
        created_at,
    })
}

#[cfg(feature = "sign")]
struct FixedOrOsRng;

#[cfg(feature = "sign")]
impl ml_dsa::signature::rand_core::TryRng for FixedOrOsRng {
    type Error = getrandom::Error;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        getrandom::fill(dst)
    }
}

#[cfg(feature = "sign")]
impl ml_dsa::signature::rand_core::TryCryptoRng for FixedOrOsRng {}

fn verify_single_signature(
    key: &PublicKeyBundle,
    pae: &[u8],
    entry: &SignatureEntry,
    policy: VerificationPolicy,
) -> Result<bool> {
    let key_hex = key.key_id.to_hex();

    // 1. Always verify Ed25519 strictly (rejects malleable / small-subgroup signatures).
    let ed_bytes = decode_sig_b64(&entry.ed25519)?;
    let ed_arr: [u8; 64] = ed_bytes
        .try_into()
        .map_err(|_| Error::InvalidEd25519Signature(key_hex.clone()))?;
    let ed_sig = EdSignature::from_bytes(&ed_arr);
    let ed_pk = key.ed_verifying_key()?;
    ed_pk
        .verify_strict(pae, &ed_sig)
        .map_err(|_| Error::InvalidEd25519Signature(key_hex.clone()))?;

    // 2. Verify ML-DSA-65 according to VerificationPolicy.
    match (&entry.ml_dsa_65, policy) {
        (Some(pqc_b64), _) => {
            let pqc_bytes = decode_sig_b64(pqc_b64)?;
            let pqc_sig = MlSignature::<MlDsa65>::try_from(pqc_bytes.as_slice())
                .map_err(|_| Error::InvalidMlDsaSignature(key_hex.clone()))?;
            let ml_pk = key.ml_verifying_key()?;
            if !ml_pk.verify_with_context(pae, ML_DSA_DSSE_CONTEXT, &pqc_sig) {
                return Err(Error::InvalidMlDsaSignature(key_hex));
            }
            Ok(true)
        }
        (None, VerificationPolicy::HybridStrict { .. }) => {
            Err(Error::MissingMlDsaSignature(key_hex))
        }
        (
            None,
            VerificationPolicy::ClassicalOnly { .. }
            | VerificationPolicy::TransitionalAllowMissingPqc { .. },
        ) => Ok(false),
    }
}

fn decode_sig_b64(s: &str) -> Result<Vec<u8>> {
    let trimmed = s.trim();
    if let Ok(bytes) = STANDARD.decode(trimmed) {
        return Ok(bytes);
    }
    Ok(URL_SAFE_NO_PAD.decode(trimmed)?)
}

fn leak_or_static_hint(expected: &str) -> &'static str {
    if expected == crate::digest::ARTIFACT_DESCRIPTOR_PAYLOAD_TYPE {
        crate::digest::ARTIFACT_DESCRIPTOR_PAYLOAD_TYPE
    } else if expected == crate::keys::KEY_ROTATION_PAYLOAD_TYPE {
        crate::keys::KEY_ROTATION_PAYLOAD_TYPE
    } else {
        "expected payload type"
    }
}

#[cfg(all(test, feature = "sign"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::keys::SecretKeyBundle;

    #[test]
    fn hybrid_envelope_signs_verifies_and_rejects_tampering() {
        let sk = SecretKeyBundle::generate().unwrap();
        let store = TrustStore::from_keys([sk.public_key().clone()]);

        let mut env = HybridEnvelope::sign(&sk, "application/test", b"hello sigilup", 100).unwrap();
        let verified = env
            .verify("application/test", &store, VerificationPolicy::strict(), 1)
            .unwrap();
        assert_eq!(verified.payload, b"hello sigilup");
        assert!(verified.all_pqc_verified);
        assert_eq!(verified.verified_keys, alloc::vec![sk.public_key().key_id]);

        // Wrong payload type must fail (PAE domain separation)
        let err = env
            .verify("application/other", &store, VerificationPolicy::strict(), 1)
            .unwrap_err();
        assert!(matches!(err, Error::PayloadTypeMismatch { .. }));

        // Stripping ML-DSA-65 signature must fail closed under strict policy
        env.signatures[0].ml_dsa_65 = None;
        let err = env
            .verify("application/test", &store, VerificationPolicy::strict(), 1)
            .unwrap_err();
        assert!(matches!(err, Error::MissingMlDsaSignature(_)));

        // Transitional policy accepts missing PQC and reports all_pqc_verified == false
        let ok = env
            .verify(
                "application/test",
                &store,
                VerificationPolicy::TransitionalAllowMissingPqc { min_signatures: 1 },
                1,
            )
            .unwrap();
        assert!(!ok.all_pqc_verified);
    }

    #[test]
    fn multi_signature_quorum_rejects_duplicate_same_key() {
        let sk1 = SecretKeyBundle::generate().unwrap();
        let sk2 = SecretKeyBundle::generate().unwrap();
        let store = TrustStore::from_keys([sk1.public_key().clone(), sk2.public_key().clone()]);

        let mut env = HybridEnvelope::sign(&sk1, "application/test", b"quorum", 100).unwrap();
        // Adding same key twice must NOT satisfy min_signatures = 2
        env.add_signature(&sk1, 101).unwrap();
        let err = env
            .verify(
                "application/test",
                &store,
                VerificationPolicy::HybridStrict { min_signatures: 2 },
                1,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            Error::InsufficientSignatures {
                required: 2,
                verified: 1
            }
        ));

        // Second distinct key satisfies quorum
        env.add_signature(&sk2, 102).unwrap();
        let ok = env
            .verify(
                "application/test",
                &store,
                VerificationPolicy::HybridStrict { min_signatures: 2 },
                1,
            )
            .unwrap();
        assert_eq!(ok.verified_keys.len(), 2);
    }
}
