use crate::envelope::{HybridEnvelope, SignatureEntry};
use crate::error::Result;
use crate::keys::KeyId;
use crate::pae::pae_encode;

/// Abstraction over signing backends (local seed, HSM, Cloud KMS, Sigstore, etc.).
pub trait SignerBackend {
    /// Key ID of this signing identity.
    fn key_id(&self) -> KeyId;

    /// Sign pre-encoded DSSE PAE bytes and return a [`SignatureEntry`].
    fn sign_pae(&self, pae: &[u8], created_at: u64) -> Result<SignatureEntry>;
}

impl HybridEnvelope {
    /// Sign using any [`SignerBackend`] (e.g. KMS, HSM, or local key).
    pub fn add_signature_with_backend(
        &mut self,
        backend: &dyn SignerBackend,
        created_at: u64,
    ) -> Result<()> {
        let raw_payload = self.decode_payload()?;
        let pae = pae_encode(&self.payload_type, &raw_payload);
        let entry = backend.sign_pae(&pae, created_at)?;
        self.signatures.push(entry);
        Ok(())
    }
}

#[cfg(feature = "sign")]
impl SignerBackend for crate::keys::SecretKeyBundle {
    fn key_id(&self) -> KeyId {
        self.public_key().key_id
    }

    fn sign_pae(&self, pae: &[u8], created_at: u64) -> Result<SignatureEntry> {
        crate::envelope::sign_pae_entry(self, pae, created_at)
    }
}

/// Persistence abstraction for monotonic anti-rollback state (highest seen `security_epoch`).
pub trait EpochStore {
    /// Load the highest persisted security epoch (`0` if none recorded yet).
    fn load_min_epoch(&self) -> Result<u64>;

    /// Persist a new highest security epoch atomically.
    fn save_min_epoch(&mut self, epoch: u64) -> Result<()>;
}
