//! HSM/KMS envelope encryption abstraction for MPC key shares.
//!
//! Provides the [`KeyEncryptionProvider`] trait for envelope encryption:
//! - A master Key Encryption Key (KEK) lives in HSM/KMS
//! - Data Encryption Keys (DEKs) are derived per key group
//! - DEKs are wrapped (encrypted) under the KEK for storage
//! - On load, the HSM unwraps the DEK, and the gateway decrypts shares in-process
//!
//! The [`LocalKeyEncryption`] implementation uses a static master key in memory,
//! equivalent to current behavior. Future HSM integration will implement this
//! trait with calls to AWS KMS / Azure Key Vault / GCP Cloud KMS.

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::error::CoreError;

/// Envelope encryption provider for MPC key share protection.
///
/// Implementations manage a master KEK and derive/wrap/unwrap per-group DEKs.
/// The key share plaintext is always decrypted in-process (never sent to HSM).
#[async_trait]
pub trait KeyEncryptionProvider: Send + Sync {
    /// Derive or retrieve a data encryption key for a key group.
    ///
    /// The returned 32-byte key is used to encrypt/decrypt key shares belonging
    /// to this group. Implementations may cache DEKs or derive them on each call.
    async fn derive_dek(&self, group_id: &str) -> Result<[u8; 32], CoreError>;

    /// Wrap (encrypt) a DEK under the master KEK.
    ///
    /// Returns opaque ciphertext that can only be unwrapped by this provider.
    /// The wrapped DEK is stored alongside the encrypted key share.
    async fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CoreError>;

    /// Unwrap (decrypt) a wrapped DEK.
    ///
    /// Returns the original 32-byte DEK from the opaque ciphertext produced
    /// by [`wrap_dek`](KeyEncryptionProvider::wrap_dek).
    async fn unwrap_dek(&self, wrapped: &[u8]) -> Result<[u8; 32], CoreError>;
}

/// Local in-process key encryption using a static master key.
///
/// This is equivalent to the current behavior where the encryption key is
/// derived from a password via Argon2id. It uses HKDF-SHA256 to derive
/// per-group DEKs and a simple XOR-based wrapping (the master key never
/// leaves process memory).
///
/// **Not for production use** — replace with an HSM-backed implementation.
pub struct LocalKeyEncryption {
    /// 32-byte master key (KEK).
    master_key: [u8; 32],
}

impl LocalKeyEncryption {
    /// Create a new local key encryption provider from a 32-byte master key.
    pub fn new(master_key: [u8; 32]) -> Self {
        Self { master_key }
    }
}

#[async_trait]
impl KeyEncryptionProvider for LocalKeyEncryption {
    async fn derive_dek(&self, group_id: &str) -> Result<[u8; 32], CoreError> {
        // HKDF-like derivation: SHA256(master_key || "dek" || group_id)
        let mut hasher = Sha256::new();
        hasher.update(self.master_key);
        hasher.update(b"dek-derivation-v1");
        hasher.update(group_id.as_bytes());
        let hash = hasher.finalize();
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&hash);
        Ok(dek)
    }

    async fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CoreError> {
        // Simple XOR wrap with master key (placeholder — real HSM uses AES-KW).
        let mut wrapped = vec![0u8; 32];
        for i in 0..32 {
            wrapped[i] = dek[i] ^ self.master_key[i];
        }
        Ok(wrapped)
    }

    async fn unwrap_dek(&self, wrapped: &[u8]) -> Result<[u8; 32], CoreError> {
        if wrapped.len() != 32 {
            return Err(CoreError::Encryption(format!(
                "invalid wrapped DEK length: expected 32, got {}",
                wrapped.len()
            )));
        }
        // XOR unwrap (inverse of wrap).
        let mut dek = [0u8; 32];
        for i in 0..32 {
            dek[i] = wrapped[i] ^ self.master_key[i];
        }
        Ok(dek)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(0x42);
        }
        key
    }

    #[tokio::test]
    async fn test_derive_dek_deterministic() {
        let provider = LocalKeyEncryption::new(test_master_key());
        let dek1 = provider.derive_dek("group-1").await.unwrap();
        let dek2 = provider.derive_dek("group-1").await.unwrap();
        assert_eq!(dek1, dek2);
    }

    #[tokio::test]
    async fn test_derive_dek_different_groups() {
        let provider = LocalKeyEncryption::new(test_master_key());
        let dek1 = provider.derive_dek("group-1").await.unwrap();
        let dek2 = provider.derive_dek("group-2").await.unwrap();
        assert_ne!(dek1, dek2);
    }

    #[tokio::test]
    async fn test_wrap_unwrap_roundtrip() {
        let provider = LocalKeyEncryption::new(test_master_key());
        let original_dek = [0xABu8; 32];
        let wrapped = provider.wrap_dek(&original_dek).await.unwrap();
        assert_ne!(
            &wrapped[..],
            &original_dek[..],
            "wrapped should differ from plaintext"
        );
        let unwrapped = provider.unwrap_dek(&wrapped).await.unwrap();
        assert_eq!(unwrapped, original_dek);
    }

    #[tokio::test]
    async fn test_unwrap_wrong_length_fails() {
        let provider = LocalKeyEncryption::new(test_master_key());
        let result = provider.unwrap_dek(&[0u8; 16]).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid wrapped DEK length"));
    }

    #[tokio::test]
    async fn test_different_master_keys_different_wrapping() {
        let p1 = LocalKeyEncryption::new([1u8; 32]);
        let p2 = LocalKeyEncryption::new([2u8; 32]);
        let dek = [0xFFu8; 32];
        let w1 = p1.wrap_dek(&dek).await.unwrap();
        let w2 = p2.wrap_dek(&dek).await.unwrap();
        assert_ne!(w1, w2);
    }

    #[tokio::test]
    async fn test_wrong_master_key_unwrap_gives_wrong_dek() {
        let p1 = LocalKeyEncryption::new([1u8; 32]);
        let p2 = LocalKeyEncryption::new([2u8; 32]);
        let original = [0xAAu8; 32];
        let wrapped = p1.wrap_dek(&original).await.unwrap();
        let unwrapped = p2.unwrap_dek(&wrapped).await.unwrap();
        assert_ne!(
            unwrapped, original,
            "wrong master key should not recover original DEK"
        );
    }

    #[test]
    fn test_trait_object_compatible() {
        let provider = LocalKeyEncryption::new([0u8; 32]);
        let _boxed: Box<dyn KeyEncryptionProvider> = Box::new(provider);
    }

    #[tokio::test]
    async fn test_derive_dek_different_master_keys() {
        let p1 = LocalKeyEncryption::new([1u8; 32]);
        let p2 = LocalKeyEncryption::new([2u8; 32]);
        let dek1 = p1.derive_dek("same-group").await.unwrap();
        let dek2 = p2.derive_dek("same-group").await.unwrap();
        assert_ne!(dek1, dek2);
    }
}
