use std::path::PathBuf;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::key_store::types::{KeyGroupId, KeyMetadata};
use crate::key_store::KeyStore;
use crate::protocol::KeyShare;
use crate::types::PartyId;

/// Argon2id parameters for wallet-class key derivation (SEC-006 hardened).
///
/// - m_cost: 65536 KiB (64 MiB) — memory hardness
/// - t_cost: 3 iterations
/// - p_cost: 4 parallelism lanes
/// - output:  32 bytes (AES-256 key)
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

/// File-based encrypted key storage using AES-256-GCM + Argon2id.
pub struct EncryptedFileStore {
    base_dir: PathBuf,
    /// Password is stored as `Zeroizing<String>` so it is wiped from memory
    /// when the `EncryptedFileStore` is dropped (SEC-005 fix).
    password: Zeroizing<String>,
}

impl EncryptedFileStore {
    /// Create a new `EncryptedFileStore` rooted at `base_dir`.
    ///
    /// Key shares are stored as AES-256-GCM encrypted files under subdirectories
    /// of `base_dir`, one subdirectory per key group. The `password` is used
    /// with Argon2id key derivation (64 MiB / 3 iterations / 4 lanes) to produce
    /// the AES key for each encrypt/decrypt operation. The password is wrapped in
    /// `Zeroizing<String>` and is wiped from memory when this struct is dropped
    /// (SEC-005 fix).
    ///
    /// **Encrypted file format** (as of T-S3-02):
    /// `salt (32 bytes) | nonce (12 bytes) | ciphertext`
    ///
    /// Note: this format is incompatible with files produced before T-S3-02,
    /// which used a 16-byte salt. All test files use `tempdir()` and are ephemeral,
    /// so no migration is required.
    ///
    /// The directory is created on first `save`; it need not exist when this
    /// constructor is called.
    pub fn new(base_dir: PathBuf, password: &str) -> Self {
        Self {
            base_dir,
            password: Zeroizing::new(password.to_string()),
        }
    }

    fn derive_key(&self, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CoreError> {
        // SEC-006: use hardened Argon2id parameters instead of weak defaults.
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|e| CoreError::Encryption(format!("Argon2 params error: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // SEC-005: wrap password bytes in Zeroizing so they are wiped after use.
        let password_bytes = Zeroizing::new(self.password.as_bytes().to_vec());

        // SEC-005: wrap derived key in Zeroizing so it is wiped after use.
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password_bytes.as_slice(), salt, key_bytes.as_mut())
            .map_err(|e| CoreError::Encryption(format!("Key derivation failed: {e}")))?;

        Ok(key_bytes)
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CoreError> {
        use rand::RngCore;

        // SEC-006: 32-byte salt (upgraded from 16) for stronger KDF salt.
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let key_bytes = self.derive_key(&salt)?;
        let cipher = Aes256Gcm::new_from_slice(key_bytes.as_ref())
            .map_err(|e| CoreError::Encryption(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| CoreError::Encryption(e.to_string()))?;

        // Format: salt (32) + nonce (12) + ciphertext
        let mut result = Vec::with_capacity(32 + 12 + ciphertext.len());
        result.extend_from_slice(&salt);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CoreError> {
        // Minimum: salt (32) + nonce (12) = 44 bytes
        if data.len() < 44 {
            return Err(CoreError::Encryption("encrypted data too short".into()));
        }

        let salt = &data[..32];
        let nonce = Nonce::from_slice(&data[32..44]);
        let ciphertext = &data[44..];

        let key_bytes = self.derive_key(salt)?;
        let cipher = Aes256Gcm::new_from_slice(key_bytes.as_ref())
            .map_err(|e| CoreError::Encryption(e.to_string()))?;

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CoreError::Encryption(e.to_string()))
    }

    fn group_dir(&self, group_id: &KeyGroupId) -> PathBuf {
        self.base_dir.join(&group_id.0)
    }

    fn share_path(&self, group_id: &KeyGroupId, party_id: PartyId) -> PathBuf {
        self.group_dir(group_id)
            .join(format!("party_{}.enc", party_id.0))
    }

    fn metadata_path(&self, group_id: &KeyGroupId) -> PathBuf {
        self.group_dir(group_id).join("metadata.json")
    }

    /// Record the timestamp of the most recent key refresh for a key group.
    ///
    /// Writes a `touch.json` file in the group directory containing the current
    /// Unix timestamp (seconds since epoch). Does NOT access or decrypt key shares.
    ///
    /// Used by the proactive refresh protocol to track when key material was
    /// last rotated.
    pub async fn touch(&self, group_id: &KeyGroupId) -> Result<(), CoreError> {
        let group_dir = self.group_dir(group_id);
        if !group_dir.exists() {
            return Err(CoreError::KeyStore(format!(
                "key group not found: {}",
                group_id.0
            )));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CoreError::KeyStore(e.to_string()))?
            .as_secs();

        let touch_data = serde_json::json!({ "last_refreshed": now });
        let touch_path = group_dir.join("touch.json");
        let json = serde_json::to_string_pretty(&touch_data)
            .map_err(|e| CoreError::KeyStore(e.to_string()))?;

        tokio::fs::write(&touch_path, json.as_bytes())
            .await
            .map_err(|e| CoreError::KeyStore(e.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl KeyStore for EncryptedFileStore {
    async fn save(
        &self,
        group_id: &KeyGroupId,
        metadata: &KeyMetadata,
        party_id: PartyId,
        share: &KeyShare,
    ) -> Result<(), CoreError> {
        let dir = self.group_dir(group_id);
        tokio::fs::create_dir_all(&dir).await?;

        // Write metadata
        let meta_json = serde_json::to_string_pretty(metadata)?;
        tokio::fs::write(self.metadata_path(group_id), meta_json).await?;

        // Encrypt and write share
        let share_json = serde_json::to_vec(share)?;
        let encrypted = self.encrypt(&share_json)?;
        tokio::fs::write(self.share_path(group_id, party_id), encrypted).await?;

        Ok(())
    }

    async fn load(
        &self,
        group_id: &KeyGroupId,
        party_id: PartyId,
    ) -> Result<KeyShare, CoreError> {
        // SEC: check frozen state BEFORE any decryption attempt.
        // A frozen key group must never have its ciphertext read or decrypted.
        let frozen_path = self.group_dir(group_id).join("frozen");
        if frozen_path.exists() {
            return Err(CoreError::KeyFrozen(group_id.0.clone()));
        }

        let path = self.share_path(group_id, party_id);
        let encrypted = tokio::fs::read(&path)
            .await
            .map_err(|_| CoreError::NotFound(format!("key share not found: {}", path.display())))?;

        let decrypted = self.decrypt(&encrypted)?;
        let share: KeyShare = serde_json::from_slice(&decrypted)?;
        Ok(share)
    }

    async fn list(&self) -> Result<Vec<KeyMetadata>, CoreError> {
        let mut results = Vec::new();

        let mut entries = match tokio::fs::read_dir(&self.base_dir).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(results),
            Err(e) => return Err(CoreError::KeyStore(e.to_string())),
        };

        while let Some(entry) = entries.next_entry().await? {
            let meta_path = entry.path().join("metadata.json");
            if tokio::fs::metadata(&meta_path).await.is_ok() {
                let data = tokio::fs::read_to_string(&meta_path).await?;
                if let Ok(metadata) = serde_json::from_str::<KeyMetadata>(&data) {
                    results.push(metadata);
                }
            }
        }

        Ok(results)
    }

    async fn delete(&self, group_id: &KeyGroupId) -> Result<(), CoreError> {
        let dir = self.group_dir(group_id);
        tokio::fs::remove_dir_all(&dir)
            .await
            .map_err(|e| CoreError::KeyStore(format!("failed to delete key group: {e}")))?;
        Ok(())
    }

    async fn freeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError> {
        let group_dir = self.group_dir(group_id);
        if !group_dir.exists() {
            return Err(CoreError::NotFound(format!(
                "key group '{}' not found",
                group_id.0
            )));
        }
        // Write a zero-byte marker file. The file's existence (not its content)
        // is what signals the frozen state — checked in load() before decryption.
        let frozen_path = group_dir.join("frozen");
        tokio::fs::write(&frozen_path, b"")
            .await
            .map_err(|e| CoreError::KeyStore(format!("failed to write frozen marker: {e}")))?;
        Ok(())
    }

    async fn unfreeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError> {
        let frozen_path = self.group_dir(group_id).join("frozen");
        if frozen_path.exists() {
            tokio::fs::remove_file(&frozen_path)
                .await
                .map_err(|e| {
                    CoreError::KeyStore(format!("failed to remove frozen marker: {e}"))
                })?;
        }
        // If the frozen marker does not exist, unfreeze is idempotent — no error.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::GroupPublicKey;
    use crate::types::{CryptoScheme, ThresholdConfig};

    #[tokio::test]
    async fn test_save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("mpc-test-{}", uuid::Uuid::new_v4()));
        let store = EncryptedFileStore::new(dir.clone(), "test-password");

        let group_id = KeyGroupId::new();
        let config = ThresholdConfig::new(2, 3).unwrap();
        let metadata = KeyMetadata {
            group_id: group_id.clone(),
            label: "test".into(),
            scheme: CryptoScheme::FrostEd25519,
            config,
            created_at: 1234567890,
        };

        let share = KeyShare {
            scheme: CryptoScheme::FrostEd25519,
            party_id: PartyId(1),
            config,
            group_public_key: GroupPublicKey::Ed25519(vec![0u8; 32]),
            share_data: zeroize::Zeroizing::new(vec![1, 2, 3, 4]),
        };

        store
            .save(&group_id, &metadata, PartyId(1), &share)
            .await
            .unwrap();
        let loaded = store.load(&group_id, PartyId(1)).await.unwrap();

        assert_eq!(loaded.party_id, PartyId(1));
        assert_eq!(*loaded.share_data, vec![1, 2, 3, 4]);

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn test_list_and_delete() {
        let dir = std::env::temp_dir().join(format!("mpc-test-{}", uuid::Uuid::new_v4()));
        let store = EncryptedFileStore::new(dir.clone(), "test-password");

        let config = ThresholdConfig::new(2, 3).unwrap();

        for i in 0..3 {
            let group_id = KeyGroupId::from_string(format!("group-{i}"));
            let metadata = KeyMetadata {
                group_id: group_id.clone(),
                label: format!("test-{i}"),
                scheme: CryptoScheme::Gg20Ecdsa,
                config,
                created_at: 1000 + i as u64,
            };
            let share = KeyShare {
                scheme: CryptoScheme::Gg20Ecdsa,
                party_id: PartyId(1),
                config,
                group_public_key: GroupPublicKey::Secp256k1(vec![0u8; 33]),
                share_data: zeroize::Zeroizing::new(vec![]),
            };
            store
                .save(&group_id, &metadata, PartyId(1), &share)
                .await
                .unwrap();
        }

        let list = store.list().await.unwrap();
        assert_eq!(list.len(), 3);

        store
            .delete(&KeyGroupId::from_string("group-0".into()))
            .await
            .unwrap();
        let list = store.list().await.unwrap();
        assert_eq!(list.len(), 2);

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn test_touch_updates_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let store = EncryptedFileStore::new(dir.path().to_path_buf(), "test-password");
        let group_id = KeyGroupId::new();

        // touch should fail if group doesn't exist
        let result = store.touch(&group_id).await;
        assert!(result.is_err(), "touch on non-existent group should fail");

        // create the group directory manually to simulate a saved key group
        let group_dir = dir.path().join(&group_id.0);
        tokio::fs::create_dir_all(&group_dir).await.unwrap();

        // touch should succeed now
        store.touch(&group_id).await.expect("touch should succeed");

        // touch.json should exist and contain last_refreshed
        let touch_path = group_dir.join("touch.json");
        assert!(touch_path.exists(), "touch.json must be created");
        let content = tokio::fs::read_to_string(&touch_path).await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(
            json["last_refreshed"].as_u64().unwrap() > 0,
            "timestamp must be positive"
        );
    }

    // ─── Freeze / Unfreeze tests ─────────────────────────────────────────────

    fn make_test_share() -> KeyShare {
        use crate::protocol::GroupPublicKey;
        use crate::types::{CryptoScheme, ThresholdConfig};
        KeyShare {
            scheme: CryptoScheme::FrostEd25519,
            party_id: PartyId(1),
            config: ThresholdConfig::new(2, 3).unwrap(),
            group_public_key: GroupPublicKey::Ed25519(vec![0u8; 32]),
            share_data: zeroize::Zeroizing::new(vec![0xAB, 0xCD]),
        }
    }

    fn make_test_metadata(group_id: &KeyGroupId) -> KeyMetadata {
        use crate::types::{CryptoScheme, ThresholdConfig};
        KeyMetadata {
            group_id: group_id.clone(),
            label: "freeze-test".into(),
            scheme: CryptoScheme::FrostEd25519,
            config: ThresholdConfig::new(2, 3).unwrap(),
            created_at: 0,
        }
    }

    #[tokio::test]
    async fn test_freeze_blocks_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = EncryptedFileStore::new(dir.path().to_path_buf(), "test-pw");
        let group_id = KeyGroupId::new();
        let share = make_test_share();
        let meta = make_test_metadata(&group_id);

        store.save(&group_id, &meta, PartyId(1), &share).await.unwrap();
        // Verify load succeeds before freeze
        assert!(store.load(&group_id, PartyId(1)).await.is_ok());

        // Freeze the group
        store.freeze(&group_id).await.unwrap();

        // Load must now return KeyFrozen — no decryption should occur
        let err = store.load(&group_id, PartyId(1)).await.unwrap_err();
        assert!(
            matches!(err, CoreError::KeyFrozen(_)),
            "expected KeyFrozen after freeze, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_unfreeze_restores_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = EncryptedFileStore::new(dir.path().to_path_buf(), "test-pw");
        let group_id = KeyGroupId::new();
        let share = make_test_share();
        let meta = make_test_metadata(&group_id);

        store.save(&group_id, &meta, PartyId(1), &share).await.unwrap();
        store.freeze(&group_id).await.unwrap();
        // Confirm frozen
        assert!(matches!(
            store.load(&group_id, PartyId(1)).await.unwrap_err(),
            CoreError::KeyFrozen(_)
        ));

        // Unfreeze and confirm load works again
        store.unfreeze(&group_id).await.unwrap();
        assert!(store.load(&group_id, PartyId(1)).await.is_ok());
    }

    #[tokio::test]
    async fn test_freeze_nonexistent_group_returns_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = EncryptedFileStore::new(dir.path().to_path_buf(), "test-pw");
        let group_id = KeyGroupId::new();

        let err = store.freeze(&group_id).await.unwrap_err();
        assert!(
            matches!(err, CoreError::NotFound(_)),
            "expected NotFound for freeze on non-existent group, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_double_freeze_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = EncryptedFileStore::new(dir.path().to_path_buf(), "test-pw");
        let group_id = KeyGroupId::new();
        let share = make_test_share();
        let meta = make_test_metadata(&group_id);

        store.save(&group_id, &meta, PartyId(1), &share).await.unwrap();
        store.freeze(&group_id).await.unwrap();
        // Second freeze on already-frozen group must succeed (idempotent)
        assert!(store.freeze(&group_id).await.is_ok());
    }

    #[tokio::test]
    async fn test_double_unfreeze_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = EncryptedFileStore::new(dir.path().to_path_buf(), "test-pw");
        let group_id = KeyGroupId::new();
        let share = make_test_share();
        let meta = make_test_metadata(&group_id);

        store.save(&group_id, &meta, PartyId(1), &share).await.unwrap();
        // Unfreeze a group that was never frozen — must succeed (idempotent)
        assert!(store.unfreeze(&group_id).await.is_ok());
        // Unfreeze again — still idempotent
        assert!(store.unfreeze(&group_id).await.is_ok());
    }
}
