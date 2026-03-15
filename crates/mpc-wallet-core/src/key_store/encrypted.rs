use std::path::PathBuf;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;

use crate::error::CoreError;
use crate::key_store::types::{KeyGroupId, KeyMetadata};
use crate::key_store::KeyStore;
use crate::protocol::KeyShare;
use crate::types::PartyId;

/// File-based encrypted key storage using AES-256-GCM + Argon2id.
pub struct EncryptedFileStore {
    base_dir: PathBuf,
    password: String,
}

impl EncryptedFileStore {
    pub fn new(base_dir: PathBuf, password: &str) -> Self {
        Self {
            base_dir,
            password: password.to_string(),
        }
    }

    fn derive_key(&self, salt: &[u8]) -> Result<[u8; 32], CoreError> {
        let mut key = [0u8; 32];
        argon2::Argon2::default()
            .hash_password_into(self.password.as_bytes(), salt, &mut key)
            .map_err(|e| CoreError::Encryption(e.to_string()))?;
        Ok(key)
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CoreError> {
        use rand::RngCore;

        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);

        let key = self.derive_key(&salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| CoreError::Encryption(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| CoreError::Encryption(e.to_string()))?;

        // Format: salt (16) + nonce (12) + ciphertext
        let mut result = Vec::with_capacity(16 + 12 + ciphertext.len());
        result.extend_from_slice(&salt);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CoreError> {
        if data.len() < 28 {
            return Err(CoreError::Encryption("encrypted data too short".into()));
        }

        let salt = &data[..16];
        let nonce = Nonce::from_slice(&data[16..28]);
        let ciphertext = &data[28..];

        let key = self.derive_key(salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
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
            share_data: vec![1, 2, 3, 4],
        };

        store
            .save(&group_id, &metadata, PartyId(1), &share)
            .await
            .unwrap();
        let loaded = store.load(&group_id, PartyId(1)).await.unwrap();

        assert_eq!(loaded.party_id, PartyId(1));
        assert_eq!(loaded.share_data, vec![1, 2, 3, 4]);

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
                share_data: vec![],
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
}
