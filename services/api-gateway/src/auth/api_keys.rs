//! API Key Store — unified management for static and dynamic API keys.
//!
//! **Static keys** (service-to-service): loaded from `API_KEYS_FILE` or `API_KEYS` env at startup.
//! **Dynamic keys** (user-facing): created via `POST /v1/api-keys`, raw key shown once.
//!
//! All keys are stored as HMAC-SHA256 hashes — raw keys are never persisted.
//! Verification uses constant-time comparison to prevent timing attacks.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use mpc_wallet_core::rbac::{AbacAttributes, ApiRole, AuthContext};

use super::types::{compute_hmac_sha256, parse_role, unix_now};

/// Origin of an API key.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyOrigin {
    /// Loaded from config file / env at startup.
    Static,
    /// Created dynamically via API.
    Dynamic,
}

/// Metadata for a stored API key (no secret material).
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyMeta {
    /// Unique key ID (e.g., `vxk_a1b2c3d4`).
    pub key_id: String,
    /// Human-readable label.
    pub label: String,
    /// Maximum role.
    pub role: ApiRole,
    /// Key origin (static or dynamic).
    pub origin: KeyOrigin,
    /// Optional: restrict to specific wallet IDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_wallets: Option<Vec<String>>,
    /// Optional: restrict to specific chains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_chains: Option<Vec<String>>,
    /// Expiration (UNIX seconds). None = no expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Who created this key.
    pub created_by: String,
    /// Creation timestamp.
    pub created_at: u64,
    /// Whether the key has been revoked.
    pub revoked: bool,
}

/// Internal entry: metadata + hash.
#[derive(Clone)]
struct StoredKey {
    /// HMAC-SHA256(hmac_key, raw_key).
    key_hash: [u8; 32],
    meta: ApiKeyMeta,
}

/// Unified API key store.
#[derive(Clone)]
pub struct ApiKeyStore {
    /// HMAC key for hashing (derived from JWT_SECRET).
    hmac_key: Arc<Vec<u8>>,
    /// All keys indexed by key_id.
    keys: Arc<RwLock<HashMap<String, StoredKey>>>,
}

impl ApiKeyStore {
    /// Create a new store with the given HMAC key.
    pub fn new(hmac_key: Vec<u8>) -> Self {
        Self {
            hmac_key: Arc::new(hmac_key),
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load static keys from config (called at startup).
    pub async fn load_static_keys(&self, configs: &[crate::config::ApiKeyConfig]) {
        let mut keys = self.keys.write().await;
        for (i, config) in configs.iter().enumerate() {
            let key_id = format!("vxk_static_{i}");
            let hash = self.compute_hash(&config.key);
            keys.insert(
                key_id.clone(),
                StoredKey {
                    key_hash: hash,
                    meta: ApiKeyMeta {
                        key_id,
                        label: config.label.clone(),
                        role: parse_role(&config.role),
                        origin: KeyOrigin::Static,
                        allowed_wallets: config.allowed_wallets.clone(),
                        allowed_chains: config.allowed_chains.clone(),
                        expires_at: config.expires_at,
                        created_by: "config".into(),
                        created_at: unix_now(),
                        revoked: false,
                    },
                },
            );
        }
    }

    /// Create a new dynamic API key. Returns `(key_id, raw_key)`.
    /// The raw key is shown **once** — it is not stored.
    pub async fn create_key(
        &self,
        label: String,
        role: String,
        created_by: String,
        allowed_wallets: Option<Vec<String>>,
        allowed_chains: Option<Vec<String>>,
        expires_at: Option<u64>,
    ) -> (String, String) {
        // Generate unique key_id and random raw key.
        let key_id = format!("vxk_{}", hex::encode(&super::types::random_nonce()[..8]));
        let raw_secret = hex::encode(super::types::random_nonce());
        let raw_key = format!("sk_{}_{}", role, raw_secret);

        let hash = self.compute_hash(&raw_key);
        let now = unix_now();

        let entry = StoredKey {
            key_hash: hash,
            meta: ApiKeyMeta {
                key_id: key_id.clone(),
                label,
                role: parse_role(&role),
                origin: KeyOrigin::Dynamic,
                allowed_wallets,
                allowed_chains,
                expires_at,
                created_by,
                created_at: now,
                revoked: false,
            },
        };

        let mut keys = self.keys.write().await;
        keys.insert(key_id.clone(), entry);

        (key_id, raw_key)
    }

    /// Verify a raw API key. Returns metadata if valid.
    pub async fn verify(&self, raw_key: &str) -> Option<ApiKeyMeta> {
        let incoming_hash = self.compute_hash(raw_key);
        let keys = self.keys.read().await;

        for entry in keys.values() {
            if incoming_hash.ct_eq(&entry.key_hash).into() {
                if entry.meta.revoked {
                    return None;
                }
                if let Some(exp) = entry.meta.expires_at {
                    if unix_now() > exp {
                        return None;
                    }
                }
                return Some(entry.meta.clone());
            }
        }
        None
    }

    /// List all keys (metadata only — no secrets).
    pub async fn list(&self) -> Vec<ApiKeyMeta> {
        let keys = self.keys.read().await;
        keys.values().map(|e| e.meta.clone()).collect()
    }

    /// Revoke a key by ID. Returns true if the key existed and was not already revoked.
    pub async fn revoke(&self, key_id: &str) -> bool {
        let mut keys = self.keys.write().await;
        if let Some(entry) = keys.get_mut(key_id) {
            if entry.meta.revoked {
                return false;
            }
            entry.meta.revoked = true;
            true
        } else {
            false
        }
    }

    /// Delete a key permanently. Returns true if the key existed.
    pub async fn delete(&self, key_id: &str) -> bool {
        let mut keys = self.keys.write().await;
        keys.remove(key_id).is_some()
    }

    /// Get metadata for a specific key.
    pub async fn get(&self, key_id: &str) -> Option<ApiKeyMeta> {
        let keys = self.keys.read().await;
        keys.get(key_id).map(|e| e.meta.clone())
    }

    /// Count active (non-revoked, non-expired) keys.
    pub async fn count_active(&self) -> usize {
        let keys = self.keys.read().await;
        let now = unix_now();
        keys.values()
            .filter(|e| !e.meta.revoked && e.meta.expires_at.is_none_or(|exp| now <= exp))
            .count()
    }

    fn compute_hash(&self, raw_key: &str) -> [u8; 32] {
        compute_hmac_sha256(&self.hmac_key, raw_key)
    }
}

impl ApiKeyMeta {
    /// Build an `AuthContext` from this key's metadata.
    pub fn auth_context(&self) -> AuthContext {
        AuthContext::with_attributes(
            format!("api-key:{}", self.label),
            vec![self.role.clone()],
            AbacAttributes::default(),
            false,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_verify_dynamic_key() {
        let store = ApiKeyStore::new(b"test-hmac-secret-32-bytes-long!!".to_vec());
        let (key_id, raw_key) = store
            .create_key(
                "test-key".into(),
                "admin".into(),
                "test-user".into(),
                None,
                None,
                None,
            )
            .await;

        assert!(key_id.starts_with("vxk_"));
        assert!(raw_key.starts_with("sk_admin_"));

        // Verify works.
        let meta = store.verify(&raw_key).await;
        assert!(meta.is_some());
        let meta = meta.unwrap();
        assert_eq!(meta.key_id, key_id);
        assert_eq!(meta.label, "test-key");
        assert_eq!(meta.role, ApiRole::Admin);
        assert_eq!(meta.origin, KeyOrigin::Dynamic);

        // Wrong key fails.
        assert!(store.verify("sk_admin_wrong").await.is_none());
    }

    #[tokio::test]
    async fn test_revoke_key() {
        let store = ApiKeyStore::new(b"test-hmac-secret-32-bytes-long!!".to_vec());
        let (key_id, raw_key) = store
            .create_key(
                "revoketest".into(),
                "viewer".into(),
                "u".into(),
                None,
                None,
                None,
            )
            .await;

        assert!(store.verify(&raw_key).await.is_some());
        assert!(store.revoke(&key_id).await);
        assert!(store.verify(&raw_key).await.is_none());

        // Double revoke returns false.
        assert!(!store.revoke(&key_id).await);
    }

    #[tokio::test]
    async fn test_expired_key_rejected() {
        let store = ApiKeyStore::new(b"test-hmac-secret-32-bytes-long!!".to_vec());
        let (_key_id, raw_key) = store
            .create_key(
                "expired".into(),
                "viewer".into(),
                "u".into(),
                None,
                None,
                Some(1000), // long expired
            )
            .await;

        assert!(store.verify(&raw_key).await.is_none());
    }

    #[tokio::test]
    async fn test_list_keys_no_secrets() {
        let store = ApiKeyStore::new(b"test-hmac-secret-32-bytes-long!!".to_vec());
        store
            .create_key("k1".into(), "admin".into(), "u".into(), None, None, None)
            .await;
        store
            .create_key("k2".into(), "viewer".into(), "u".into(), None, None, None)
            .await;

        let list = store.list().await;
        assert_eq!(list.len(), 2);
        // Metadata only — no key_hash or raw_key exposed.
    }

    #[tokio::test]
    async fn test_delete_key() {
        let store = ApiKeyStore::new(b"test-hmac-secret-32-bytes-long!!".to_vec());
        let (key_id, raw_key) = store
            .create_key("del".into(), "viewer".into(), "u".into(), None, None, None)
            .await;

        assert!(store.delete(&key_id).await);
        assert!(store.verify(&raw_key).await.is_none());
        assert!(!store.delete(&key_id).await); // already gone
    }

    #[tokio::test]
    async fn test_static_keys_loaded() {
        let store = ApiKeyStore::new(b"test-hmac-secret-32-bytes-long!!".to_vec());
        let configs = vec![crate::config::ApiKeyConfig {
            key: "my-static-key".into(),
            label: "static-test".into(),
            role: "admin".into(),
            allowed_wallets: None,
            allowed_chains: None,
            expires_at: None,
        }];
        store.load_static_keys(&configs).await;

        let meta = store.verify("my-static-key").await;
        assert!(meta.is_some());
        assert_eq!(meta.unwrap().origin, KeyOrigin::Static);
    }

    #[tokio::test]
    async fn test_constant_time_verification() {
        let store = ApiKeyStore::new(b"test-hmac-secret-32-bytes-long!!".to_vec());
        store
            .create_key("ct".into(), "admin".into(), "u".into(), None, None, None)
            .await;

        // All wrong keys should fail identically.
        assert!(store.verify("").await.is_none());
        assert!(store.verify("sk_admin_").await.is_none());
        assert!(store.verify("sk_admin_wrong").await.is_none());
        assert!(store.verify("completely-different").await.is_none());
    }
}
