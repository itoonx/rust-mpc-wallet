//! Redis-ready session backend with encrypted session key storage.
//!
//! Provides `EncryptedSessionData` for serializing sessions with encrypted
//! key material, and a `RedisSessionBackend` that uses a pluggable
//! `RedisClient` trait for actual storage (trait-based so the real Redis
//! client can be plugged in later without code changes).
//!
//! Session keys (`client_write_key`, `server_write_key`) are encrypted with
//! ChaCha20-Poly1305 before storage to prevent plaintext key material in
//! Redis or any external store.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::session::SessionBackend;
use super::types::AuthenticatedSession;

/// Encrypted session data suitable for JSON serialization and external storage.
///
/// The `encrypted_keys` field contains `nonce (12 bytes) || ciphertext (64 + 16 bytes)`
/// encoded as base64. The plaintext is `client_write_key (32) || server_write_key (32)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSessionData {
    /// Client's Ed25519 public key (hex-encoded).
    pub client_pubkey: String,
    /// Client key ID (first 8 bytes of pubkey, hex).
    pub client_key_id: String,
    /// Base64-encoded `nonce || ciphertext` for the session keys.
    pub encrypted_keys: String,
    /// Session expiry (UNIX timestamp).
    pub expires_at: u64,
    /// Session creation time (UNIX timestamp).
    pub created_at: u64,
}

/// Errors from session encryption/decryption.
#[derive(Debug, thiserror::Error)]
pub enum SessionCryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed — key material may be corrupt or wrong KEK")]
    DecryptionFailed,
    #[error("invalid encrypted data length (expected >= 28 bytes, got {0})")]
    InvalidLength(usize),
    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("invalid plaintext length (expected 64 bytes, got {0})")]
    InvalidPlaintextLength(usize),
}

/// Nonce size for ChaCha20-Poly1305 (12 bytes).
const NONCE_SIZE: usize = 12;
/// Session key plaintext: client_write_key (32) + server_write_key (32).
const SESSION_KEYS_LEN: usize = 64;

/// Encrypt an `AuthenticatedSession` into `EncryptedSessionData`.
///
/// The `kek` (key encryption key) is a 32-byte ChaCha20-Poly1305 key used
/// to encrypt the session's write keys before storage.
pub fn encrypt_session(
    session: &AuthenticatedSession,
    kek: &[u8; 32],
) -> Result<EncryptedSessionData, SessionCryptoError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(kek).map_err(|_| SessionCryptoError::EncryptionFailed)?;

    // Assemble plaintext: client_write_key || server_write_key
    let mut plaintext = [0u8; SESSION_KEYS_LEN];
    plaintext[..32].copy_from_slice(&session.client_write_key);
    plaintext[32..].copy_from_slice(&session.server_write_key);

    // Random nonce
    let nonce_bytes: [u8; NONCE_SIZE] = {
        let mut buf = [0u8; NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut OsRng, &mut buf);
        buf
    };
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| SessionCryptoError::EncryptionFailed)?;

    // Zeroize plaintext
    plaintext.zeroize();

    // Combine nonce || ciphertext and base64 encode
    let mut blob = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    use base64::Engine;
    let encrypted_keys = base64::engine::general_purpose::STANDARD.encode(&blob);

    Ok(EncryptedSessionData {
        client_pubkey: hex::encode(session.client_pubkey),
        client_key_id: session.client_key_id.clone(),
        encrypted_keys,
        expires_at: session.expires_at,
        created_at: session.created_at,
    })
}

/// Decrypt an `EncryptedSessionData` back into an `AuthenticatedSession`.
pub fn decrypt_session(
    session_id: &str,
    data: &EncryptedSessionData,
    kek: &[u8; 32],
) -> Result<AuthenticatedSession, SessionCryptoError> {
    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD.decode(&data.encrypted_keys)?;

    // Minimum: 12 (nonce) + 16 (tag) + 64 (plaintext) = 92
    if blob.len() < NONCE_SIZE + 16 {
        return Err(SessionCryptoError::InvalidLength(blob.len()));
    }

    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher =
        ChaCha20Poly1305::new_from_slice(kek).map_err(|_| SessionCryptoError::DecryptionFailed)?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SessionCryptoError::DecryptionFailed)?;

    if plaintext.len() != SESSION_KEYS_LEN {
        return Err(SessionCryptoError::InvalidPlaintextLength(plaintext.len()));
    }

    let mut client_write_key = [0u8; 32];
    let mut server_write_key = [0u8; 32];
    client_write_key.copy_from_slice(&plaintext[..32]);
    server_write_key.copy_from_slice(&plaintext[32..]);

    // Parse client pubkey from hex
    let pubkey_bytes = hex::decode(&data.client_pubkey).unwrap_or_default();
    let mut client_pubkey = [0u8; 32];
    if pubkey_bytes.len() == 32 {
        client_pubkey.copy_from_slice(&pubkey_bytes);
    }

    Ok(AuthenticatedSession {
        session_id: session_id.to_string(),
        client_pubkey,
        client_key_id: data.client_key_id.clone(),
        client_write_key,
        server_write_key,
        expires_at: data.expires_at,
        created_at: data.created_at,
    })
}

// ── Redis Client Trait ──────────────────────────────────────────────

/// Trait abstracting Redis operations needed by `RedisSessionBackend`.
///
/// The real Redis implementation will fulfill this trait. For now, we
/// provide the encryption/serialization layer and test with an in-memory
/// mock that simulates Redis key-value semantics.
#[async_trait]
pub trait RedisClient: Send + Sync {
    /// SET a key with a value and optional TTL (seconds). Returns Ok(true) on success.
    async fn set_ex(&self, key: &str, value: &str, ttl_secs: u64) -> Result<bool, String>;
    /// GET a key. Returns None if not found or expired.
    async fn get(&self, key: &str) -> Result<Option<String>, String>;
    /// DEL a key. Returns true if the key existed.
    async fn del(&self, key: &str) -> Result<bool, String>;
    /// Count keys matching a pattern (e.g., "session:*").
    /// In Redis this would use SCAN + COUNT; the trait abstracts it.
    async fn count_keys(&self, pattern: &str) -> Result<usize, String>;
    /// Get all keys matching a pattern (for prune). Returns key names.
    async fn scan_keys(&self, pattern: &str) -> Result<Vec<String>, String>;
}

// ── RedisSessionBackend ──────────────────────────────────────────────

/// Session backend that encrypts session keys and stores them via a
/// `RedisClient` implementation.
///
/// Session keys are encrypted with ChaCha20-Poly1305 using a 32-byte KEK
/// before being sent to the Redis client.
/// Redis key prefix for sessions.
pub const SESSION_KEY_PREFIX: &str = "session:";

pub struct RedisSessionBackend {
    client: Arc<dyn RedisClient>,
    /// Key encryption key for session data (32 bytes, zeroized on drop).
    kek: zeroize::Zeroizing<[u8; 32]>,
    /// Key prefix for Redis keys.
    prefix: String,
}

impl RedisSessionBackend {
    /// Create a new Redis session backend.
    ///
    /// - `client`: Redis client implementation
    /// - `kek`: 32-byte key encryption key for session data
    pub fn new(client: Arc<dyn RedisClient>, kek: [u8; 32]) -> Self {
        Self {
            client,
            kek: zeroize::Zeroizing::new(kek),
            prefix: SESSION_KEY_PREFIX.to_string(),
        }
    }

    fn key(&self, session_id: &str) -> String {
        format!("{}{}", self.prefix, session_id)
    }
}

#[async_trait]
impl SessionBackend for RedisSessionBackend {
    async fn store(&self, session: AuthenticatedSession) -> bool {
        // No capacity check here — Redis TTL handles expiry automatically.
        // Avoid KEYS command (O(n)) on every store; rely on Redis memory limits.
        let encrypted = match encrypt_session(&session, &self.kek) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, "session encryption failed");
                return false;
            }
        };

        let json = match serde_json::to_string(&encrypted) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "session serialization failed");
                return false;
            }
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ttl = session.expires_at.saturating_sub(now).max(1);

        match self
            .client
            .set_ex(&self.key(&session.session_id), &json, ttl)
            .await
        {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => {
                tracing::error!(error = %e, "Redis SET failed");
                false
            }
        }
    }

    async fn get(&self, session_id: &str) -> Option<AuthenticatedSession> {
        let json = match self.client.get(&self.key(session_id)).await {
            Ok(Some(j)) => j,
            Ok(None) => return None,
            Err(e) => {
                tracing::error!(error = %e, "Redis GET failed");
                return None;
            }
        };

        let encrypted: EncryptedSessionData = match serde_json::from_str(&json) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, "session deserialization failed");
                return None;
            }
        };

        // Check expiry using shared helper.
        if super::session::is_expired(encrypted.expires_at) {
            return None;
        }

        match decrypt_session(session_id, &encrypted, &self.kek) {
            Ok(session) => Some(session),
            Err(e) => {
                tracing::error!(error = %e, "session decryption failed");
                None
            }
        }
    }

    async fn revoke(&self, session_id: &str) -> bool {
        match self.client.del(&self.key(session_id)).await {
            Ok(existed) => existed,
            Err(e) => {
                tracing::error!(error = %e, "Redis DEL failed");
                false
            }
        }
    }

    async fn prune_expired(&self) -> usize {
        // Redis handles TTL-based expiry automatically.
        // This is a no-op for Redis; the TTL is set on each key.
        0
    }

    async fn count(&self) -> usize {
        match self.client.count_keys(&format!("{}*", self.prefix)).await {
            Ok(count) => count,
            Err(e) => {
                tracing::error!(error = %e, "Redis count_keys failed");
                0
            }
        }
    }
}

// ── In-Memory Redis Mock (for testing) ───────────────────────────────

/// In-memory mock of `RedisClient` for testing the encryption/serialization
/// layer without an actual Redis server.
#[derive(Clone, Default)]
pub struct InMemoryRedisClient {
    store: Arc<tokio::sync::RwLock<std::collections::HashMap<String, (String, u64)>>>,
}

impl InMemoryRedisClient {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RedisClient for InMemoryRedisClient {
    async fn set_ex(&self, key: &str, value: &str, ttl_secs: u64) -> Result<bool, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut store = self.store.write().await;
        store.insert(key.to_string(), (value.to_string(), now + ttl_secs));
        Ok(true)
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let store = self.store.read().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        match store.get(key) {
            Some((value, expires_at)) if *expires_at > now => Ok(Some(value.clone())),
            Some(_) => Ok(None), // expired
            None => Ok(None),
        }
    }

    async fn del(&self, key: &str) -> Result<bool, String> {
        let mut store = self.store.write().await;
        Ok(store.remove(key).is_some())
    }

    async fn count_keys(&self, pattern: &str) -> Result<usize, String> {
        let prefix = pattern.trim_end_matches('*');
        let store = self.store.read().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let count = store
            .iter()
            .filter(|(k, (_, exp))| k.starts_with(prefix) && *exp > now)
            .count();
        Ok(count)
    }

    async fn scan_keys(&self, pattern: &str) -> Result<Vec<String>, String> {
        let prefix = pattern.trim_end_matches('*');
        let store = self.store.read().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let keys: Vec<String> = store
            .iter()
            .filter(|(k, (_, exp))| k.starts_with(prefix) && *exp > now)
            .map(|(k, _)| k.clone())
            .collect();
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> [u8; 32] {
        [42u8; 32]
    }

    fn make_session(id: &str, expires_at: u64) -> AuthenticatedSession {
        AuthenticatedSession {
            session_id: id.to_string(),
            client_pubkey: [0xABu8; 32],
            client_key_id: "test-key".into(),
            client_write_key: [1u8; 32],
            server_write_key: [2u8; 32],
            expires_at,
            created_at: 1000,
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let session = make_session("s1", 9999999999);
        let kek = test_kek();

        let encrypted = encrypt_session(&session, &kek).unwrap();
        assert_eq!(encrypted.client_key_id, "test-key");
        assert_eq!(encrypted.client_pubkey, hex::encode([0xABu8; 32]));
        assert_eq!(encrypted.expires_at, 9999999999);

        let decrypted = decrypt_session("s1", &encrypted, &kek).unwrap();
        assert_eq!(decrypted.session_id, "s1");
        assert_eq!(decrypted.client_write_key, [1u8; 32]);
        assert_eq!(decrypted.server_write_key, [2u8; 32]);
        assert_eq!(decrypted.client_pubkey, [0xABu8; 32]);
    }

    #[test]
    fn test_wrong_kek_fails_decryption() {
        let session = make_session("s1", 9999999999);
        let kek = test_kek();
        let encrypted = encrypt_session(&session, &kek).unwrap();

        let wrong_kek = [99u8; 32];
        let result = decrypt_session("s1", &encrypted, &wrong_kek);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_data_is_json_serializable() {
        let session = make_session("s1", 9999999999);
        let kek = test_kek();
        let encrypted = encrypt_session(&session, &kek).unwrap();

        let json = serde_json::to_string(&encrypted).unwrap();
        let deserialized: EncryptedSessionData = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.client_key_id, encrypted.client_key_id);

        // Roundtrip via JSON
        let decrypted = decrypt_session("s1", &deserialized, &kek).unwrap();
        assert_eq!(decrypted.client_write_key, [1u8; 32]);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let session = make_session("s1", 9999999999);
        let kek = test_kek();
        let mut encrypted = encrypt_session(&session, &kek).unwrap();

        // Tamper with the encrypted keys
        use base64::Engine;
        let mut blob = base64::engine::general_purpose::STANDARD
            .decode(&encrypted.encrypted_keys)
            .unwrap();
        if let Some(byte) = blob.last_mut() {
            *byte ^= 0xFF;
        }
        encrypted.encrypted_keys = base64::engine::general_purpose::STANDARD.encode(&blob);

        let result = decrypt_session("s1", &encrypted, &kek);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_base64_fails() {
        let data = EncryptedSessionData {
            client_pubkey: "aa".repeat(32),
            client_key_id: "test".into(),
            encrypted_keys: "not-valid-base64!!!".into(),
            expires_at: 9999999999,
            created_at: 1000,
        };
        let result = decrypt_session("s1", &data, &test_kek());
        assert!(result.is_err());
    }

    #[test]
    fn test_too_short_blob_fails() {
        use base64::Engine;
        let short_blob = vec![0u8; 10]; // too short
        let data = EncryptedSessionData {
            client_pubkey: "aa".repeat(32),
            client_key_id: "test".into(),
            encrypted_keys: base64::engine::general_purpose::STANDARD.encode(&short_blob),
            expires_at: 9999999999,
            created_at: 1000,
        };
        let result = decrypt_session("s1", &data, &test_kek());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_redis_backend_store_and_get() {
        let client = Arc::new(InMemoryRedisClient::new());
        let backend = RedisSessionBackend::new(client, test_kek());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let session = make_session("rs1", now + 3600);

        assert!(backend.store(session).await);
        let retrieved = backend.get("rs1").await;
        assert!(retrieved.is_some());
        let s = retrieved.unwrap();
        assert_eq!(s.session_id, "rs1");
        assert_eq!(s.client_write_key, [1u8; 32]);
        assert_eq!(s.server_write_key, [2u8; 32]);
    }

    #[tokio::test]
    async fn test_redis_backend_revoke() {
        let client = Arc::new(InMemoryRedisClient::new());
        let backend = RedisSessionBackend::new(client, test_kek());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        backend.store(make_session("rs2", now + 3600)).await;
        assert!(backend.revoke("rs2").await);
        assert!(backend.get("rs2").await.is_none());
    }

    #[tokio::test]
    async fn test_redis_backend_expired_returns_none() {
        let client = Arc::new(InMemoryRedisClient::new());
        let backend = RedisSessionBackend::new(client, test_kek());

        // Store with past expiry — the mock still stores it (TTL=1)
        // but get() checks expires_at in the data
        backend.store(make_session("rs3", 1000)).await;
        assert!(backend.get("rs3").await.is_none());
    }

    #[tokio::test]
    async fn test_redis_backend_count() {
        let client = Arc::new(InMemoryRedisClient::new());
        let backend = RedisSessionBackend::new(client, test_kek());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        backend.store(make_session("c1", now + 3600)).await;
        backend.store(make_session("c2", now + 3600)).await;
        assert_eq!(backend.count().await, 2);
    }
}
