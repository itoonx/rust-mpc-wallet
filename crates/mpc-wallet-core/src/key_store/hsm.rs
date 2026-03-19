//! HSM/KMS envelope encryption abstraction for MPC key shares.
//!
//! Provides the [`KeyEncryptionProvider`] trait for envelope encryption:
//! - A master Key Encryption Key (KEK) lives in HSM/KMS
//! - Data Encryption Keys (DEKs) are derived per key group
//! - DEKs are wrapped (encrypted) under the KEK for storage
//! - On load, the HSM unwraps the DEK, and the gateway decrypts shares in-process
//!
//! ## Implementations
//!
//! - [`LocalKeyEncryption`] — AES-256-GCM wrapping with an in-process master key.
//!   Suitable for single-node deployments or development.
//!
//! - [`KmsKeyEncryption`] (behind `aws-kms` feature) — AWS KMS envelope encryption
//!   stub. Defines the interface for `GenerateDataKey` / `Encrypt` / `Decrypt` with
//!   a local [`DekCache`] for unwrapped DEK caching.
//!
//! ## Environment Variables (for `KmsKeyEncryption`)
//!
//! - `KMS_KEY_ARN` — AWS KMS key ARN or alias (e.g., `arn:aws:kms:us-east-1:...`)
//! - `KMS_REGION` — AWS region (e.g., `us-east-1`)

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CoreError;

/// AES-256-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;

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

/// Local in-process key encryption using AES-256-GCM wrapping.
///
/// Uses HKDF-SHA256 to derive per-group DEKs from the master key, and
/// AES-256-GCM to wrap/unwrap DEKs for storage. The 12-byte nonce is
/// randomly generated and prepended to the ciphertext.
///
/// Wire format: `[nonce (12 bytes)][ciphertext + tag (32 + 16 bytes)]`
pub struct LocalKeyEncryption {
    /// 32-byte master key (KEK), zeroized on drop.
    master_key: Zeroizing<[u8; 32]>,
}

impl LocalKeyEncryption {
    /// Create a new local key encryption provider from a 32-byte master key.
    pub fn new(master_key: [u8; 32]) -> Self {
        Self {
            master_key: Zeroizing::new(master_key),
        }
    }
}

#[async_trait]
impl KeyEncryptionProvider for LocalKeyEncryption {
    async fn derive_dek(&self, group_id: &str) -> Result<[u8; 32], CoreError> {
        // HKDF-like derivation: SHA256(master_key || "dek-derivation-v1" || group_id)
        let mut hasher = Sha256::new();
        hasher.update(self.master_key.as_ref());
        hasher.update(b"dek-derivation-v1");
        hasher.update(group_id.as_bytes());
        let hash = hasher.finalize();
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&hash);
        Ok(dek)
    }

    async fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CoreError> {
        // AES-256-GCM encryption of DEK under the master key.
        // Wire format: nonce (12 bytes) || ciphertext+tag (48 bytes)
        let cipher = Aes256Gcm::new_from_slice(self.master_key.as_ref())
            .map_err(|e| CoreError::Encryption(format!("AES-256-GCM key init failed: {e}")))?;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, dek.as_ref())
            .map_err(|e| CoreError::Encryption(format!("AES-256-GCM wrap failed: {e}")))?;

        let mut wrapped = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&ciphertext);
        Ok(wrapped)
    }

    async fn unwrap_dek(&self, wrapped: &[u8]) -> Result<[u8; 32], CoreError> {
        // Minimum length: 12 (nonce) + 32 (DEK) + 16 (GCM tag) = 60 bytes
        if wrapped.len() < NONCE_SIZE + 32 + 16 {
            return Err(CoreError::Encryption(format!(
                "invalid wrapped DEK length: expected at least {}, got {}",
                NONCE_SIZE + 32 + 16,
                wrapped.len()
            )));
        }

        let (nonce_bytes, ciphertext) = wrapped.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(self.master_key.as_ref())
            .map_err(|e| CoreError::Encryption(format!("AES-256-GCM key init failed: {e}")))?;

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            CoreError::Encryption(
                "AES-256-GCM unwrap failed: authentication tag mismatch (wrong key or tampered ciphertext)".to_string(),
            )
        })?;

        if plaintext.len() != 32 {
            return Err(CoreError::Encryption(format!(
                "unwrapped DEK has invalid length: expected 32, got {}",
                plaintext.len()
            )));
        }

        let mut dek = [0u8; 32];
        dek.copy_from_slice(&plaintext);
        Ok(dek)
    }
}

// ---------------------------------------------------------------------------
// AWS KMS envelope encryption (feature-gated)
// ---------------------------------------------------------------------------

/// DEK cache entry: unwrapped DEK + insertion timestamp.
#[cfg(feature = "aws-kms")]
struct DekCacheEntry {
    dek: Zeroizing<[u8; 32]>,
    inserted_at: std::time::Instant,
}

/// In-memory cache for unwrapped DEKs to avoid repeated KMS calls.
///
/// Entries expire after `ttl` (default 5 minutes). The cache key is formed
/// from the group_id so each key group has its own cached DEK.
#[cfg(feature = "aws-kms")]
pub struct DekCache {
    entries: std::sync::Mutex<std::collections::HashMap<String, DekCacheEntry>>,
    ttl: std::time::Duration,
    max_entries: usize,
}

#[cfg(feature = "aws-kms")]
impl DekCache {
    /// Create a new DEK cache with default TTL (5 minutes) and max 1000 entries.
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
            ttl: std::time::Duration::from_secs(300),
            max_entries: 1000,
        }
    }

    /// Create a DEK cache with custom TTL and max entries.
    pub fn with_config(ttl: std::time::Duration, max_entries: usize) -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
            ttl,
            max_entries,
        }
    }

    /// Get a cached DEK if it exists and hasn't expired.
    pub fn get(&self, group_id: &str) -> Option<[u8; 32]> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get(group_id) {
            if entry.inserted_at.elapsed() < self.ttl {
                return Some(*entry.dek);
            }
            // Expired — remove it
            entries.remove(group_id);
        }
        None
    }

    /// Insert a DEK into the cache. Evicts expired entries if at capacity.
    pub fn insert(&self, group_id: &str, dek: [u8; 32]) {
        let mut entries = self.entries.lock().unwrap();
        // Evict expired entries if at capacity
        if entries.len() >= self.max_entries {
            let ttl = self.ttl;
            entries.retain(|_, v| v.inserted_at.elapsed() < ttl);
        }
        entries.insert(
            group_id.to_string(),
            DekCacheEntry {
                dek: Zeroizing::new(dek),
                inserted_at: std::time::Instant::now(),
            },
        );
    }

    /// Unwrap a DEK, checking the cache first.
    ///
    /// If the cache has a valid (non-expired) entry for `group_id`, returns it
    /// directly. Otherwise, calls the provider's `unwrap_dek` and caches the result.
    pub async fn cached_unwrap(
        &self,
        group_id: &str,
        wrapped: &[u8],
        provider: &dyn KeyEncryptionProvider,
    ) -> Result<[u8; 32], CoreError> {
        if let Some(dek) = self.get(group_id) {
            return Ok(dek);
        }
        let dek = provider.unwrap_dek(wrapped).await?;
        self.insert(group_id, dek);
        Ok(dek)
    }
}

#[cfg(feature = "aws-kms")]
impl Default for DekCache {
    fn default() -> Self {
        Self::new()
    }
}

/// AWS KMS-backed envelope encryption provider.
///
/// Uses AWS KMS to generate, wrap, and unwrap DEKs. The master KEK never
/// leaves KMS — all cryptographic operations happen server-side.
///
/// **Current status:** Stub implementation. Methods return `CoreError::Encryption`
/// with guidance to wire up the real AWS SDK. The struct defines the correct
/// interface and includes a [`DekCache`] for reducing KMS API calls.
///
/// ## Required Environment Variables
///
/// - `KMS_KEY_ARN` — KMS key ARN or alias
/// - `KMS_REGION` — AWS region
#[cfg(feature = "aws-kms")]
pub struct KmsKeyEncryption {
    /// KMS key ARN or alias (e.g., `arn:aws:kms:us-east-1:123456:key/...`).
    pub key_arn: String,
    /// AWS region (e.g., `us-east-1`).
    pub region: String,
    /// Local DEK cache to reduce KMS API calls.
    pub cache: DekCache,
}

#[cfg(feature = "aws-kms")]
impl KmsKeyEncryption {
    /// Create a new KMS key encryption provider.
    pub fn new(key_arn: String, region: String) -> Self {
        Self {
            key_arn,
            region,
            cache: DekCache::new(),
        }
    }

    /// Create with a custom DEK cache configuration.
    pub fn with_cache(key_arn: String, region: String, cache: DekCache) -> Self {
        Self {
            key_arn,
            region,
            cache,
        }
    }
}

#[cfg(feature = "aws-kms")]
#[async_trait]
impl KeyEncryptionProvider for KmsKeyEncryption {
    async fn derive_dek(&self, _group_id: &str) -> Result<[u8; 32], CoreError> {
        // TODO: replace with real AWS SDK call
        // ```
        // let client = aws_sdk_kms::Client::new(&config);
        // let resp = client.generate_data_key()
        //     .key_id(&self.key_arn)
        //     .key_spec(DataKeySpec::Aes256)
        //     .send()
        //     .await?;
        // let plaintext = resp.plaintext().unwrap();
        // let ciphertext_blob = resp.ciphertext_blob().unwrap();
        // // Store ciphertext_blob alongside encrypted share
        // // Return plaintext DEK
        // ```
        Err(CoreError::Encryption(
            "KMS derive_dek not yet implemented: requires aws-sdk-kms dependency".to_string(),
        ))
    }

    async fn wrap_dek(&self, _dek: &[u8; 32]) -> Result<Vec<u8>, CoreError> {
        // TODO: replace with real AWS SDK call
        // ```
        // let client = aws_sdk_kms::Client::new(&config);
        // let resp = client.encrypt()
        //     .key_id(&self.key_arn)
        //     .plaintext(Blob::new(dek.to_vec()))
        //     .send()
        //     .await?;
        // Ok(resp.ciphertext_blob().unwrap().as_ref().to_vec())
        // ```
        Err(CoreError::Encryption(
            "KMS wrap_dek not yet implemented: requires aws-sdk-kms dependency".to_string(),
        ))
    }

    async fn unwrap_dek(&self, _wrapped: &[u8]) -> Result<[u8; 32], CoreError> {
        // TODO: replace with real AWS SDK call
        // ```
        // let client = aws_sdk_kms::Client::new(&config);
        // let resp = client.decrypt()
        //     .key_id(&self.key_arn)
        //     .ciphertext_blob(Blob::new(wrapped.to_vec()))
        //     .send()
        //     .await?;
        // let plaintext = resp.plaintext().unwrap();
        // // Convert to [u8; 32]
        // ```
        Err(CoreError::Encryption(
            "KMS unwrap_dek not yet implemented: requires aws-sdk-kms dependency".to_string(),
        ))
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

    // --- AES-256-GCM wrapping tests ---

    #[tokio::test]
    async fn test_aes_gcm_wrap_unwrap_roundtrip() {
        let provider = LocalKeyEncryption::new(test_master_key());
        let original_dek = [0xABu8; 32];
        let wrapped = provider.wrap_dek(&original_dek).await.unwrap();

        // Wrapped should be nonce (12) + ciphertext (32) + tag (16) = 60 bytes
        assert_eq!(wrapped.len(), NONCE_SIZE + 32 + 16);

        // Wrapped should differ from plaintext
        assert_ne!(&wrapped[NONCE_SIZE..NONCE_SIZE + 32], &original_dek[..]);

        let unwrapped = provider.unwrap_dek(&wrapped).await.unwrap();
        assert_eq!(unwrapped, original_dek);
    }

    #[tokio::test]
    async fn test_aes_gcm_wrong_key_fails() {
        let p1 = LocalKeyEncryption::new([1u8; 32]);
        let p2 = LocalKeyEncryption::new([2u8; 32]);
        let original = [0xAAu8; 32];
        let wrapped = p1.wrap_dek(&original).await.unwrap();

        // Wrong key should fail authentication (not silently return wrong data)
        let result = p2.unwrap_dek(&wrapped).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("authentication tag mismatch"),
            "expected auth tag error, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_aes_gcm_tampered_ciphertext_fails() {
        let provider = LocalKeyEncryption::new(test_master_key());
        let dek = [0xCCu8; 32];
        let mut wrapped = provider.wrap_dek(&dek).await.unwrap();

        // Tamper with a byte in the ciphertext portion (after nonce)
        wrapped[NONCE_SIZE + 5] ^= 0xFF;

        let result = provider.unwrap_dek(&wrapped).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("authentication tag mismatch"));
    }

    #[tokio::test]
    async fn test_unwrap_too_short_fails() {
        let provider = LocalKeyEncryption::new(test_master_key());
        let result = provider.unwrap_dek(&[0u8; 16]).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid wrapped DEK length"));
    }

    // --- DEK derivation tests ---

    #[tokio::test]
    async fn test_dek_derivation_deterministic() {
        let provider = LocalKeyEncryption::new(test_master_key());
        let dek1 = provider.derive_dek("group-1").await.unwrap();
        let dek2 = provider.derive_dek("group-1").await.unwrap();
        assert_eq!(dek1, dek2, "same group_id must produce same DEK");
    }

    #[tokio::test]
    async fn test_dek_derivation_group_isolation() {
        let provider = LocalKeyEncryption::new(test_master_key());
        let dek1 = provider.derive_dek("group-alpha").await.unwrap();
        let dek2 = provider.derive_dek("group-beta").await.unwrap();
        assert_ne!(
            dek1, dek2,
            "different group_ids must produce different DEKs"
        );
    }

    #[tokio::test]
    async fn test_derive_dek_different_master_keys() {
        let p1 = LocalKeyEncryption::new([1u8; 32]);
        let p2 = LocalKeyEncryption::new([2u8; 32]);
        let dek1 = p1.derive_dek("same-group").await.unwrap();
        let dek2 = p2.derive_dek("same-group").await.unwrap();
        assert_ne!(dek1, dek2);
    }

    // --- Wrapping nonce uniqueness ---

    #[tokio::test]
    async fn test_wrap_produces_different_ciphertexts() {
        let provider = LocalKeyEncryption::new(test_master_key());
        let dek = [0xBBu8; 32];
        let w1 = provider.wrap_dek(&dek).await.unwrap();
        let w2 = provider.wrap_dek(&dek).await.unwrap();
        // Random nonces mean wrapping the same DEK twice yields different output
        assert_ne!(w1, w2, "each wrap should use a unique nonce");
        // But both should unwrap to the same DEK
        let u1 = provider.unwrap_dek(&w1).await.unwrap();
        let u2 = provider.unwrap_dek(&w2).await.unwrap();
        assert_eq!(u1, dek);
        assert_eq!(u2, dek);
    }

    #[test]
    fn test_trait_object_compatible() {
        let provider = LocalKeyEncryption::new([0u8; 32]);
        let _boxed: Box<dyn KeyEncryptionProvider> = Box::new(provider);
    }

    // --- DekCache tests (aws-kms feature) ---

    #[cfg(feature = "aws-kms")]
    mod kms_tests {
        use super::*;

        #[tokio::test]
        async fn test_dek_cache_hit() {
            let cache = DekCache::new();
            let dek = [0xDDu8; 32];
            cache.insert("group-1", dek);

            // Cache hit should return the same DEK
            let cached = cache.get("group-1");
            assert_eq!(cached, Some(dek));
        }

        #[tokio::test]
        async fn test_dek_cache_expiry() {
            let cache = DekCache::with_config(std::time::Duration::from_millis(50), 100);
            let dek = [0xEEu8; 32];
            cache.insert("group-expire", dek);

            // Should be cached immediately
            assert_eq!(cache.get("group-expire"), Some(dek));

            // Wait for expiry
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            // Should be expired
            assert_eq!(cache.get("group-expire"), None);
        }

        #[tokio::test]
        async fn test_dek_cache_cached_unwrap() {
            // Use LocalKeyEncryption as the underlying provider
            let provider = LocalKeyEncryption::new([0x11u8; 32]);
            let original_dek = [0xFFu8; 32];
            let wrapped = provider.wrap_dek(&original_dek).await.unwrap();

            let cache = DekCache::new();
            // First call: cache miss, calls provider
            let dek1 = cache
                .cached_unwrap("group-x", &wrapped, &provider)
                .await
                .unwrap();
            assert_eq!(dek1, original_dek);

            // Second call: cache hit
            let dek2 = cache
                .cached_unwrap("group-x", &wrapped, &provider)
                .await
                .unwrap();
            assert_eq!(dek2, original_dek);
        }

        #[tokio::test]
        async fn test_kms_key_encryption_stub() {
            let kms = KmsKeyEncryption::new(
                "arn:aws:kms:us-east-1:123456:key/test".to_string(),
                "us-east-1".to_string(),
            );

            // All methods should return Err (stub implementation)
            let derive_result = kms.derive_dek("group-1").await;
            assert!(derive_result.is_err());
            assert!(derive_result
                .unwrap_err()
                .to_string()
                .contains("not yet implemented"));

            let wrap_result = kms.wrap_dek(&[0u8; 32]).await;
            assert!(wrap_result.is_err());
            assert!(wrap_result
                .unwrap_err()
                .to_string()
                .contains("not yet implemented"));

            let unwrap_result = kms.unwrap_dek(&[0u8; 60]).await;
            assert!(unwrap_result.is_err());
            assert!(unwrap_result
                .unwrap_err()
                .to_string()
                .contains("not yet implemented"));
        }
    }
}
