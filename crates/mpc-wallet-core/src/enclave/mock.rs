//! Mock SGX enclave provider for testing and development.
//!
//! [`MockEnclaveProvider`] implements [`EnclaveProvider`] entirely in software,
//! using AES-256-GCM + Argon2id decryption (same format as [`EncryptedFileStore`])
//! and in-memory storage of plaintext shares behind a `Mutex<HashMap>`.
//!
//! Key material is wrapped in [`Zeroizing`] and explicitly cleared on destroy.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::types::PartyId;

use super::{AttestationReport, EnclaveHandle, EnclaveProvider, PartialSignature};

/// Argon2id parameters — matches EncryptedFileStore (SEC-006).
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

/// Mock SGX enclave provider.
///
/// Stores decrypted key shares in a `Mutex<HashMap>` keyed by [`EnclaveHandle`].
/// Each handle is a monotonically increasing u64. Destroyed shares are zeroized
/// and removed from the map.
///
/// # Thread Safety
///
/// `MockEnclaveProvider` is `Send + Sync` — the inner `HashMap` is protected
/// by a `Mutex`, and the handle counter uses `AtomicU64`.
pub struct MockEnclaveProvider {
    /// Monotonic handle counter.
    next_handle: AtomicU64,
    /// In-memory store of decrypted shares, keyed by handle.
    /// Values are wrapped in `Zeroizing` so they are cleared on removal.
    shares: Mutex<HashMap<u64, Zeroizing<Vec<u8>>>>,
    /// Random enclave identity (used in attestation report_data seed).
    enclave_id: [u8; 32],
}

impl MockEnclaveProvider {
    /// Create a new `MockEnclaveProvider` with a random enclave identity.
    pub fn new() -> Self {
        use rand::RngCore;
        let mut enclave_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut enclave_id);
        Self {
            next_handle: AtomicU64::new(1),
            shares: Mutex::new(HashMap::new()),
            enclave_id,
        }
    }

    /// Derive an AES-256-GCM key from password + salt using Argon2id.
    fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CoreError> {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|e| CoreError::Encryption(format!("Argon2 params error: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key_bytes = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password, salt, key_bytes.as_mut())
            .map_err(|e| CoreError::Encryption(format!("Key derivation failed: {e}")))?;

        Ok(key_bytes)
    }

    /// Decrypt data in the EncryptedFileStore format: `salt(32) | nonce(12) | ciphertext`.
    fn decrypt(password: &[u8], data: &[u8]) -> Result<Vec<u8>, CoreError> {
        if data.len() < 44 {
            return Err(CoreError::Encryption("encrypted data too short".into()));
        }

        let salt = &data[..32];
        let nonce = Nonce::from_slice(&data[32..44]);
        let ciphertext = &data[44..];

        let key_bytes = Self::derive_key(password, salt)?;
        let cipher = Aes256Gcm::new_from_slice(key_bytes.as_ref())
            .map_err(|e| CoreError::Encryption(e.to_string()))?;

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CoreError::Encryption(e.to_string()))
    }

    /// Encrypt data in the EncryptedFileStore format: `salt(32) | nonce(12) | ciphertext`.
    ///
    /// Exposed for test helpers that need to prepare encrypted share payloads.
    pub fn encrypt(password: &[u8], data: &[u8]) -> Result<Vec<u8>, CoreError> {
        use rand::RngCore;

        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let key_bytes = Self::derive_key(password, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(key_bytes.as_ref())
            .map_err(|e| CoreError::Encryption(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| CoreError::Encryption(e.to_string()))?;

        let mut result = Vec::with_capacity(32 + 12 + ciphertext.len());
        result.extend_from_slice(&salt);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }
}

impl Default for MockEnclaveProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EnclaveProvider for MockEnclaveProvider {
    async fn load_share(
        &self,
        encrypted_share: &[u8],
        password: &[u8],
    ) -> Result<EnclaveHandle, CoreError> {
        let plaintext = Self::decrypt(password, encrypted_share)?;
        let handle_id = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let mut map = self
            .shares
            .lock()
            .map_err(|e| CoreError::Other(format!("enclave lock poisoned: {e}")))?;
        map.insert(handle_id, Zeroizing::new(plaintext));
        Ok(EnclaveHandle {
            id: handle_id.to_string(),
        })
    }

    async fn sign(
        &self,
        handle: &EnclaveHandle,
        message: &[u8],
    ) -> Result<PartialSignature, CoreError> {
        let handle_id: u64 = handle
            .id
            .parse()
            .map_err(|e| CoreError::Other(format!("invalid handle id: {e}")))?;
        let map = self
            .shares
            .lock()
            .map_err(|e| CoreError::Other(format!("enclave lock poisoned: {e}")))?;
        let share_data = map.get(&handle_id).ok_or_else(|| {
            CoreError::NotFound(format!(
                "enclave handle {} not found (share not loaded or already destroyed)",
                handle.id
            ))
        })?;

        // Mock signing: produce a deterministic partial signature
        // derived from the share data and message. This is NOT cryptographically
        // valid — it exists only so tests can exercise the enclave signing path.
        let mut hasher = Sha256::new();
        hasher.update(share_data.as_slice());
        hasher.update(message);
        let hash = hasher.finalize();

        Ok(PartialSignature {
            party_id: PartyId(1),
            data: hash.to_vec(),
        })
    }

    fn attestation_report(&self) -> Result<AttestationReport, CoreError> {
        use rand::RngCore;

        // mrenclave = SHA-256("mock-enclave-v1")
        let mrenclave: [u8; 32] = Sha256::digest(b"mock-enclave-v1").into();

        // mrsigner = SHA-256("mock-signer-v1")
        let mrsigner: [u8; 32] = Sha256::digest(b"mock-signer-v1").into();

        // Current time
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CoreError::Other(format!("system time error: {e}")))?
            .as_secs();

        // 64-byte report_data: first 32 bytes from enclave_id, last 32 random
        let mut report_data = vec![0u8; 64];
        report_data[..32].copy_from_slice(&self.enclave_id);
        rand::thread_rng().fill_bytes(&mut report_data[32..]);

        // Raw report placeholder (mock)
        let raw_report = b"mock-raw-attestation-report".to_vec();

        Ok(AttestationReport {
            mrenclave,
            mrsigner,
            isv_prod_id: 1,
            isv_svn: 1,
            timestamp,
            report_data,
            raw_report,
        })
    }

    fn destroy(&self, handle: EnclaveHandle) {
        let handle_id: u64 = match handle.id.parse() {
            Ok(id) => id,
            Err(_) => return, // invalid handle — nothing to destroy
        };
        let mut map = match self.shares.lock() {
            Ok(m) => m,
            Err(_) => return, // poisoned lock — can't clean up
        };
        // Remove and drop — Zeroizing<Vec<u8>> will clear the bytes on drop.
        // If handle doesn't exist (double destroy), this is a no-op.
        map.remove(&handle_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encrypt some share data with the given password.
    fn encrypt_share(data: &[u8], password: &[u8]) -> Vec<u8> {
        MockEnclaveProvider::encrypt(password, data).expect("encryption should succeed")
    }

    #[tokio::test]
    async fn test_mock_enclave_load_and_destroy() {
        let enclave = MockEnclaveProvider::new();
        let password = b"test-password-123";
        let share_data = b"secret-share-bytes-here";
        let encrypted = encrypt_share(share_data, password);

        // Load share into enclave
        let handle = enclave
            .load_share(&encrypted, password)
            .await
            .expect("load_share should succeed");

        // Verify handle is valid by signing with it
        let sig = enclave.sign(&handle, b"test-message").await;
        assert!(sig.is_ok(), "sign with valid handle should succeed");

        // Destroy the share
        let handle_id = handle.id.clone();
        enclave.destroy(handle);

        // Verify handle is now invalid
        let dead_handle = EnclaveHandle { id: handle_id };
        let err = enclave.sign(&dead_handle, b"test-message").await;
        assert!(err.is_err(), "sign after destroy should fail");
        let err_msg = format!("{}", err.unwrap_err());
        assert!(
            err_msg.contains("not found"),
            "error should mention handle not found, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_mock_enclave_attestation_report() {
        let enclave = MockEnclaveProvider::new();
        let report = enclave
            .attestation_report()
            .expect("attestation_report should succeed");

        // mrenclave = SHA-256("mock-enclave-v1")
        let expected_mrenclave: [u8; 32] = Sha256::digest(b"mock-enclave-v1").into();
        assert_eq!(
            report.mrenclave, expected_mrenclave,
            "mrenclave should be SHA-256 of 'mock-enclave-v1'"
        );

        // mrsigner = SHA-256("mock-signer-v1")
        let expected_mrsigner: [u8; 32] = Sha256::digest(b"mock-signer-v1").into();
        assert_eq!(
            report.mrsigner, expected_mrsigner,
            "mrsigner should be SHA-256 of 'mock-signer-v1'"
        );

        // report_data should be 64 bytes
        assert_eq!(report.report_data.len(), 64);
        // At least some bytes should be non-zero (random)
        assert!(
            report.report_data.iter().any(|&b| b != 0),
            "report_data should contain non-zero bytes"
        );
    }

    #[tokio::test]
    async fn test_mock_enclave_double_destroy() {
        let enclave = MockEnclaveProvider::new();
        let password = b"test-pw";
        let encrypted = encrypt_share(b"share-data", password);

        let handle = enclave
            .load_share(&encrypted, password)
            .await
            .expect("load should succeed");

        let handle_id = handle.id.clone();

        // First destroy
        enclave.destroy(handle);

        // Second destroy — should NOT panic, should be a no-op
        enclave.destroy(EnclaveHandle { id: handle_id });
    }

    #[tokio::test]
    async fn test_mock_enclave_sign_without_load() {
        let enclave = MockEnclaveProvider::new();

        // Try to sign with a handle that was never loaded
        let bogus_handle = EnclaveHandle {
            id: "999".to_string(),
        };
        let result = enclave.sign(&bogus_handle, b"message").await;

        assert!(result.is_err(), "sign with unloaded handle should fail");
        match result.unwrap_err() {
            CoreError::NotFound(msg) => {
                assert!(
                    msg.contains("999"),
                    "error should reference the handle ID, got: {msg}"
                );
            }
            other => panic!("expected NotFound error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_mock_enclave_provider_is_send_sync() {
        // Compile-time check that MockEnclaveProvider is Send + Sync
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MockEnclaveProvider>();

        // Also check the trait object is Send + Sync
        fn assert_trait_send_sync<T: EnclaveProvider>() {}
        assert_trait_send_sync::<MockEnclaveProvider>();
    }

    #[tokio::test]
    async fn test_mock_enclave_multiple_shares() {
        let enclave = MockEnclaveProvider::new();
        let password = b"multi-share-pw";

        // Load 3 different shares
        let share1 = encrypt_share(b"share-1-secret", password);
        let share2 = encrypt_share(b"share-2-secret", password);
        let share3 = encrypt_share(b"share-3-secret", password);

        let h1 = enclave.load_share(&share1, password).await.unwrap();
        let h2 = enclave.load_share(&share2, password).await.unwrap();
        let h3 = enclave.load_share(&share3, password).await.unwrap();

        // All handles should be unique
        assert_ne!(h1.id, h2.id, "handles must be unique");
        assert_ne!(h2.id, h3.id, "handles must be unique");
        assert_ne!(h1.id, h3.id, "handles must be unique");

        // All handles should produce valid signatures
        let msg = b"test-message";

        let s1 = enclave.sign(&h1, msg).await.unwrap();
        let s2 = enclave.sign(&h2, msg).await.unwrap();
        let _s3 = enclave.sign(&h3, msg).await.unwrap();

        // Signatures should differ (different share data)
        assert_ne!(
            s1.data, s2.data,
            "different shares should produce different signatures"
        );

        // Destroy one, others should still work
        let h2_id = h2.id.clone();
        enclave.destroy(h2);
        assert!(enclave.sign(&h1, msg).await.is_ok());
        let dead_h2 = EnclaveHandle { id: h2_id };
        assert!(enclave.sign(&dead_h2, msg).await.is_err());
        assert!(enclave.sign(&h3, msg).await.is_ok());
    }

    #[tokio::test]
    async fn test_mock_enclave_wrong_password() {
        let enclave = MockEnclaveProvider::new();
        let encrypted = encrypt_share(b"secret-data", b"correct-password");

        let result = enclave.load_share(&encrypted, b"wrong-password").await;
        assert!(
            result.is_err(),
            "load_share with wrong password should fail"
        );
    }

    #[tokio::test]
    async fn test_mock_enclave_deterministic_signing() {
        let enclave = MockEnclaveProvider::new();
        let password = b"det-pw";
        let share_data = b"deterministic-share";
        let encrypted = encrypt_share(share_data, password);

        let handle = enclave.load_share(&encrypted, password).await.unwrap();

        // Same share + same message = same signature
        let msg = b"same-message";
        let sig1 = enclave.sign(&handle, msg).await.unwrap();
        let sig2 = enclave.sign(&handle, msg).await.unwrap();

        assert_eq!(
            sig1.data, sig2.data,
            "deterministic signing: data should match"
        );
        assert_eq!(
            sig1.party_id, sig2.party_id,
            "deterministic signing: party_id should match"
        );
    }
}
