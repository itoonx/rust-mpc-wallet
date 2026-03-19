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
use crate::protocol::MpcSignature;
use crate::types::PartyId;

use super::{AttestationReport, EnclaveHandle, EnclaveProvider};

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
    fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CoreError> {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|e| CoreError::Encryption(format!("Argon2 params error: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let password_bytes = Zeroizing::new(password.as_bytes().to_vec());
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password_bytes.as_slice(), salt, key_bytes.as_mut())
            .map_err(|e| CoreError::Encryption(format!("Key derivation failed: {e}")))?;

        Ok(key_bytes)
    }

    /// Decrypt data in the EncryptedFileStore format: `salt(32) | nonce(12) | ciphertext`.
    fn decrypt(password: &str, data: &[u8]) -> Result<Vec<u8>, CoreError> {
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
    pub fn encrypt(password: &str, data: &[u8]) -> Result<Vec<u8>, CoreError> {
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
        password: &str,
    ) -> Result<EnclaveHandle, CoreError> {
        let plaintext = Self::decrypt(password, encrypted_share)?;
        let handle_id = self.next_handle.fetch_add(1, Ordering::SeqCst);
        let mut map = self
            .shares
            .lock()
            .map_err(|e| CoreError::Other(format!("enclave lock poisoned: {e}")))?;
        map.insert(handle_id, Zeroizing::new(plaintext));
        Ok(EnclaveHandle(handle_id))
    }

    async fn sign(
        &self,
        handle: EnclaveHandle,
        message: &[u8],
        _signers: &[PartyId],
    ) -> Result<MpcSignature, CoreError> {
        let map = self
            .shares
            .lock()
            .map_err(|e| CoreError::Other(format!("enclave lock poisoned: {e}")))?;
        let share_data = map.get(&handle.0).ok_or_else(|| {
            CoreError::NotFound(format!(
                "enclave handle {} not found (share not loaded or already destroyed)",
                handle.0
            ))
        })?;

        // Mock signing: produce a deterministic ECDSA-shaped signature
        // derived from the share data and message. This is NOT cryptographically
        // valid — it exists only so tests can exercise the enclave signing path.
        let mut hasher = Sha256::new();
        hasher.update(share_data.as_slice());
        hasher.update(message);
        let hash = hasher.finalize();

        let mut r = hash.to_vec();
        let mut s = {
            let mut h2 = Sha256::new();
            h2.update(hash);
            h2.update(b"mock-s-component");
            h2.finalize().to_vec()
        };

        // Pad to 32 bytes (they already are from SHA-256, but be explicit)
        r.resize(32, 0);
        s.resize(32, 0);

        Ok(MpcSignature::Ecdsa {
            r,
            s,
            recovery_id: 0,
        })
    }

    async fn attestation_report(&self) -> Result<AttestationReport, CoreError> {
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
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&self.enclave_id);
        rand::thread_rng().fill_bytes(&mut report_data[32..]);

        Ok(AttestationReport {
            mrenclave,
            mrsigner,
            timestamp,
            report_data,
        })
    }

    async fn destroy(&self, handle: EnclaveHandle) -> Result<(), CoreError> {
        let mut map = self
            .shares
            .lock()
            .map_err(|e| CoreError::Other(format!("enclave lock poisoned: {e}")))?;
        // Remove and drop — Zeroizing<Vec<u8>> will clear the bytes on drop.
        // If handle doesn't exist (double destroy), this is a no-op.
        map.remove(&handle.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encrypt some share data with the given password.
    fn encrypt_share(data: &[u8], password: &str) -> Vec<u8> {
        MockEnclaveProvider::encrypt(password, data).expect("encryption should succeed")
    }

    #[tokio::test]
    async fn test_mock_enclave_load_and_destroy() {
        let enclave = MockEnclaveProvider::new();
        let password = "test-password-123";
        let share_data = b"secret-share-bytes-here";
        let encrypted = encrypt_share(share_data, password);

        // Load share into enclave
        let handle = enclave
            .load_share(&encrypted, password)
            .await
            .expect("load_share should succeed");

        // Verify handle is valid by signing with it
        let sig = enclave.sign(handle, b"test-message", &[PartyId(1)]).await;
        assert!(sig.is_ok(), "sign with valid handle should succeed");

        // Destroy the share
        enclave
            .destroy(handle)
            .await
            .expect("destroy should succeed");

        // Verify handle is now invalid
        let err = enclave.sign(handle, b"test-message", &[PartyId(1)]).await;
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
            .await
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

        // Timestamp should be recent (within last 60 seconds)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            report.timestamp <= now && report.timestamp >= now - 60,
            "timestamp should be recent"
        );

        // report_data should be 64 bytes (already guaranteed by type, but check non-zero)
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
        let password = "test-pw";
        let encrypted = encrypt_share(b"share-data", password);

        let handle = enclave
            .load_share(&encrypted, password)
            .await
            .expect("load should succeed");

        // First destroy
        enclave
            .destroy(handle)
            .await
            .expect("first destroy should succeed");

        // Second destroy — should NOT panic, should be a no-op
        enclave
            .destroy(handle)
            .await
            .expect("second destroy should succeed (no-op)");
    }

    #[tokio::test]
    async fn test_mock_enclave_sign_without_load() {
        let enclave = MockEnclaveProvider::new();

        // Try to sign with a handle that was never loaded
        let bogus_handle = EnclaveHandle(999);
        let result = enclave.sign(bogus_handle, b"message", &[PartyId(1)]).await;

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
        let password = "multi-share-pw";

        // Load 3 different shares
        let share1 = encrypt_share(b"share-1-secret", password);
        let share2 = encrypt_share(b"share-2-secret", password);
        let share3 = encrypt_share(b"share-3-secret", password);

        let h1 = enclave.load_share(&share1, password).await.unwrap();
        let h2 = enclave.load_share(&share2, password).await.unwrap();
        let h3 = enclave.load_share(&share3, password).await.unwrap();

        // All handles should be unique
        assert_ne!(h1, h2, "handles must be unique");
        assert_ne!(h2, h3, "handles must be unique");
        assert_ne!(h1, h3, "handles must be unique");

        // All handles should produce valid signatures
        let msg = b"test-message";
        let signers = &[PartyId(1), PartyId(2)];

        let s1 = enclave.sign(h1, msg, signers).await.unwrap();
        let s2 = enclave.sign(h2, msg, signers).await.unwrap();
        let _s3 = enclave.sign(h3, msg, signers).await.unwrap();

        // Signatures should differ (different share data)
        match (&s1, &s2) {
            (
                MpcSignature::Ecdsa { r: r1, s: s1v, .. },
                MpcSignature::Ecdsa { r: r2, s: s2v, .. },
            ) => {
                assert_ne!(r1, r2, "different shares should produce different r");
                assert_ne!(s1v, s2v, "different shares should produce different s");
            }
            _ => panic!("expected ECDSA signatures"),
        }

        // Destroy one, others should still work
        enclave.destroy(h2).await.unwrap();
        assert!(enclave.sign(h1, msg, signers).await.is_ok());
        assert!(enclave.sign(h2, msg, signers).await.is_err());
        assert!(enclave.sign(h3, msg, signers).await.is_ok());
    }

    #[tokio::test]
    async fn test_mock_enclave_wrong_password() {
        let enclave = MockEnclaveProvider::new();
        let encrypted = encrypt_share(b"secret-data", "correct-password");

        let result = enclave.load_share(&encrypted, "wrong-password").await;
        assert!(
            result.is_err(),
            "load_share with wrong password should fail"
        );
    }

    #[tokio::test]
    async fn test_mock_enclave_deterministic_signing() {
        let enclave = MockEnclaveProvider::new();
        let password = "det-pw";
        let share_data = b"deterministic-share";
        let encrypted = encrypt_share(share_data, password);

        let handle = enclave.load_share(&encrypted, password).await.unwrap();

        // Same share + same message = same signature
        let msg = b"same-message";
        let signers = &[PartyId(1)];
        let sig1 = enclave.sign(handle, msg, signers).await.unwrap();
        let sig2 = enclave.sign(handle, msg, signers).await.unwrap();

        match (&sig1, &sig2) {
            (
                MpcSignature::Ecdsa {
                    r: r1,
                    s: s1v,
                    recovery_id: v1,
                },
                MpcSignature::Ecdsa {
                    r: r2,
                    s: s2v,
                    recovery_id: v2,
                },
            ) => {
                assert_eq!(r1, r2, "deterministic signing: r should match");
                assert_eq!(s1v, s2v, "deterministic signing: s should match");
                assert_eq!(v1, v2, "deterministic signing: recovery_id should match");
            }
            _ => panic!("expected ECDSA signatures"),
        }
    }
}
