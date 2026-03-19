//! KMS signer stub and key wrapping client for AWS KMS integration.
//!
//! This module provides:
//! - [`KmsSigner`]: placeholder that implements [`AuthSigner`] but returns an error
//!   on `sign()` (DEC-016: AWS KMS doesn't support Ed25519, so signing stays local).
//! - [`KmsConfig`]: configuration for KMS key ARN and region.
//! - [`KmsClient`]: key management helper for envelope encryption (wrap/unwrap/generate DEK).
//!
//! The `KmsClient` defines the interface for KMS key wrapping operations. Stub
//! implementations return errors until `aws-sdk-kms` is wired in behind the
//! `aws-kms` feature flag.

use async_trait::async_trait;
use mpc_wallet_core::error::CoreError;

use super::signer::AuthSigner;

// ---------------------------------------------------------------------------
// KmsSigner (backward-compatible AuthSigner stub)
// ---------------------------------------------------------------------------

/// KMS-backed signer stub.
///
/// Holds the KMS key ID and the corresponding Ed25519 verifying key (pre-loaded
/// at startup from KMS `GetPublicKey`). The `sign()` method will delegate to
/// KMS once the SDK is wired; for now it returns an error.
///
/// **DEC-016:** AWS KMS doesn't support Ed25519. Ed25519 signing stays local
/// via [`super::signer::LocalSigner`]. This struct is kept for backward compat.
pub struct KmsSigner {
    /// KMS key ID or alias (e.g. `alias/mpc-server-signing`).
    key_id: String,
    /// Ed25519 verifying key bytes (32 bytes), retrieved from KMS at startup.
    verifying_key: [u8; 32],
}

impl KmsSigner {
    /// Create a stub KMS signer for tests.
    ///
    /// In production, this will be replaced by a constructor that calls
    /// `kms:GetPublicKey` to fetch the verifying key.
    pub fn new_stub(key_id: String, verifying_key: [u8; 32]) -> Self {
        Self {
            key_id,
            verifying_key,
        }
    }
}

#[async_trait]
impl AuthSigner for KmsSigner {
    async fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, CoreError> {
        Err(CoreError::Protocol(
            "KMS signing not configured — set KMS_KEY_ID".to_string(),
        ))
    }

    fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key
    }

    fn key_id(&self) -> String {
        self.key_id.clone()
    }
}

// ---------------------------------------------------------------------------
// KmsConfig
// ---------------------------------------------------------------------------

/// Configuration for AWS KMS key wrapping operations.
///
/// Loaded from environment variables:
/// - `KMS_KEY_ARN`: ARN of the KMS key used for envelope encryption
/// - `KMS_REGION`: AWS region (e.g., `us-east-1`)
#[derive(Debug, Clone)]
pub struct KmsConfig {
    /// ARN of the KMS CMK (e.g., `arn:aws:kms:us-east-1:123456789:key/...`).
    pub key_arn: String,
    /// AWS region (e.g., `us-east-1`).
    pub region: String,
}

impl KmsConfig {
    /// Load KMS configuration from environment variables.
    ///
    /// Returns `None` if `KMS_KEY_ARN` is not set (KMS disabled).
    pub fn from_env() -> Option<Self> {
        let key_arn = std::env::var("KMS_KEY_ARN").ok()?;
        let region = std::env::var("KMS_REGION").unwrap_or_else(|_| "us-east-1".into());
        Some(Self { key_arn, region })
    }

    /// Create a config with explicit values (for tests).
    pub fn new(key_arn: String, region: String) -> Self {
        Self { key_arn, region }
    }
}

// ---------------------------------------------------------------------------
// KmsClient — key wrapping operations
// ---------------------------------------------------------------------------

/// KMS client for envelope encryption key management.
///
/// Provides wrap/unwrap/generate-DEK operations using a KMS customer master key (CMK).
/// Currently stubs — returns errors until `aws-sdk-kms` is wired in.
///
/// # Envelope Encryption Pattern
///
/// 1. `generate_data_key()` → KMS returns (plaintext DEK, encrypted DEK)
/// 2. Use plaintext DEK locally for AES/ChaCha20 encryption
/// 3. Store encrypted DEK alongside ciphertext
/// 4. `unwrap_key(encrypted_dek)` → recover plaintext DEK for decryption
/// 5. `wrap_key(plaintext)` → encrypt arbitrary key material with CMK
pub struct KmsClient {
    config: KmsConfig,
}

impl KmsClient {
    /// Create a new KMS client with the given configuration.
    pub fn new(config: KmsConfig) -> Self {
        Self { config }
    }

    /// Get the configured KMS key ARN.
    pub fn key_arn(&self) -> &str {
        &self.config.key_arn
    }

    /// Get the configured AWS region.
    pub fn region(&self) -> &str {
        &self.config.region
    }

    /// Encrypt (wrap) a plaintext key using the KMS CMK.
    ///
    /// In production this calls `kms:Encrypt` with the configured CMK ARN.
    /// Returns the ciphertext blob that can only be decrypted by calling
    /// `unwrap_key()` with the same CMK.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Protocol` until real AWS SDK is wired in.
    pub async fn wrap_key(&self, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
        if plaintext.is_empty() {
            return Err(CoreError::Protocol(
                "KMS wrap_key: plaintext must not be empty".to_string(),
            ));
        }
        // TODO: Replace with real aws-sdk-kms Encrypt call.
        // let client = aws_sdk_kms::Client::new(&config);
        // let resp = client.encrypt()
        //     .key_id(&self.config.key_arn)
        //     .plaintext(Blob::new(plaintext))
        //     .send().await?;
        Err(CoreError::Protocol(format!(
            "KMS wrap_key not available — aws-sdk-kms not configured (key_arn={})",
            self.config.key_arn
        )))
    }

    /// Decrypt (unwrap) a ciphertext blob using the KMS CMK.
    ///
    /// In production this calls `kms:Decrypt` with the ciphertext that was
    /// previously produced by `wrap_key()` or `generate_data_key()`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Protocol` until real AWS SDK is wired in.
    pub async fn unwrap_key(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CoreError> {
        if ciphertext.is_empty() {
            return Err(CoreError::Protocol(
                "KMS unwrap_key: ciphertext must not be empty".to_string(),
            ));
        }
        // TODO: Replace with real aws-sdk-kms Decrypt call.
        // let client = aws_sdk_kms::Client::new(&config);
        // let resp = client.decrypt()
        //     .ciphertext_blob(Blob::new(ciphertext))
        //     .send().await?;
        Err(CoreError::Protocol(format!(
            "KMS unwrap_key not available — aws-sdk-kms not configured (key_arn={})",
            self.config.key_arn
        )))
    }

    /// Generate a data encryption key (DEK) using the KMS CMK.
    ///
    /// Returns `(plaintext_key, encrypted_key)`:
    /// - `plaintext_key`: 32-byte AES-256 key for local encryption (zeroize after use!)
    /// - `encrypted_key`: KMS-encrypted copy to store alongside ciphertext
    ///
    /// In production this calls `kms:GenerateDataKey` with `AES_256`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Protocol` until real AWS SDK is wired in.
    pub async fn generate_data_key(&self) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
        // TODO: Replace with real aws-sdk-kms GenerateDataKey call.
        // let client = aws_sdk_kms::Client::new(&config);
        // let resp = client.generate_data_key()
        //     .key_id(&self.config.key_arn)
        //     .key_spec(DataKeySpec::Aes256)
        //     .send().await?;
        // Ok((resp.plaintext.unwrap().into_inner(), resp.ciphertext_blob.unwrap().into_inner()))
        Err(CoreError::Protocol(format!(
            "KMS generate_data_key not available — aws-sdk-kms not configured (key_arn={})",
            self.config.key_arn
        )))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::types::gen_ed25519_key;

    // -- Existing KmsSigner tests (backward compat) --

    #[tokio::test]
    async fn test_kms_signer_sign_returns_error() {
        let key = gen_ed25519_key();
        let vk = key.verifying_key().to_bytes();
        let signer = KmsSigner::new_stub("alias/test-key".into(), vk);

        let result = signer.sign(b"test message").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("KMS signing not configured"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_kms_signer_verifying_key() {
        let key = gen_ed25519_key();
        let vk = key.verifying_key().to_bytes();
        let signer = KmsSigner::new_stub("alias/test-key".into(), vk);
        assert_eq!(signer.verifying_key_bytes(), vk);
    }

    #[tokio::test]
    async fn test_kms_signer_key_id() {
        let signer = KmsSigner::new_stub("alias/my-kms-key".into(), [0u8; 32]);
        assert_eq!(signer.key_id(), "alias/my-kms-key");
    }

    #[test]
    fn test_kms_signer_trait_object_compatible() {
        let signer = KmsSigner::new_stub("test".into(), [0u8; 32]);
        let _boxed: Box<dyn AuthSigner> = Box::new(signer);
    }

    // -- T-S22-01: KmsConfig tests --

    #[test]
    fn test_kms_config_from_env() {
        // Without KMS_KEY_ARN → None
        std::env::remove_var("KMS_KEY_ARN");
        std::env::remove_var("KMS_REGION");
        assert!(KmsConfig::from_env().is_none());

        // With KMS_KEY_ARN, no region → defaults to us-east-1
        std::env::set_var(
            "KMS_KEY_ARN",
            "arn:aws:kms:us-east-1:123456789:key/test-key-id",
        );
        let config = KmsConfig::from_env().expect("should parse with KMS_KEY_ARN");
        assert_eq!(
            config.key_arn,
            "arn:aws:kms:us-east-1:123456789:key/test-key-id"
        );
        assert_eq!(config.region, "us-east-1");

        // With explicit region
        std::env::set_var("KMS_REGION", "eu-west-1");
        let config = KmsConfig::from_env().unwrap();
        assert_eq!(config.region, "eu-west-1");

        // Cleanup
        std::env::remove_var("KMS_KEY_ARN");
        std::env::remove_var("KMS_REGION");
    }

    #[test]
    fn test_kms_config_new() {
        let config = KmsConfig::new(
            "arn:aws:kms:us-west-2:111:key/abc".into(),
            "us-west-2".into(),
        );
        assert_eq!(config.key_arn, "arn:aws:kms:us-west-2:111:key/abc");
        assert_eq!(config.region, "us-west-2");
    }

    // -- T-S22-01: KmsClient tests --

    #[tokio::test]
    async fn test_kms_client_wrap_unwrap_stub() {
        let config = KmsConfig::new(
            "arn:aws:kms:us-east-1:123:key/test".into(),
            "us-east-1".into(),
        );
        let client = KmsClient::new(config);

        // wrap_key returns structured error (not available)
        let result = client.wrap_key(b"secret-key-material").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("KMS wrap_key not available"),
            "unexpected: {err}"
        );
        assert!(err.contains("key/test"), "should include key ARN: {err}");

        // unwrap_key returns structured error (not available)
        let result = client.unwrap_key(b"encrypted-blob").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("KMS unwrap_key not available"),
            "unexpected: {err}"
        );
    }

    #[tokio::test]
    async fn test_kms_client_wrap_empty_plaintext_rejected() {
        let config = KmsConfig::new("arn:test".into(), "us-east-1".into());
        let client = KmsClient::new(config);

        let result = client.wrap_key(b"").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("plaintext must not be empty"),
            "should reject empty plaintext: {err}"
        );
    }

    #[tokio::test]
    async fn test_kms_client_unwrap_empty_ciphertext_rejected() {
        let config = KmsConfig::new("arn:test".into(), "us-east-1".into());
        let client = KmsClient::new(config);

        let result = client.unwrap_key(b"").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("ciphertext must not be empty"),
            "should reject empty ciphertext: {err}"
        );
    }

    #[tokio::test]
    async fn test_kms_generate_data_key_stub() {
        let config = KmsConfig::new(
            "arn:aws:kms:us-east-1:123:key/dek-test".into(),
            "us-east-1".into(),
        );
        let client = KmsClient::new(config);

        let result = client.generate_data_key().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("KMS generate_data_key not available"),
            "unexpected: {err}"
        );
        assert!(err.contains("dek-test"), "should include key ARN: {err}");
    }

    #[test]
    fn test_kms_client_accessors() {
        let config = KmsConfig::new(
            "arn:aws:kms:ap-south-1:999:key/xyz".into(),
            "ap-south-1".into(),
        );
        let client = KmsClient::new(config);
        assert_eq!(client.key_arn(), "arn:aws:kms:ap-south-1:999:key/xyz");
        assert_eq!(client.region(), "ap-south-1");
    }
}
