//! KMS signer stub for future AWS KMS / Azure Key Vault / GCP Cloud KMS integration.
//!
//! This module provides a placeholder [`KmsSigner`] that implements [`AuthSigner`]
//! but returns an error on `sign()`. It exists to define the integration surface
//! so that the handshake protocol can be wired to `Arc<dyn AuthSigner>` today,
//! with the real KMS implementation added later when the AWS SDK dependency is introduced.

use async_trait::async_trait;
use mpc_wallet_core::error::CoreError;

use super::signer::AuthSigner;

/// KMS-backed signer stub.
///
/// Holds the KMS key ID and the corresponding Ed25519 verifying key (pre-loaded
/// at startup from KMS `GetPublicKey`). The `sign()` method will delegate to
/// KMS once the SDK is wired; for now it returns an error.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::types::gen_ed25519_key;

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
}
