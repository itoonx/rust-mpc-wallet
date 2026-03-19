//! Signing abstraction for server authentication.
//!
//! Provides the [`AuthSigner`] trait so the handshake protocol can use either
//! a local Ed25519 key (`LocalSigner`) or a remote KMS key (`KmsSigner`)
//! without changing the handshake logic.

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use mpc_wallet_core::error::CoreError;

/// Async signing abstraction for server identity operations.
///
/// Implementations sign messages with Ed25519 and expose the verifying key
/// so handshake peers can verify ServerHello signatures.
#[async_trait]
pub trait AuthSigner: Send + Sync {
    /// Sign a message. Returns 64-byte Ed25519 signature.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError>;

    /// Get the public verifying key (32 bytes).
    fn verifying_key_bytes(&self) -> [u8; 32];

    /// Get the key ID (first 8 bytes of pubkey, hex-encoded).
    fn key_id(&self) -> String;
}

/// Local Ed25519 signer — wraps an in-process `ed25519_dalek::SigningKey`.
///
/// This is the default signer for dev/test environments where the server
/// signing key lives in process memory (loaded from `SERVER_SIGNING_KEY` env).
pub struct LocalSigner {
    signing_key: SigningKey,
}

impl LocalSigner {
    /// Create a new `LocalSigner` from an Ed25519 signing key.
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Get a reference to the underlying signing key (for backward compat).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

#[async_trait]
impl AuthSigner for LocalSigner {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        let signature = self.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    fn key_id(&self) -> String {
        hex::encode(&self.signing_key.verifying_key().to_bytes()[..8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::types::gen_ed25519_key;
    use ed25519_dalek::{Signature, Verifier};

    #[tokio::test]
    async fn test_local_signer_sign_and_verify() {
        let key = gen_ed25519_key();
        let verifying = key.verifying_key();
        let signer = LocalSigner::new(key);

        let message = b"test message for signing";
        let sig_bytes = signer.sign(message).await.unwrap();
        assert_eq!(sig_bytes.len(), 64);

        // Verify with dalek
        let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = Signature::from_bytes(&sig_array);
        verifying.verify(message, &signature).unwrap();
    }

    #[tokio::test]
    async fn test_local_signer_verifying_key_bytes() {
        let key = gen_ed25519_key();
        let expected = key.verifying_key().to_bytes();
        let signer = LocalSigner::new(key);
        assert_eq!(signer.verifying_key_bytes(), expected);
    }

    #[tokio::test]
    async fn test_local_signer_key_id() {
        let key = gen_ed25519_key();
        let expected = hex::encode(&key.verifying_key().to_bytes()[..8]);
        let signer = LocalSigner::new(key);
        assert_eq!(signer.key_id(), expected);
    }

    #[tokio::test]
    async fn test_local_signer_different_messages_different_sigs() {
        let signer = LocalSigner::new(gen_ed25519_key());
        let sig1 = signer.sign(b"message one").await.unwrap();
        let sig2 = signer.sign(b"message two").await.unwrap();
        assert_ne!(sig1, sig2);
    }

    #[tokio::test]
    async fn test_local_signer_deterministic() {
        let signer = LocalSigner::new(gen_ed25519_key());
        let msg = b"deterministic test";
        let sig1 = signer.sign(msg).await.unwrap();
        let sig2 = signer.sign(msg).await.unwrap();
        // Ed25519 is deterministic (RFC 8032).
        assert_eq!(sig1, sig2);
    }

    #[tokio::test]
    async fn test_local_signer_wrong_key_rejects() {
        let signer = LocalSigner::new(gen_ed25519_key());
        let other_key = gen_ed25519_key();
        let other_verifying = other_key.verifying_key();

        let sig_bytes = signer.sign(b"test").await.unwrap();
        let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = Signature::from_bytes(&sig_array);
        assert!(other_verifying.verify(b"test", &signature).is_err());
    }

    #[test]
    fn test_local_signer_trait_object_compatible() {
        let signer = LocalSigner::new(gen_ed25519_key());
        // Verify AuthSigner is object-safe by creating a trait object.
        let _boxed: Box<dyn AuthSigner> = Box::new(signer);
    }
}
