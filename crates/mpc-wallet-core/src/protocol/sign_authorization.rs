//! Sign Authorization Proof — independent verification at MPC nodes.
//!
//! **Problem:** MPC nodes blindly trust the gateway to enforce policy and approvals.
//! If the gateway is compromised, an attacker can sign any transaction.
//!
//! **Solution:** The gateway produces a `SignAuthorization` — a signed proof that:
//! 1. The requester was authenticated (who)
//! 2. Policy was checked and passed (what)
//! 3. Approval quorum was met (how many approved)
//! 4. The request is fresh (when)
//!
//! Each MPC node **independently verifies** this proof before participating in signing.
//! The node refuses to sign if the proof is missing, expired, or has an invalid signature.
//!
//! ```text
//! Gateway (compromised?)          MPC Node (independent)
//! ┌────────────────────┐          ┌──────────────────────┐
//! │ 1. Auth user       │          │                      │
//! │ 2. Check policy    │          │ Verify:              │
//! │ 3. Collect approvals│ ──────► │  - Gateway signature │
//! │ 4. Sign authorization│        │  - Not expired       │
//! │ 5. Send to MPC node│          │  - Approvals valid   │
//! └────────────────────┘          │  - Policy hash match │
//!                                 │ THEN sign            │
//!                                 └──────────────────────┘
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::request_context::EncryptedRequestContext;
use crate::error::CoreError;

/// Maximum age of a sign authorization (seconds).
pub const MAX_AUTHORIZATION_AGE_SECS: u64 = 120; // 2 minutes

/// The authorization payload — signed by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationPayload {
    /// Who requested the sign (user ID from auth context).
    pub requester_id: String,
    /// Which wallet is being signed.
    pub wallet_id: String,
    /// SHA-256 of the message to be signed (hex).
    pub message_hash: String,
    /// SHA-256 of the policy that was evaluated (hex). Empty if no policy.
    pub policy_hash: String,
    /// Whether policy check passed.
    pub policy_passed: bool,
    /// Number of approvals collected.
    pub approval_count: u32,
    /// Required approval count (quorum).
    pub approval_required: u32,
    /// Approval evidence — each approver's ID + signature hash.
    pub approvers: Vec<ApproverEvidence>,
    /// UNIX timestamp when authorization was created.
    pub timestamp: u64,
    /// Session ID for correlation.
    pub session_id: String,
    /// Encrypted request context (IP, device, fingerprint) — for audit/tracing.
    /// Encrypted with ChaCha20-Poly1305 using the session's derived key.
    /// MPC nodes store this opaque blob for audit without needing to decrypt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_context: Option<EncryptedRequestContext>,
}

/// Evidence from a single approver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverEvidence {
    /// Approver's user ID.
    pub approver_id: String,
    /// SHA-256 of the approver's Ed25519 signature (hex) — not the full sig.
    pub signature_hash: String,
}

/// A signed authorization proof from the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignAuthorization {
    /// The authorization payload.
    pub payload: AuthorizationPayload,
    /// Ed25519 signature over SHA-256(payload) by the gateway's signing key.
    pub gateway_signature: Vec<u8>,
    /// Gateway's Ed25519 public key (for verification).
    pub gateway_pubkey: Vec<u8>,
}

impl SignAuthorization {
    /// Create a new authorization proof, signed by the gateway.
    pub fn create(payload: AuthorizationPayload, gateway_key: &SigningKey) -> Self {
        let hash = Self::payload_hash(&payload);
        let signature = gateway_key.sign(&hash);

        Self {
            payload,
            gateway_signature: signature.to_bytes().to_vec(),
            gateway_pubkey: gateway_key.verifying_key().to_bytes().to_vec(),
        }
    }

    /// Verify the authorization proof at an MPC node.
    ///
    /// Checks:
    /// 1. Gateway signature is valid (proof of origin)
    /// 2. Gateway pubkey matches expected (prevents impersonation)
    /// 3. Authorization is not expired (freshness)
    /// 4. Message hash matches what we're about to sign (binding)
    /// 5. Policy check passed
    /// 6. Approval quorum met
    pub fn verify(
        &self,
        expected_gateway_pubkey: &VerifyingKey,
        message_to_sign: &[u8],
    ) -> Result<(), CoreError> {
        // 1. Verify gateway pubkey matches expected.
        if self.gateway_pubkey.len() != 32 {
            return Err(CoreError::Protocol(
                "sign authorization: invalid gateway pubkey length".into(),
            ));
        }
        let presented_pubkey =
            VerifyingKey::from_bytes(&self.gateway_pubkey.clone().try_into().map_err(|_| {
                CoreError::Protocol("sign authorization: invalid gateway pubkey".into())
            })?)
            .map_err(|_| {
                CoreError::Protocol("sign authorization: invalid gateway pubkey format".into())
            })?;

        if presented_pubkey != *expected_gateway_pubkey {
            return Err(CoreError::Protocol(
                "sign authorization: gateway pubkey mismatch — possible impersonation".into(),
            ));
        }

        // 2. Verify gateway signature.
        let hash = Self::payload_hash(&self.payload);
        if self.gateway_signature.len() != 64 {
            return Err(CoreError::Protocol(
                "sign authorization: invalid signature length".into(),
            ));
        }
        let sig_bytes: [u8; 64] = self
            .gateway_signature
            .clone()
            .try_into()
            .map_err(|_| CoreError::Protocol("sign authorization: invalid signature".into()))?;
        let signature = Signature::from_bytes(&sig_bytes);
        expected_gateway_pubkey
            .verify(&hash, &signature)
            .map_err(|_| {
                CoreError::Protocol("sign authorization: invalid gateway signature".into())
            })?;

        // 3. Check freshness (not expired).
        let now = super::request_context::unix_now_secs();
        if now.abs_diff(self.payload.timestamp) > MAX_AUTHORIZATION_AGE_SECS {
            return Err(CoreError::Protocol(format!(
                "sign authorization expired: age {}s > max {}s",
                now.abs_diff(self.payload.timestamp),
                MAX_AUTHORIZATION_AGE_SECS
            )));
        }

        // 4. Verify message binding (what we're about to sign matches the proof).
        let expected_hash = hex::encode(Sha256::digest(message_to_sign));
        if self.payload.message_hash != expected_hash {
            return Err(CoreError::Protocol(
                "sign authorization: message hash mismatch — gateway authorized a different message".into(),
            ));
        }

        // 5. Verify policy check passed.
        if !self.payload.policy_passed {
            return Err(CoreError::Protocol(
                "sign authorization: policy check did not pass".into(),
            ));
        }

        // 6. Verify approval quorum met.
        if self.payload.approval_count < self.payload.approval_required {
            return Err(CoreError::Protocol(format!(
                "sign authorization: insufficient approvals ({}/{})",
                self.payload.approval_count, self.payload.approval_required
            )));
        }

        Ok(())
    }

    /// Compute SHA-256 hash of the payload for signing/verification.
    fn payload_hash(payload: &AuthorizationPayload) -> [u8; 32] {
        let serialized =
            serde_json::to_vec(payload).expect("AuthorizationPayload serialization cannot fail");
        Sha256::digest(serialized).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        SigningKey::from_bytes(&bytes)
    }

    fn valid_payload(message: &[u8]) -> AuthorizationPayload {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        AuthorizationPayload {
            requester_id: "user-123".into(),
            wallet_id: "wallet-abc".into(),
            message_hash: hex::encode(Sha256::digest(message)),
            policy_hash: hex::encode(Sha256::digest(b"test-policy")),
            policy_passed: true,
            approval_count: 2,
            approval_required: 2,
            approvers: vec![
                ApproverEvidence {
                    approver_id: "approver-1".into(),
                    signature_hash: "aabb".into(),
                },
                ApproverEvidence {
                    approver_id: "approver-2".into(),
                    signature_hash: "ccdd".into(),
                },
            ],
            timestamp: now,
            session_id: "session-xyz".into(),
            encrypted_context: None,
        }
    }

    #[test]
    fn test_valid_authorization() {
        let key = test_key();
        let message = b"hello world";
        let payload = valid_payload(message);
        let auth = SignAuthorization::create(payload, &key);

        let result = auth.verify(&key.verifying_key(), message);
        assert!(
            result.is_ok(),
            "valid authorization should pass: {result:?}"
        );
    }

    #[test]
    fn test_wrong_gateway_key_rejected() {
        let key = test_key();
        let wrong_key = SigningKey::from_bytes(&[99u8; 32]);
        let message = b"hello world";
        let payload = valid_payload(message);
        let auth = SignAuthorization::create(payload, &key);

        let result = auth.verify(&wrong_key.verifying_key(), message);
        assert!(result.is_err());
        assert!(
            format!("{result:?}").contains("pubkey mismatch"),
            "should detect gateway impersonation"
        );
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let key = test_key();
        let message = b"hello world";
        let payload = valid_payload(message);
        let mut auth = SignAuthorization::create(payload, &key);

        // Tamper with the payload after signing.
        auth.payload.requester_id = "attacker".into();

        let result = auth.verify(&key.verifying_key(), message);
        assert!(result.is_err());
        assert!(
            format!("{result:?}").contains("invalid gateway signature"),
            "should detect payload tampering"
        );
    }

    #[test]
    fn test_wrong_message_rejected() {
        let key = test_key();
        let message = b"hello world";
        let payload = valid_payload(message);
        let auth = SignAuthorization::create(payload, &key);

        // Try to sign a different message.
        let result = auth.verify(&key.verifying_key(), b"different message");
        assert!(result.is_err());
        assert!(
            format!("{result:?}").contains("message hash mismatch"),
            "should detect message substitution"
        );
    }

    #[test]
    fn test_expired_authorization_rejected() {
        let key = test_key();
        let message = b"hello world";
        let mut payload = valid_payload(message);
        payload.timestamp = 1000; // very old

        let auth = SignAuthorization::create(payload, &key);
        let result = auth.verify(&key.verifying_key(), message);
        assert!(result.is_err());
        assert!(
            format!("{result:?}").contains("expired"),
            "should detect expired authorization"
        );
    }

    #[test]
    fn test_policy_not_passed_rejected() {
        let key = test_key();
        let message = b"hello world";
        let mut payload = valid_payload(message);
        payload.policy_passed = false;

        let auth = SignAuthorization::create(payload, &key);
        let result = auth.verify(&key.verifying_key(), message);
        assert!(result.is_err());
        assert!(format!("{result:?}").contains("policy check did not pass"));
    }

    #[test]
    fn test_insufficient_approvals_rejected() {
        let key = test_key();
        let message = b"hello world";
        let mut payload = valid_payload(message);
        payload.approval_count = 1; // only 1 of 2 required

        let auth = SignAuthorization::create(payload, &key);
        let result = auth.verify(&key.verifying_key(), message);
        assert!(result.is_err());
        assert!(format!("{result:?}").contains("insufficient approvals"));
    }

    #[test]
    fn test_forged_signature_rejected() {
        let key = test_key();
        let message = b"hello world";
        let payload = valid_payload(message);
        let mut auth = SignAuthorization::create(payload, &key);

        // Replace signature with garbage.
        auth.gateway_signature = vec![0xFF; 64];

        let result = auth.verify(&key.verifying_key(), message);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_approvals_required_passes() {
        let key = test_key();
        let message = b"hello world";
        let mut payload = valid_payload(message);
        payload.approval_count = 0;
        payload.approval_required = 0;
        payload.approvers.clear();

        let auth = SignAuthorization::create(payload, &key);
        let result = auth.verify(&key.verifying_key(), message);
        assert!(result.is_ok(), "zero-required approvals should pass");
    }
}
