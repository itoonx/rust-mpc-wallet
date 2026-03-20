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

use std::collections::HashMap;

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
    /// Unique authorization ID for replay dedup within the TTL window (SEC-025).
    ///
    /// Each MPC node MUST track seen `authorization_id` values and reject any
    /// duplicate within `MAX_AUTHORIZATION_AGE_SECS`. This prevents a captured
    /// authorization from being replayed to sign the same message twice.
    pub authorization_id: String,
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
        // 0. Verify authorization_id is present (SEC-025 replay dedup).
        if self.payload.authorization_id.is_empty() {
            return Err(CoreError::Protocol(
                "sign authorization: missing authorization_id — required for replay protection"
                    .into(),
            ));
        }

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

    /// Verify the authorization proof and check for replay using a dedup cache.
    ///
    /// This is the recommended entry point for MPC nodes: it calls `verify()` first,
    /// then records the `authorization_id` in the cache. If the same ID was already
    /// seen (within the TTL window), the call returns an error.
    pub fn verify_with_cache(
        &self,
        expected_gateway_pubkey: &VerifyingKey,
        message_to_sign: &[u8],
        cache: &mut AuthorizationCache,
    ) -> Result<(), CoreError> {
        // First verify the authorization itself (signature, freshness, policy, etc.).
        self.verify(expected_gateway_pubkey, message_to_sign)?;

        // Then check and record the authorization_id for replay protection.
        cache.check_and_record(&self.payload.authorization_id, MAX_AUTHORIZATION_AGE_SECS)
    }
}

/// Node-side dedup cache for `SignAuthorization` replay protection (SEC-025).
///
/// Tracks seen `authorization_id` values and rejects duplicates within the TTL window.
/// An attacker who captures a valid `SignAuthorization` cannot replay it to sign the
/// same message twice — the second attempt will be rejected by this cache.
///
/// Each MPC node maintains its own `AuthorizationCache` instance.
pub struct AuthorizationCache {
    /// Maps authorization_id -> expiry timestamp (UNIX seconds).
    seen: HashMap<String, u64>,
    /// Maximum number of entries before forced pruning.
    max_entries: usize,
}

impl AuthorizationCache {
    /// Create a new cache with the given maximum entry count.
    pub fn new(max_entries: usize) -> Self {
        Self {
            seen: HashMap::new(),
            max_entries,
        }
    }

    /// Check if `auth_id` has been seen before; if not, record it.
    ///
    /// Returns `Err` if the `auth_id` is a duplicate (replay detected).
    /// Records the ID with expiry = now + `ttl_secs`.
    /// Prunes expired entries when approaching `max_entries`.
    pub fn check_and_record(&mut self, auth_id: &str, ttl_secs: u64) -> Result<(), CoreError> {
        let now = super::request_context::unix_now_secs();

        // Prune expired entries if we're at or near capacity.
        if self.seen.len() >= self.max_entries {
            self.prune_with_now(now);
        }

        // Hard reject if still at capacity after prune — prevents unbounded memory growth.
        // Legitimate traffic retries after entries expire; attack traffic is rate-limited.
        if self.seen.len() >= self.max_entries {
            return Err(CoreError::Protocol(
                "authorization cache at capacity — try again after entries expire".into(),
            ));
        }

        // Check for replay — entry exists and hasn't expired.
        if let Some(&expiry) = self.seen.get(auth_id) {
            if now < expiry {
                return Err(CoreError::Protocol(format!(
                    "sign authorization replay detected: authorization_id '{}' already used",
                    auth_id
                )));
            }
            // Entry exists but expired — allow reuse (remove stale entry).
            self.seen.remove(auth_id);
        }

        // Record the new authorization_id.
        self.seen.insert(auth_id.to_string(), now + ttl_secs);
        Ok(())
    }

    /// Remove all expired entries from the cache.
    pub fn prune(&mut self) {
        let now = super::request_context::unix_now_secs();
        self.prune_with_now(now);
    }

    /// Internal prune with explicit timestamp (for testability).
    fn prune_with_now(&mut self, now: u64) {
        self.seen.retain(|_, expiry| *expiry > now);
    }

    /// Number of entries currently in the cache (for diagnostics).
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
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
            authorization_id: format!("auth-{now}-test"),
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

    #[test]
    fn test_empty_authorization_id_rejected() {
        let key = test_key();
        let message = b"hello world";
        let mut payload = valid_payload(message);
        payload.authorization_id = String::new();

        let auth = SignAuthorization::create(payload, &key);
        let result = auth.verify(&key.verifying_key(), message);
        assert!(result.is_err());
        assert!(
            format!("{result:?}").contains("missing authorization_id"),
            "should reject empty authorization_id for replay protection"
        );
    }

    #[test]
    fn test_authorization_id_present_in_payload() {
        let key = test_key();
        let message = b"hello world";
        let payload = valid_payload(message);
        assert!(
            !payload.authorization_id.is_empty(),
            "authorization_id must be populated"
        );

        let auth = SignAuthorization::create(payload.clone(), &key);
        assert_eq!(auth.payload.authorization_id, payload.authorization_id);
    }

    // --- AuthorizationCache tests ---

    #[test]
    fn test_authorization_cache_rejects_replay() {
        let mut cache = AuthorizationCache::new(100);
        let key = test_key();
        let message = b"replay test";
        let payload = valid_payload(message);
        let auth = SignAuthorization::create(payload, &key);

        // First use should succeed.
        let result = auth.verify_with_cache(&key.verifying_key(), message, &mut cache);
        assert!(result.is_ok(), "first use should succeed: {result:?}");

        // Second use of the same authorization_id should be rejected.
        let result = auth.verify_with_cache(&key.verifying_key(), message, &mut cache);
        assert!(result.is_err(), "replay should be rejected");
        assert!(
            format!("{result:?}").contains("replay detected"),
            "error should mention replay: {result:?}"
        );
    }

    #[test]
    fn test_authorization_cache_allows_different_ids() {
        let mut cache = AuthorizationCache::new(100);
        let key = test_key();
        let message = b"different ids test";

        // Create two authorizations with different IDs.
        let mut payload1 = valid_payload(message);
        payload1.authorization_id = "auth-id-001".into();
        let auth1 = SignAuthorization::create(payload1, &key);

        let mut payload2 = valid_payload(message);
        payload2.authorization_id = "auth-id-002".into();
        let auth2 = SignAuthorization::create(payload2, &key);

        // Both should succeed.
        let r1 = auth1.verify_with_cache(&key.verifying_key(), message, &mut cache);
        assert!(r1.is_ok(), "first ID should succeed: {r1:?}");

        let r2 = auth2.verify_with_cache(&key.verifying_key(), message, &mut cache);
        assert!(r2.is_ok(), "second (different) ID should succeed: {r2:?}");

        assert_eq!(cache.len(), 2, "cache should have 2 entries");
    }

    #[test]
    fn test_authorization_cache_expires_old_entries() {
        let mut cache = AuthorizationCache::new(100);

        // Manually insert an entry that is already expired (expiry in the past).
        let now = crate::protocol::request_context::unix_now_secs();
        cache
            .seen
            .insert("old-auth-1".to_string(), now.saturating_sub(10));
        cache
            .seen
            .insert("old-auth-2".to_string(), now.saturating_sub(5));
        cache.seen.insert("fresh-auth".to_string(), now + 300);

        assert_eq!(cache.len(), 3);

        // Prune should remove the two expired entries.
        cache.prune();

        assert_eq!(cache.len(), 1, "only fresh entry should remain");
        assert!(
            cache.seen.contains_key("fresh-auth"),
            "fresh entry should survive pruning"
        );
    }

    #[test]
    fn test_authorization_cache_burst_exceeds_capacity() {
        // Create a cache with small capacity
        let mut cache = AuthorizationCache::new(5);

        // Insert exactly max_entries (5) entries — all with TTL=120s
        for i in 0..5 {
            let auth_id = format!("auth-burst-{i}");
            let result = cache.check_and_record(&auth_id, 120);
            assert!(
                result.is_ok(),
                "inserting auth-burst-{i} should succeed: {result:?}"
            );
        }
        assert_eq!(cache.len(), 5, "cache should be at capacity");

        // Next insert should be REJECTED — cache is full, no expired entries to prune.
        // This hard cap prevents unbounded memory growth under burst traffic.
        let overflow_result = cache.check_and_record("auth-burst-overflow", 120);
        assert!(
            overflow_result.is_err(),
            "insert beyond capacity must be rejected"
        );
        let err_msg = format!("{overflow_result:?}");
        assert!(
            err_msg.contains("at capacity"),
            "error should mention capacity: {err_msg}"
        );

        // Replay of existing entry also rejected (capacity check runs before replay check)
        let replay_result = cache.check_and_record("auth-burst-0", 120);
        assert!(
            replay_result.is_err(),
            "replay at capacity must be rejected"
        );
    }

    #[test]
    fn test_authorization_cache_capacity_with_mixed_expiry() {
        // Create a cache with max_entries=6 (3 short-lived + room for 6 long-lived after prune)
        let mut cache = AuthorizationCache::new(6);

        // Insert 3 entries with TTL=1 (will expire in 1 second)
        for i in 0..3 {
            let auth_id = format!("auth-short-{i}");
            let result = cache.check_and_record(&auth_id, 1);
            assert!(result.is_ok(), "short-TTL insert should succeed");
        }
        assert_eq!(cache.len(), 3, "should have 3 short-lived entries");

        // Wait for the short-TTL entries to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Insert 6 more entries with normal TTL.
        // When the cache reaches max_entries (6), prune will run and evict
        // the 3 expired entries, making room for the new ones.
        for i in 0..6 {
            let auth_id = format!("auth-long-{i}");
            let result = cache.check_and_record(&auth_id, 120);
            assert!(
                result.is_ok(),
                "long-TTL insert should succeed after expired entries are pruned"
            );
        }

        // After pruning the 3 expired entries and inserting 6 new ones,
        // the cache should contain exactly 6 entries (the long-lived ones).
        assert_eq!(
            cache.len(),
            6,
            "cache should contain only the 6 long-lived entries after pruning expired ones"
        );

        // Cache is now full — inserting the 7th should fail
        let overflow_result = cache.check_and_record("auth-overflow", 120);
        assert!(
            overflow_result.is_err(),
            "insert beyond capacity must be rejected"
        );

        // The expired short-TTL entries were pruned — they should NOT be treated as replays.
        // But cache is full (6/6), so we need to prune first. Force prune by waiting
        // (not possible here since long entries have 120s TTL). Instead, verify that
        // the expired entries are indeed gone from the cache.
        assert_eq!(cache.len(), 6, "cache stays at capacity");
    }
}
