//! Request context — encrypted metadata for sign request tracing.
//!
//! Captures device/network information at the point of request and encrypts it
//! using ChaCha20-Poly1305 with the session's derived key. This provides:
//!
//! 1. **Integrity** — context cannot be tampered with (AEAD authentication)
//! 2. **Confidentiality** — IP/device info encrypted in transit and at rest
//! 3. **Binding** — context is tied to the session key (key-exchange derived)
//! 4. **Traceability** — MPC nodes can store encrypted context for audit without decrypting
//!
//! ```text
//! Client Device                        Gateway                         MPC Node
//! ┌──────────────┐   encrypted    ┌──────────────────┐   encrypted   ┌────────────┐
//! │ IP, UA, FP   │──────────────►│ decrypt + verify  │─────────────►│ store blob │
//! │ in JWT/header│  (session key) │ re-encrypt for    │ (audit key)  │ for audit  │
//! └──────────────┘                │ audit trail       │              └────────────┘
//! ```

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CoreError;

/// Plaintext request context — captured at the gateway from the HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    /// Client IP address (from X-Forwarded-For or socket addr).
    pub client_ip: String,
    /// User-Agent header.
    pub user_agent: String,
    /// Device fingerprint (from client SDK — browser/device hash).
    pub device_fingerprint: String,
    /// Request ID (unique per request, for correlation).
    pub request_id: String,
    /// ISO 8601 timestamp when the request was received.
    pub requested_at: String,
    /// Geographic location hint (from IP geolocation, optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_hint: Option<String>,
    /// Additional metadata (extensible).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Encrypted request context — AEAD-encrypted with ChaCha20-Poly1305.
///
/// The encryption key can be:
/// - **Session key** (`client_write_key` from handshake) — for client→gateway transmission
/// - **Audit key** (service-level key) — for at-rest storage in audit logs
///
/// The nonce is unique per encryption and included in the struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedRequestContext {
    /// 12-byte nonce (hex-encoded).
    pub nonce: String,
    /// AEAD ciphertext + 16-byte authentication tag (hex-encoded).
    pub ciphertext: String,
    /// SHA-256 of the plaintext context (hex) — for integrity verification without decryption.
    pub context_hash: String,
}

impl EncryptedRequestContext {
    /// Encrypt a `RequestContext` using ChaCha20-Poly1305.
    ///
    /// `key` must be exactly 32 bytes (e.g., session's `client_write_key`).
    pub fn encrypt(context: &RequestContext, key: &[u8; 32]) -> Result<Self, CoreError> {
        let plaintext = serde_json::to_vec(context)
            .map_err(|e| CoreError::Protocol(format!("request context serialization: {e}")))?;

        let context_hash = hex::encode(Sha256::digest(&plaintext));

        // Generate a random 12-byte nonce.
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| CoreError::Protocol(format!("AEAD key init: {e}")))?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_slice())
            .map_err(|e| CoreError::Protocol(format!("AEAD encrypt: {e}")))?;

        Ok(Self {
            nonce: hex::encode(nonce_bytes),
            ciphertext: hex::encode(ciphertext),
            context_hash,
        })
    }

    /// Decrypt back to `RequestContext` using the same key.
    pub fn decrypt(&self, key: &[u8; 32]) -> Result<RequestContext, CoreError> {
        let nonce_bytes = hex::decode(&self.nonce)
            .map_err(|_| CoreError::Protocol("request context: invalid nonce hex".into()))?;
        if nonce_bytes.len() != 12 {
            return Err(CoreError::Protocol(
                "request context: nonce must be 12 bytes".into(),
            ));
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = hex::decode(&self.ciphertext)
            .map_err(|_| CoreError::Protocol("request context: invalid ciphertext hex".into()))?;

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| CoreError::Protocol(format!("AEAD key init: {e}")))?;
        let plaintext = cipher.decrypt(nonce, ciphertext.as_slice()).map_err(|_| {
            CoreError::Protocol(
                "request context: AEAD decryption failed (tampered or wrong key)".into(),
            )
        })?;

        // Verify content hash.
        let actual_hash = hex::encode(Sha256::digest(&plaintext));
        if actual_hash != self.context_hash {
            return Err(CoreError::Protocol(
                "request context: content hash mismatch after decryption".into(),
            ));
        }

        serde_json::from_slice(&plaintext)
            .map_err(|e| CoreError::Protocol(format!("request context deserialization: {e}")))
    }
}

// ── Sign Timeline ─────────────────────────────────────────────────

/// A timestamped event in the signing lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// What happened.
    pub step: SignStep,
    /// UNIX timestamp (milliseconds) when this step occurred.
    pub timestamp_ms: u64,
    /// Who performed this step (user ID, party ID, or system).
    pub actor: String,
    /// Additional details (step-specific).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Steps in the signing lifecycle — every step is recorded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignStep {
    /// Sign request received at gateway.
    RequestReceived,
    /// Authentication validated (which method: session/api-key/jwt).
    AuthValidated,
    /// RBAC/ABAC permission check passed.
    PermissionChecked,
    /// Policy evaluation completed.
    PolicyEvaluated,
    /// Single approval submitted by an approver.
    ApprovalSubmitted,
    /// Approval quorum reached (M-of-N met).
    QuorumReached,
    /// SignAuthorization created and signed by gateway.
    AuthorizationCreated,
    /// MPC party received sign request + authorization.
    PartyReceived,
    /// MPC party verified SignAuthorization independently.
    PartyVerifiedAuth,
    /// MPC protocol round started (round number in detail).
    ProtocolRoundStarted,
    /// MPC protocol round completed (round number in detail).
    ProtocolRoundCompleted,
    /// MPC party produced its partial signature.
    PartialSignatureProduced,
    /// Final signature assembled from partial signatures.
    SignatureAssembled,
    /// Signature verified against group public key.
    SignatureVerified,
    /// Transaction broadcast to chain (if applicable).
    TransactionBroadcast,
    /// Audit record committed to ledger.
    AuditCommitted,
    /// Signing failed at this step.
    Failed,
}

/// Record of a single approver's participation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverRecord {
    /// Approver's user ID.
    pub approver_id: String,
    /// Approver's role (e.g., "approver", "admin").
    pub role: String,
    /// UNIX timestamp (ms) when approval was submitted.
    pub approved_at_ms: u64,
    /// SHA-256 of the approval signature (hex) — not the full signature.
    pub signature_hash: String,
}

/// Record of a single MPC party's participation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyRecord {
    /// Party ID (1-indexed).
    pub party_id: u16,
    /// UNIX timestamp (ms) when party received the request.
    pub received_at_ms: u64,
    /// UNIX timestamp (ms) when party verified the authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at_ms: Option<u64>,
    /// UNIX timestamp (ms) when party produced its partial signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at_ms: Option<u64>,
    /// Whether the party completed successfully.
    pub success: bool,
    /// Error message if the party failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Complete audit record for a single sign operation.
///
/// Captures **every participant** and **every step** with millisecond timestamps.
/// This is the primary artifact for compliance, incident investigation, and monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignAuditRecord {
    // ── Identity ─────────────────────────────────────
    /// Unique session ID for this sign operation.
    pub session_id: String,
    /// Wallet being signed.
    pub wallet_id: String,
    /// MPC signing scheme used (e.g., "gg20-ecdsa").
    pub scheme: String,
    /// Threshold config (e.g., "2-of-3").
    pub threshold: String,

    // ── Message ──────────────────────────────────────
    /// SHA-256 of the message that was signed (hex).
    pub message_hash: String,
    /// Chain (if applicable, e.g., "ethereum").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,

    // ── Requester ────────────────────────────────────
    /// Who requested the sign (from AuthContext).
    pub requester_id: String,
    /// Auth method used (session_token, api_key, jwt).
    pub auth_method: String,
    /// Encrypted request context (IP, device, fingerprint).
    pub encrypted_context: EncryptedRequestContext,

    // ── Policy ───────────────────────────────────────
    /// SHA-256 of the policy that was evaluated (hex).
    pub policy_hash: String,
    /// Whether policy check passed.
    pub policy_passed: bool,
    /// Policy evaluation details (e.g., "allowlist: pass, velocity: 3/10 daily").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_detail: Option<String>,

    // ── Approvals ────────────────────────────────────
    /// Required approval count (quorum).
    pub approval_required: u32,
    /// Record of every approver who participated.
    pub approvers: Vec<ApproverRecord>,

    // ── MPC Parties ──────────────────────────────────
    /// Record of every MPC party that participated.
    pub parties: Vec<PartyRecord>,

    // ── Result ───────────────────────────────────────
    /// Whether the overall sign operation succeeded.
    pub success: bool,
    /// Error message if signing failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// SHA-256 of the final signature (hex) — for correlation, not the actual sig.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_hash: Option<String>,
    /// Transaction hash if broadcast (hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,

    // ── Timeline ─────────────────────────────────────
    /// Ordered list of every step with timestamps.
    pub timeline: Vec<TimelineEvent>,

    // ── Timestamps (summary) ─────────────────────────
    /// When the sign request was first received (ms).
    pub started_at_ms: u64,
    /// When the sign operation completed or failed (ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at_ms: Option<u64>,
    /// Total duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Get current UNIX timestamp in milliseconds.
pub fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl SignAuditRecord {
    /// Add a timeline event.
    pub fn record(&mut self, step: SignStep, actor: &str, detail: Option<String>) {
        self.timeline.push(TimelineEvent {
            step,
            timestamp_ms: unix_now_ms(),
            actor: actor.into(),
            detail,
        });
    }

    /// Add an approver record.
    pub fn record_approval(&mut self, approver: ApproverRecord) {
        self.record(
            SignStep::ApprovalSubmitted,
            &approver.approver_id.clone(),
            Some(format!("role={}", approver.role)),
        );
        self.approvers.push(approver);
    }

    /// Add an MPC party record (initial — received request).
    pub fn record_party_received(&mut self, party_id: u16) {
        let now = unix_now_ms();
        self.record(SignStep::PartyReceived, &format!("party_{party_id}"), None);
        self.parties.push(PartyRecord {
            party_id,
            received_at_ms: now,
            verified_at_ms: None,
            signed_at_ms: None,
            success: false,
            error: None,
        });
    }

    /// Update a party record — authorization verified.
    pub fn record_party_verified(&mut self, party_id: u16) {
        let now = unix_now_ms();
        self.record(
            SignStep::PartyVerifiedAuth,
            &format!("party_{party_id}"),
            None,
        );
        if let Some(p) = self.parties.iter_mut().find(|p| p.party_id == party_id) {
            p.verified_at_ms = Some(now);
        }
    }

    /// Update a party record — partial signature produced.
    pub fn record_party_signed(&mut self, party_id: u16) {
        let now = unix_now_ms();
        self.record(
            SignStep::PartialSignatureProduced,
            &format!("party_{party_id}"),
            None,
        );
        if let Some(p) = self.parties.iter_mut().find(|p| p.party_id == party_id) {
            p.signed_at_ms = Some(now);
            p.success = true;
        }
    }

    /// Mark the sign operation as completed.
    pub fn complete(&mut self, signature_hash: String) {
        let now = unix_now_ms();
        self.success = true;
        self.signature_hash = Some(signature_hash);
        self.completed_at_ms = Some(now);
        self.duration_ms = Some(now.saturating_sub(self.started_at_ms));
        self.record(SignStep::SignatureAssembled, "system", None);
    }

    /// Mark the sign operation as failed.
    pub fn fail(&mut self, error: String) {
        let now = unix_now_ms();
        self.success = false;
        self.error = Some(error.clone());
        self.completed_at_ms = Some(now);
        self.duration_ms = Some(now.saturating_sub(self.started_at_ms));
        self.record(SignStep::Failed, "system", Some(error));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> RequestContext {
        RequestContext {
            client_ip: "203.0.113.42".into(),
            user_agent: "MPC-SDK/1.0 (Linux x86_64)".into(),
            device_fingerprint: "fp_a1b2c3d4e5f6".into(),
            request_id: "req_7f3a9c2b".into(),
            requested_at: "2026-03-17T12:00:00Z".into(),
            geo_hint: Some("TH-Bangkok".into()),
            extra: None,
        }
    }

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 42;
        key[31] = 99;
        key
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let ctx = test_context();
        let key = test_key();

        let encrypted = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();

        // Ciphertext should not contain plaintext.
        assert!(!encrypted.ciphertext.contains("203.0.113.42"));

        let decrypted = encrypted.decrypt(&key).unwrap();
        assert_eq!(decrypted.client_ip, "203.0.113.42");
        assert_eq!(decrypted.device_fingerprint, "fp_a1b2c3d4e5f6");
        assert_eq!(decrypted.request_id, "req_7f3a9c2b");
        assert_eq!(decrypted.geo_hint, Some("TH-Bangkok".into()));
    }

    #[test]
    fn test_wrong_key_fails() {
        let ctx = test_context();
        let key = test_key();
        let wrong_key = [0xFFu8; 32];

        let encrypted = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();
        let result = encrypted.decrypt(&wrong_key);
        assert!(result.is_err());
        assert!(format!("{result:?}").contains("AEAD decryption failed"));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let ctx = test_context();
        let key = test_key();

        let mut encrypted = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();
        // Flip a byte in the ciphertext.
        let mut bytes = hex::decode(&encrypted.ciphertext).unwrap();
        bytes[0] ^= 0xFF;
        encrypted.ciphertext = hex::encode(bytes);

        let result = encrypted.decrypt(&key);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let ctx = test_context();
        let key = test_key();

        let enc1 = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();
        let enc2 = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();

        // Same plaintext, different nonces → different ciphertext.
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
        assert_ne!(enc1.nonce, enc2.nonce);

        // But same content hash.
        assert_eq!(enc1.context_hash, enc2.context_hash);
    }

    #[test]
    fn test_context_hash_matches() {
        let ctx = test_context();
        let key = test_key();

        let encrypted = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();

        // Hash should match serialized plaintext.
        let plaintext = serde_json::to_vec(&ctx).unwrap();
        let expected_hash = hex::encode(Sha256::digest(&plaintext));
        assert_eq!(encrypted.context_hash, expected_hash);
    }

    #[test]
    fn test_full_sign_timeline() {
        let ctx = test_context();
        let key = test_key();
        let encrypted = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();
        let now = unix_now_ms();

        let mut record = SignAuditRecord {
            session_id: "sess_123".into(),
            wallet_id: "wallet_abc".into(),
            scheme: "gg20-ecdsa".into(),
            threshold: "2-of-3".into(),
            message_hash: "deadbeef".into(),
            chain: Some("ethereum".into()),
            requester_id: "user_42".into(),
            auth_method: "session_token".into(),
            encrypted_context: encrypted,
            policy_hash: "cafebabe".into(),
            policy_passed: true,
            policy_detail: Some("allowlist: pass, velocity: 3/10".into()),
            approval_required: 2,
            approvers: vec![],
            parties: vec![],
            success: false,
            error: None,
            signature_hash: None,
            tx_hash: None,
            timeline: vec![],
            started_at_ms: now,
            completed_at_ms: None,
            duration_ms: None,
        };

        // Step 1: Request received
        record.record(SignStep::RequestReceived, "gateway", None);

        // Step 2: Auth validated
        record.record(
            SignStep::AuthValidated,
            "gateway",
            Some("session_token".into()),
        );

        // Step 3: Policy evaluated
        record.record(SignStep::PolicyEvaluated, "gateway", Some("pass".into()));

        // Step 4: Approvals
        record.record_approval(ApproverRecord {
            approver_id: "approver_A".into(),
            role: "approver".into(),
            approved_at_ms: unix_now_ms(),
            signature_hash: "aabb".into(),
        });
        record.record_approval(ApproverRecord {
            approver_id: "approver_B".into(),
            role: "admin".into(),
            approved_at_ms: unix_now_ms(),
            signature_hash: "ccdd".into(),
        });
        record.record(SignStep::QuorumReached, "gateway", Some("2/2".into()));

        // Step 5: MPC parties
        record.record_party_received(1);
        record.record_party_received(3);
        record.record_party_received(5);

        record.record_party_verified(1);
        record.record_party_verified(3);
        record.record_party_verified(5);

        record.record(
            SignStep::ProtocolRoundStarted,
            "party_1",
            Some("round=1".into()),
        );
        record.record(
            SignStep::ProtocolRoundCompleted,
            "party_1",
            Some("round=1".into()),
        );
        record.record(
            SignStep::ProtocolRoundStarted,
            "party_1",
            Some("round=2".into()),
        );
        record.record(
            SignStep::ProtocolRoundCompleted,
            "party_1",
            Some("round=2".into()),
        );

        record.record_party_signed(1);
        record.record_party_signed(3);
        record.record_party_signed(5);

        // Step 6: Complete
        record.complete("sig_hash_abcdef".into());

        // Verify the record
        assert!(record.success);
        assert_eq!(record.approvers.len(), 2);
        assert_eq!(record.parties.len(), 3);
        assert!(record.duration_ms.is_some());
        assert!(
            record.timeline.len() >= 15,
            "should have many timeline events"
        );

        // All parties should be successful
        for party in &record.parties {
            assert!(party.success);
            assert!(party.verified_at_ms.is_some());
            assert!(party.signed_at_ms.is_some());
        }

        // Serialize and verify no plaintext IP leaked
        let json = serde_json::to_string_pretty(&record).unwrap();
        assert!(json.contains("sess_123"));
        assert!(json.contains("request_received"));
        assert!(json.contains("party_verified_auth"));
        assert!(json.contains("signature_assembled"));
        assert!(!json.contains("203.0.113.42")); // IP encrypted

        // Verify timeline is ordered
        for window in record.timeline.windows(2) {
            assert!(
                window[1].timestamp_ms >= window[0].timestamp_ms,
                "timeline should be ordered"
            );
        }
    }

    #[test]
    fn test_failed_sign_timeline() {
        let ctx = test_context();
        let key = test_key();
        let encrypted = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();

        let mut record = SignAuditRecord {
            session_id: "sess_fail".into(),
            wallet_id: "wallet_xyz".into(),
            scheme: "frost-ed25519".into(),
            threshold: "3-of-5".into(),
            message_hash: "deadbeef".into(),
            chain: Some("solana".into()),
            requester_id: "user_99".into(),
            auth_method: "api_key".into(),
            encrypted_context: encrypted,
            policy_hash: "cafebabe".into(),
            policy_passed: true,
            policy_detail: None,
            approval_required: 0,
            approvers: vec![],
            parties: vec![],
            success: false,
            error: None,
            signature_hash: None,
            tx_hash: None,
            timeline: vec![],
            started_at_ms: unix_now_ms(),
            completed_at_ms: None,
            duration_ms: None,
        };

        record.record(SignStep::RequestReceived, "gateway", None);
        record.record_party_received(1);
        record.record_party_received(2);

        // Party 2 fails verification
        record.fail("party 2: authorization expired".into());

        assert!(!record.success);
        assert_eq!(
            record.error.as_deref(),
            Some("party 2: authorization expired")
        );
        assert!(record.duration_ms.is_some());
        assert!(record.timeline.iter().any(|e| e.step == SignStep::Failed));
    }
}
