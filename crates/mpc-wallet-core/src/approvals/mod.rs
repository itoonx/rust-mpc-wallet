//! Approval workflow for MPC Wallet signing sessions (FR-C).
//!
//! # Overview
//!
//! Before a signing session can proceed from `Pending` to `Signing`, it must
//! collect a configurable M-of-N quorum of cryptographic approvals. Each approver
//! signs an [`ApprovalPayload`] containing the session ID, tx fingerprint, and
//! timestamp, committing to the exact transaction being signed.
//!
//! # Separation of Duties (SoD)
//!
//! The [`Role`] enum enforces maker / checker / approver separation:
//! - **Maker** — initiates the signing request
//! - **Checker** — reviews and endorses the transaction
//! - **Approver** — final approval authority
//!
//! The same `user_id` **cannot** fill more than one role in the same session.
//! Violation returns [`crate::error::CoreError::ApprovalRequired`] with a clear reason.
//!
//! # Sprint 5 scope
//!
//! - Ed25519 approval signatures (approver signs the payload hash)
//! - M-of-N quorum enforcement (configurable per session)
//! - SoD validation (same user_id blocked from two roles)
//! - In-memory store (Sprint 6 will add persistence)
//!
//! **Not in Sprint 5:** hold periods (FR-C.3), break-glass (FR-C.4), RBAC integration.

use std::collections::HashMap;
use std::sync::RwLock;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CoreError;

// ─── Role ────────────────────────────────────────────────────────────────────

/// The role a participant plays in a signing session's approval workflow.
///
/// The same `user_id` cannot fill more than one role in the same session (SoD).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Initiates the signing request (creates the session).
    Maker,
    /// Reviews and endorses the transaction before approval.
    Checker,
    /// Provides cryptographic approval; counted toward the quorum.
    Approver,
}

// ─── ApprovalPayload ─────────────────────────────────────────────────────────

/// The canonical payload that an approver signs to express approval.
///
/// The payload commits to the session ID, the exact transaction fingerprint,
/// and the approver's identity. Signing this payload with the approver's
/// Ed25519 key produces an [`Approval`] that is stored in the [`ApprovalStore`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPayload {
    /// The signing session ID this approval is for.
    pub session_id: String,
    /// SHA-256 hash of the canonical transaction bytes (idempotency key).
    pub tx_fingerprint: String,
    /// The approver's user identifier.
    pub approver_id: String,
    /// Unix timestamp (seconds) when the approval was created.
    pub timestamp: u64,
}

impl ApprovalPayload {
    /// Compute the canonical hash of this payload for signing.
    ///
    /// Uses SHA-256 over the JSON-serialized payload. The signature
    /// is over this hash, not the raw JSON bytes, for determinism.
    pub fn hash(&self) -> Vec<u8> {
        let json = serde_json::to_vec(self).unwrap_or_default();
        Sha256::digest(&json).to_vec()
    }
}

// ─── Approval ────────────────────────────────────────────────────────────────

/// A single approver's signed approval for a signing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// The payload that was signed.
    pub payload: ApprovalPayload,
    /// Ed25519 signature over `payload.hash()`.
    pub signature: Vec<u8>,
    /// Ed25519 public key of the approver (32 bytes).
    pub approver_pubkey: Vec<u8>,
}

// ─── SessionApprovalState ────────────────────────────────────────────────────

/// Per-session approval tracking: roles assigned, approvals collected, quorum config.
#[derive(Debug)]
struct SessionApprovalState {
    /// Required number of Approver-role signatures before signing can proceed.
    required_approvals: usize,
    /// Maps user_id → Role for SoD enforcement.
    role_assignments: HashMap<String, Role>,
    /// Collected approvals (keyed by approver_id to deduplicate).
    approvals: HashMap<String, Approval>,
}

impl SessionApprovalState {
    fn new(required_approvals: usize) -> Self {
        SessionApprovalState {
            required_approvals,
            role_assignments: HashMap::new(),
            approvals: HashMap::new(),
        }
    }
}

// ─── ApprovalStore ───────────────────────────────────────────────────────────

/// In-memory approval workflow manager.
///
/// # Usage
///
/// 1. Call [`assign_role`](ApprovalStore::assign_role) to register a user's role
///    (Maker, Checker, Approver). SoD is enforced — same user cannot hold two roles.
/// 2. Approvers call [`submit_approval`](ApprovalStore::submit_approval) with a
///    signed [`ApprovalPayload`]. Signature is verified against their Ed25519 key.
/// 3. Call [`is_approved`](ApprovalStore::is_approved) to check if the quorum is met.
///
/// # Sprint 5 limitation
/// All state is in-memory. Sprint 6 will add durable persistence.
pub struct ApprovalStore {
    /// Sessions keyed by session_id.
    sessions: RwLock<HashMap<String, SessionApprovalState>>,
}

impl ApprovalStore {
    /// Create a new, empty approval store.
    pub fn new() -> Self {
        ApprovalStore {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Register a session with the required approval quorum.
    ///
    /// Must be called before any role assignments or approvals for a session.
    /// Calling again for an existing session is idempotent (no-op).
    pub fn register_session(
        &self,
        session_id: &str,
        required_approvals: usize,
    ) -> Result<(), CoreError> {
        let mut sessions = self.sessions.write().unwrap();
        sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionApprovalState::new(required_approvals));
        Ok(())
    }

    /// Assign a role to a user for a session.
    ///
    /// # SoD enforcement
    /// Returns [`CoreError::ApprovalRequired`] if `user_id` already holds a
    /// **different** role in this session (same role re-assignment is idempotent).
    pub fn assign_role(
        &self,
        session_id: &str,
        user_id: &str,
        role: Role,
    ) -> Result<(), CoreError> {
        let mut sessions = self.sessions.write().unwrap();
        let state = sessions.get_mut(session_id).ok_or_else(|| {
            CoreError::ApprovalRequired(format!("session '{}' not registered", session_id))
        })?;

        if let Some(existing_role) = state.role_assignments.get(user_id) {
            if existing_role != &role {
                // SoD violation: same user trying to hold two different roles
                return Err(CoreError::ApprovalRequired(format!(
                    "SoD violation: user '{}' already has role {:?} in session '{}'; \
                     cannot also be {:?}",
                    user_id, existing_role, session_id, role
                )));
            }
            // Same role re-assignment: idempotent
            return Ok(());
        }

        // Check cross-role SoD: does this user hold ANY other role in this session?
        // (checked above for their own user_id; this is already handled)
        state.role_assignments.insert(user_id.to_string(), role);
        Ok(())
    }

    /// Submit a signed approval for a session.
    ///
    /// Verifies the Ed25519 signature over `approval.payload.hash()`.
    /// Deduplicates by `approver_id` — re-submitting an approval from the same
    /// user replaces the previous one.
    ///
    /// # SoD check
    /// The approver must have been assigned the [`Role::Approver`] role.
    /// A user assigned Maker or Checker cannot submit an approval.
    pub fn submit_approval(&self, session_id: &str, approval: Approval) -> Result<(), CoreError> {
        // Verify the Ed25519 signature
        let pubkey_bytes: [u8; 32] = approval
            .approver_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::ApprovalRequired("invalid approver pubkey length".into()))?;

        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| CoreError::ApprovalRequired(format!("invalid approver pubkey: {e}")))?;

        let sig_bytes: [u8; 64] = approval
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::ApprovalRequired("invalid signature length".into()))?;

        let signature = Signature::from_bytes(&sig_bytes);
        let payload_hash = approval.payload.hash();

        verifying_key
            .verify(&payload_hash, &signature)
            .map_err(|_| {
                CoreError::ApprovalRequired(format!(
                    "approval signature verification failed for user '{}'",
                    approval.payload.approver_id
                ))
            })?;

        let mut sessions = self.sessions.write().unwrap();
        let state = sessions.get_mut(session_id).ok_or_else(|| {
            CoreError::ApprovalRequired(format!("session '{}' not registered", session_id))
        })?;

        // SoD: approver must have Approver role
        match state.role_assignments.get(&approval.payload.approver_id) {
            Some(Role::Approver) => {}
            Some(other_role) => {
                return Err(CoreError::ApprovalRequired(format!(
                    "SoD violation: user '{}' has role {:?} — cannot submit an Approver approval",
                    approval.payload.approver_id, other_role
                )));
            }
            None => {
                return Err(CoreError::ApprovalRequired(format!(
                    "user '{}' has not been assigned the Approver role in session '{}'",
                    approval.payload.approver_id, session_id
                )));
            }
        }

        state
            .approvals
            .insert(approval.payload.approver_id.clone(), approval);
        Ok(())
    }

    /// Check whether the required approval quorum has been reached for a session.
    ///
    /// Returns `Ok(())` if quorum is met, `Err(CoreError::ApprovalRequired(...))` otherwise.
    pub fn is_approved(&self, session_id: &str) -> Result<(), CoreError> {
        let sessions = self.sessions.read().unwrap();
        let state = sessions.get(session_id).ok_or_else(|| {
            CoreError::ApprovalRequired(format!("session '{}' not registered", session_id))
        })?;

        let count = state.approvals.len();
        if count >= state.required_approvals {
            Ok(())
        } else {
            Err(CoreError::ApprovalRequired(format!(
                "quorum not met for session '{}': {}/{} approvals received",
                session_id, count, state.required_approvals
            )))
        }
    }

    /// Get all approvals collected for a session (for audit evidence).
    pub fn get_approvals(&self, session_id: &str) -> Result<Vec<Approval>, CoreError> {
        let sessions = self.sessions.read().unwrap();
        let state = sessions.get(session_id).ok_or_else(|| {
            CoreError::ApprovalRequired(format!("session '{}' not registered", session_id))
        })?;
        Ok(state.approvals.values().cloned().collect())
    }
}

impl Default for ApprovalStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helper: create a signed approval ────────────────────────────────────────

/// Create a signed [`Approval`] using an Ed25519 signing key.
///
/// This is a convenience function for tests and for the approval client.
/// In production, the approver's signing key lives on their device.
pub fn sign_approval(
    session_id: &str,
    tx_fingerprint: &str,
    approver_id: &str,
    signing_key: &SigningKey,
) -> Approval {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let payload = ApprovalPayload {
        session_id: session_id.to_string(),
        tx_fingerprint: tx_fingerprint.to_string(),
        approver_id: approver_id.to_string(),
        timestamp: now,
    };

    let hash = payload.hash();
    let signature = signing_key.sign(&hash);

    Approval {
        payload,
        signature: signature.to_bytes().to_vec(),
        approver_pubkey: signing_key.verifying_key().to_bytes().to_vec(),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn new_key() -> SigningKey {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn test_quorum_not_met_initially() {
        let store = ApprovalStore::new();
        store.register_session("s1", 2).unwrap();
        let err = store.is_approved("s1").unwrap_err();
        assert!(matches!(err, CoreError::ApprovalRequired(_)));
    }

    #[test]
    fn test_single_approver_meets_quorum_of_1() {
        let store = ApprovalStore::new();
        store.register_session("s2", 1).unwrap();
        let key = new_key();
        store.assign_role("s2", "alice", Role::Approver).unwrap();
        let approval = sign_approval("s2", "fp-abc", "alice", &key);
        store.submit_approval("s2", approval).unwrap();
        assert!(store.is_approved("s2").is_ok());
    }

    #[test]
    fn test_two_of_three_quorum() {
        let store = ApprovalStore::new();
        store.register_session("s3", 2).unwrap();
        let k1 = new_key();
        let k2 = new_key();
        store.assign_role("s3", "alice", Role::Approver).unwrap();
        store.assign_role("s3", "bob", Role::Approver).unwrap();
        store.assign_role("s3", "carol", Role::Approver).unwrap();

        // Only one approval — quorum not met
        store
            .submit_approval("s3", sign_approval("s3", "fp-xyz", "alice", &k1))
            .unwrap();
        assert!(store.is_approved("s3").is_err());

        // Second approval — quorum met
        store
            .submit_approval("s3", sign_approval("s3", "fp-xyz", "bob", &k2))
            .unwrap();
        assert!(store.is_approved("s3").is_ok());
    }

    #[test]
    fn test_sod_violation_maker_cannot_approve() {
        let store = ApprovalStore::new();
        store.register_session("s4", 1).unwrap();
        let key = new_key();
        store.assign_role("s4", "alice", Role::Maker).unwrap();

        // alice is Maker — cannot submit Approver approval
        let approval = sign_approval("s4", "fp", "alice", &key);
        let err = store.submit_approval("s4", approval).unwrap_err();
        assert!(matches!(err, CoreError::ApprovalRequired(_)));
        let msg = format!("{}", err);
        assert!(msg.contains("SoD") || msg.contains("role"));
    }

    #[test]
    fn test_sod_violation_same_user_two_roles() {
        let store = ApprovalStore::new();
        store.register_session("s5", 1).unwrap();
        store.assign_role("s5", "alice", Role::Maker).unwrap();
        let err = store
            .assign_role("s5", "alice", Role::Approver)
            .unwrap_err();
        assert!(matches!(err, CoreError::ApprovalRequired(_)));
        let msg = format!("{}", err);
        assert!(msg.contains("SoD"));
    }

    #[test]
    fn test_same_role_reassignment_is_idempotent() {
        let store = ApprovalStore::new();
        store.register_session("s6", 1).unwrap();
        store.assign_role("s6", "alice", Role::Approver).unwrap();
        // Same role again — must succeed
        assert!(store.assign_role("s6", "alice", Role::Approver).is_ok());
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let store = ApprovalStore::new();
        store.register_session("s7", 1).unwrap();
        let key = new_key();
        let wrong_key = new_key();
        store.assign_role("s7", "alice", Role::Approver).unwrap();

        let mut approval = sign_approval("s7", "fp", "alice", &key);
        // Replace pubkey with wrong key's pubkey — signature won't verify
        approval.approver_pubkey = wrong_key.verifying_key().to_bytes().to_vec();
        let err = store.submit_approval("s7", approval).unwrap_err();
        assert!(matches!(err, CoreError::ApprovalRequired(_)));
    }

    #[test]
    fn test_unregistered_session_returns_error() {
        let store = ApprovalStore::new();
        let err = store.is_approved("ghost-session").unwrap_err();
        assert!(matches!(err, CoreError::ApprovalRequired(_)));
    }

    #[test]
    fn test_get_approvals_returns_all_submitted() {
        let store = ApprovalStore::new();
        store.register_session("s8", 2).unwrap();
        let k1 = new_key();
        let k2 = new_key();
        store.assign_role("s8", "alice", Role::Approver).unwrap();
        store.assign_role("s8", "bob", Role::Approver).unwrap();
        store
            .submit_approval("s8", sign_approval("s8", "fp", "alice", &k1))
            .unwrap();
        store
            .submit_approval("s8", sign_approval("s8", "fp", "bob", &k2))
            .unwrap();
        let approvals = store.get_approvals("s8").unwrap();
        assert_eq!(approvals.len(), 2);
    }
}
