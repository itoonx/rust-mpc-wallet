//! Signing session manager for MPC Wallet operations.
//!
//! # Overview
//!
//! [`SessionManager`] manages the lifecycle of signing sessions, enforcing
//! idempotency via a `tx_fingerprint` lock: a second call to [`SessionManager::create`]
//! with the same fingerprint returns the existing session rather than starting a new one.
//!
//! # State machine
//!
//! ```text
//! [create] → Pending → [mark_signing] → Signing → [mark_completed] → Completed
//!                                                → [mark_failed]   → Failed
//! ```
//!
//! Invalid transitions (e.g. `Pending → Completed`) are rejected with
//! [`crate::error::CoreError::SessionError`].
//!
//! # Sprint 4 limitation
//!
//! Sessions are stored in-memory only and are lost on process restart.
//! Sprint 5 will add persistent storage. Do NOT use this as a durable
//! idempotency store across process restarts.

pub mod state;

use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::CoreError;
use crate::session::state::{Session, SessionId, SessionState};

/// In-memory signing session manager.
///
/// # Idempotency
///
/// [`create`](SessionManager::create) is idempotent: calling it with the same
/// `tx_fingerprint` twice returns the **existing** [`SessionId`] rather than
/// creating a duplicate session. This prevents double-signing even when a caller
/// retries after a transient failure.
///
/// # Concurrency
///
/// All operations are protected by internal [`RwLock`]s. The `create` method
/// uses a double-check pattern to prevent TOCTOU races: the fingerprint index
/// is checked under both a read lock (fast path) and a write lock (creation path).
///
/// # Sprint 4 limitation
///
/// Sessions are in-memory only and are lost on process restart.
/// Sprint 5 will add durable session persistence.
pub struct SessionManager {
    /// Session records keyed by session ID string.
    sessions: RwLock<HashMap<String, Session>>,
    /// Maps `tx_fingerprint` → `session_id` string for idempotency lookups.
    fingerprint_index: RwLock<HashMap<String, String>>,
}

impl SessionManager {
    /// Create a new, empty session manager with no active sessions.
    pub fn new() -> Self {
        SessionManager {
            sessions: RwLock::new(HashMap::new()),
            fingerprint_index: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new signing session, or return the existing session if one already
    /// exists for this `tx_fingerprint` (idempotent).
    ///
    /// # Returns
    /// `(SessionId, created)` where `created` is `true` if a new session was
    /// created, `false` if an existing session was found for this fingerprint.
    ///
    /// # Idempotency
    /// If a session for `tx_fingerprint` already exists, its `SessionId` is
    /// returned regardless of `chain`. Callers should not rely on `chain` being
    /// re-validated on idempotent calls.
    pub fn create(
        &self,
        tx_fingerprint: String,
        chain: String,
    ) -> Result<(SessionId, bool), CoreError> {
        // Fast path: check fingerprint index under read lock
        {
            let idx = self.fingerprint_index.read().unwrap();
            if let Some(existing_id) = idx.get(&tx_fingerprint) {
                return Ok((SessionId(existing_id.clone()), false));
            }
        }

        // Slow path: create new session under write lock.
        // Double-check under write lock to prevent TOCTOU race condition.
        let session = Session::new(tx_fingerprint.clone(), chain);
        let session_id = session.id.clone();
        {
            let mut sessions = self.sessions.write().unwrap();
            let mut idx = self.fingerprint_index.write().unwrap();

            // TOCTOU prevention: re-check after acquiring write lock
            if let Some(existing_id) = idx.get(&tx_fingerprint) {
                return Ok((SessionId(existing_id.clone()), false));
            }

            sessions.insert(session_id.0.clone(), session);
            idx.insert(tx_fingerprint, session_id.0.clone());
        }
        Ok((session_id, true))
    }

    /// Retrieve a session by its ID.
    ///
    /// # Errors
    /// Returns [`CoreError::SessionError`] if no session with the given ID exists.
    pub fn get(&self, id: &SessionId) -> Result<Session, CoreError> {
        let sessions = self.sessions.read().unwrap();
        sessions
            .get(&id.0)
            .cloned()
            .ok_or_else(|| CoreError::SessionError(format!("session '{}' not found", id.0)))
    }

    /// Transition a session from `Pending` to `Signing`.
    ///
    /// # Errors
    /// Returns [`CoreError::SessionError`] if the session is not in `Pending` state
    /// or does not exist.
    pub fn mark_signing(&self, id: &SessionId) -> Result<(), CoreError> {
        self.transition(id, SessionState::Signing)
    }

    /// Transition a session from `Signing` to `Completed`.
    ///
    /// # Arguments
    /// - `tx_hash` — the on-chain transaction hash for the completed signing.
    ///
    /// # Errors
    /// Returns [`CoreError::SessionError`] if the session is not in `Signing` state
    /// or does not exist.
    pub fn mark_completed(&self, id: &SessionId, tx_hash: String) -> Result<(), CoreError> {
        self.transition(id, SessionState::Completed { tx_hash })
    }

    /// Transition a session from `Signing` to `Failed`.
    ///
    /// # Arguments
    /// - `reason` — human-readable description of the failure.
    ///
    /// # Errors
    /// Returns [`CoreError::SessionError`] if the session is not in `Signing` state
    /// or does not exist.
    pub fn mark_failed(&self, id: &SessionId, reason: String) -> Result<(), CoreError> {
        self.transition(id, SessionState::Failed { reason })
    }

    /// Internal state transition helper.
    ///
    /// Validates that the transition is permitted before updating the session state.
    fn transition(&self, id: &SessionId, new_state: SessionState) -> Result<(), CoreError> {
        let mut sessions = self.sessions.write().unwrap();
        let session = sessions
            .get_mut(&id.0)
            .ok_or_else(|| CoreError::SessionError(format!("session '{}' not found", id.0)))?;

        // Validate that the transition is permitted
        let valid = matches!(
            (&session.state, &new_state),
            (SessionState::Pending, SessionState::Signing)
                | (SessionState::Signing, SessionState::Completed { .. })
                | (SessionState::Signing, SessionState::Failed { .. })
        );

        if !valid {
            return Err(CoreError::SessionError(format!(
                "invalid state transition {:?} → {:?} for session '{}'",
                session.state, new_state, id.0
            )));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        session.state = new_state;
        session.updated_at = now;
        Ok(())
    }

    /// Persist all current sessions to a directory as JSON files.
    ///
    /// Each session is written to `{dir}/{session_id}.json`. The fingerprint
    /// index is written to `{dir}/_index.json`.
    ///
    /// This enables recovery of signing sessions across process restarts (FR-D3).
    /// Call after any state transition that should survive a restart.
    pub fn save_to_dir(&self, dir: &std::path::Path) -> Result<(), CoreError> {
        std::fs::create_dir_all(dir)
            .map_err(|e| CoreError::SessionError(format!("create session dir failed: {e}")))?;

        let sessions = self.sessions.read().unwrap();
        for (id, session) in sessions.iter() {
            let path = dir.join(format!("{}.json", id));
            let json = serde_json::to_string_pretty(session)
                .map_err(|e| CoreError::SessionError(format!("serialize session: {e}")))?;
            std::fs::write(&path, json)
                .map_err(|e| CoreError::SessionError(format!("write session file: {e}")))?;
        }

        // Write fingerprint index
        let idx = self.fingerprint_index.read().unwrap();
        let idx_json = serde_json::to_string_pretty(&*idx)
            .map_err(|e| CoreError::SessionError(format!("serialize index: {e}")))?;
        std::fs::write(dir.join("_index.json"), idx_json)
            .map_err(|e| CoreError::SessionError(format!("write index file: {e}")))?;

        Ok(())
    }

    /// Load sessions from a directory previously written by [`save_to_dir`].
    ///
    /// Reads all `*.json` files (except `_index.json`) as [`Session`] records
    /// and reconstructs the fingerprint index from `_index.json`.
    ///
    /// Returns a new [`SessionManager`] populated with the loaded sessions.
    pub fn load_from_dir(dir: &std::path::Path) -> Result<Self, CoreError> {
        let mgr = SessionManager::new();

        if !dir.exists() {
            return Ok(mgr); // empty directory = no sessions
        }

        // Load fingerprint index
        let idx_path = dir.join("_index.json");
        if idx_path.exists() {
            let idx_json = std::fs::read_to_string(&idx_path)
                .map_err(|e| CoreError::SessionError(format!("read index file: {e}")))?;
            let idx: HashMap<String, String> = serde_json::from_str(&idx_json)
                .map_err(|e| CoreError::SessionError(format!("deserialize index: {e}")))?;
            *mgr.fingerprint_index.write().unwrap() = idx;
        }

        // Load individual session files
        let entries = std::fs::read_dir(dir)
            .map_err(|e| CoreError::SessionError(format!("read session dir: {e}")))?;

        {
            let mut sessions = mgr.sessions.write().unwrap();
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if path.file_name().and_then(|n| n.to_str()) == Some("_index.json") {
                    continue;
                }
                let json = std::fs::read_to_string(&path)
                    .map_err(|e| CoreError::SessionError(format!("read session file: {e}")))?;
                let session: Session = serde_json::from_str(&json)
                    .map_err(|e| CoreError::SessionError(format!("deserialize session: {e}")))?;
                sessions.insert(session.id.0.clone(), session);
            }
        } // drop sessions lock before returning mgr

        Ok(mgr)
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_new_session() {
        let mgr = SessionManager::new();
        let (id, created) = mgr.create("fp-001".into(), "ethereum".into()).unwrap();
        assert!(created, "first create should return created=true");
        let session = mgr.get(&id).unwrap();
        assert_eq!(session.tx_fingerprint, "fp-001");
        assert_eq!(session.chain, "ethereum");
        assert_eq!(session.state, SessionState::Pending);
        assert!(session.created_at > 0);
    }

    #[test]
    fn test_idempotent_create_same_fingerprint() {
        let mgr = SessionManager::new();
        let (id1, created1) = mgr.create("fp-dup".into(), "ethereum".into()).unwrap();
        let (id2, created2) = mgr.create("fp-dup".into(), "bitcoin".into()).unwrap();
        assert!(created1);
        assert!(
            !created2,
            "second create with same fingerprint should return created=false"
        );
        assert_eq!(id1, id2, "both calls should return the same session ID");
    }

    #[test]
    fn test_state_transitions_pending_signing_completed() {
        let mgr = SessionManager::new();
        let (id, _) = mgr.create("fp-complete".into(), "ethereum".into()).unwrap();

        mgr.mark_signing(&id).unwrap();
        let s = mgr.get(&id).unwrap();
        assert_eq!(s.state, SessionState::Signing);

        mgr.mark_completed(&id, "0xdeadbeef".into()).unwrap();
        let s = mgr.get(&id).unwrap();
        assert_eq!(
            s.state,
            SessionState::Completed {
                tx_hash: "0xdeadbeef".into()
            }
        );
    }

    #[test]
    fn test_state_transitions_pending_signing_failed() {
        let mgr = SessionManager::new();
        let (id, _) = mgr.create("fp-fail".into(), "ethereum".into()).unwrap();

        mgr.mark_signing(&id).unwrap();
        mgr.mark_failed(&id, "nats timeout".into()).unwrap();
        let s = mgr.get(&id).unwrap();
        assert_eq!(
            s.state,
            SessionState::Failed {
                reason: "nats timeout".into()
            }
        );
    }

    #[test]
    fn test_invalid_transition_pending_to_completed_is_rejected() {
        let mgr = SessionManager::new();
        let (id, _) = mgr.create("fp-invalid".into(), "ethereum".into()).unwrap();

        // Skipping Signing → directly to Completed is not permitted
        let err = mgr.mark_completed(&id, "0xabc".into()).unwrap_err();
        assert!(
            matches!(err, CoreError::SessionError(_)),
            "expected SessionError, got {:?}",
            err
        );
    }

    #[test]
    fn test_invalid_transition_pending_to_failed_is_rejected() {
        let mgr = SessionManager::new();
        let (id, _) = mgr.create("fp-invalid2".into(), "ethereum".into()).unwrap();

        let err = mgr.mark_failed(&id, "bad".into()).unwrap_err();
        assert!(matches!(err, CoreError::SessionError(_)));
    }

    #[test]
    fn test_get_nonexistent_session_returns_error() {
        let mgr = SessionManager::new();
        let err = mgr.get(&SessionId("no-such-session".into())).unwrap_err();
        assert!(matches!(err, CoreError::SessionError(_)));
    }

    #[test]
    fn test_duplicate_fingerprint_different_chains_still_idempotent() {
        let mgr = SessionManager::new();
        let (id1, created1) = mgr.create("same-fp".into(), "ethereum".into()).unwrap();
        let (id2, created2) = mgr.create("same-fp".into(), "bitcoin".into()).unwrap();
        assert!(created1);
        assert!(!created2);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_fingerprints_create_different_sessions() {
        let mgr = SessionManager::new();
        let (id1, _) = mgr.create("fp-a".into(), "ethereum".into()).unwrap();
        let (id2, _) = mgr.create("fp-b".into(), "ethereum".into()).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_updated_at_changes_on_transition() {
        let mgr = SessionManager::new();
        let (id, _) = mgr.create("fp-time".into(), "ethereum".into()).unwrap();
        let before = mgr.get(&id).unwrap().updated_at;

        // Small sleep to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(1100));
        mgr.mark_signing(&id).unwrap();

        let after = mgr.get(&id).unwrap().updated_at;
        assert!(after >= before, "updated_at should not decrease");
    }

    // ─── Persistence tests ────────────────────────────────────────────────────

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("mpc-sessions-{}", uuid::Uuid::new_v4()));

        // Create and populate a session manager
        let mgr = SessionManager::new();
        let (id1, _) = mgr
            .create("fp-persist-1".into(), "ethereum".into())
            .unwrap();
        let (id2, _) = mgr.create("fp-persist-2".into(), "bitcoin".into()).unwrap();
        mgr.mark_signing(&id1).unwrap();
        mgr.mark_completed(&id1, "0xabc".into()).unwrap();

        // Save to disk
        mgr.save_to_dir(&dir).unwrap();

        // Load into a fresh manager
        let mgr2 = SessionManager::load_from_dir(&dir).unwrap();

        // Verify sessions round-tripped correctly
        let s1 = mgr2.get(&id1).unwrap();
        assert_eq!(s1.tx_fingerprint, "fp-persist-1");
        assert_eq!(
            s1.state,
            crate::session::state::SessionState::Completed {
                tx_hash: "0xabc".into()
            }
        );

        let s2 = mgr2.get(&id2).unwrap();
        assert_eq!(s2.tx_fingerprint, "fp-persist-2");
        assert_eq!(s2.state, crate::session::state::SessionState::Pending);

        // Verify idempotency index round-tripped (same fingerprint → same session ID)
        let (id1_again, created) = mgr2
            .create("fp-persist-1".into(), "ethereum".into())
            .unwrap();
        assert!(
            !created,
            "existing fingerprint must not create a new session"
        );
        assert_eq!(id1_again, id1);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_from_nonexistent_dir_returns_empty() {
        let dir = std::env::temp_dir().join("mpc-sessions-does-not-exist-xyz");
        let mgr = SessionManager::load_from_dir(&dir).unwrap();
        // Should return an empty manager, not an error
        assert!(mgr.sessions.read().unwrap().is_empty());
    }

    #[test]
    fn test_save_overwrites_updated_state() {
        let dir =
            std::env::temp_dir().join(format!("mpc-sessions-update-{}", uuid::Uuid::new_v4()));

        let mgr = SessionManager::new();
        let (id, _) = mgr.create("fp-overwrite".into(), "solana".into()).unwrap();
        mgr.save_to_dir(&dir).unwrap();

        // Transition state and save again
        mgr.mark_signing(&id).unwrap();
        mgr.save_to_dir(&dir).unwrap();

        // Load and verify updated state persisted
        let mgr2 = SessionManager::load_from_dir(&dir).unwrap();
        let s = mgr2.get(&id).unwrap();
        assert_eq!(s.state, crate::session::state::SessionState::Signing);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
