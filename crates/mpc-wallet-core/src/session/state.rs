//! State machine types for signing sessions.

use serde::{Deserialize, Serialize};

/// Unique identifier for a signing session (UUID v4 string).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The lifecycle states of a signing session.
///
/// Valid transitions:
/// - `Pending → Signing` (signing starts)
/// - `Signing → Completed` (signing finished successfully)
/// - `Signing → Failed` (signing encountered an error)
///
/// All other transitions are rejected with [`crate::error::CoreError::SessionError`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session created, awaiting policy check and approval.
    Pending,
    /// MPC signing protocol is in progress. No new session with the same
    /// `tx_fingerprint` can be created while another is `Signing`.
    Signing,
    /// Signing completed successfully. Contains the on-chain transaction hash.
    Completed {
        /// On-chain transaction hash (chain-specific format).
        tx_hash: String,
    },
    /// Signing failed. Contains a human-readable failure reason.
    Failed {
        /// Human-readable description of the failure.
        reason: String,
    },
}

/// A signing session record.
///
/// Each session tracks the lifecycle of a single signing operation, identified
/// by its `tx_fingerprint` (a hash of the canonical transaction bytes). The
/// `tx_fingerprint` serves as an idempotency key: only one session per fingerprint
/// is allowed, preventing double-signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier (UUID v4).
    pub id: SessionId,
    /// SHA-256 hash of the canonical transaction bytes used as an idempotency key.
    /// Only one active session per `tx_fingerprint` is permitted.
    ///
    /// The `SessionManager` treats this as an opaque string — the caller is
    /// responsible for computing the correct hash before creating a session.
    pub tx_fingerprint: String,
    /// Target chain identifier (e.g. `"ethereum"`, `"bitcoin"`).
    pub chain: String,
    /// Current state in the session lifecycle.
    pub state: SessionState,
    /// Unix timestamp (seconds since epoch) when the session was created.
    pub created_at: u64,
    /// Unix timestamp (seconds since epoch) of the most recent state transition.
    pub updated_at: u64,
}

impl Session {
    /// Create a new session in [`SessionState::Pending`] state.
    ///
    /// Assigns a fresh UUID v4 as the session ID and records the current wall-clock
    /// time as both `created_at` and `updated_at`.
    pub fn new(tx_fingerprint: String, chain: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Session {
            id: SessionId(uuid::Uuid::new_v4().to_string()),
            tx_fingerprint,
            chain,
            state: SessionState::Pending,
            created_at: now,
            updated_at: now,
        }
    }
}
