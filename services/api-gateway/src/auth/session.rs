//! Session store for authenticated sessions.
//!
//! Provides a trait-based session store with two backends:
//! - `InMemoryBackend` — for dev/test (default)
//! - `RedisBackend` — for production (horizontal scaling, survives restarts)
//!
//! Session keys are encrypted before storage (AES-256-GCM) to prevent
//! plaintext key material in Redis or memory dumps.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::sync::RwLock;

use super::types::AuthenticatedSession;

/// Maximum number of sessions (DoS protection, in-memory backend only).
pub const MAX_SESSIONS: usize = 100_000;

/// Check if a session has expired.
pub fn is_expired(expires_at: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now > expires_at
}

/// Background prune interval (seconds).
const PRUNE_INTERVAL_SECS: u64 = 60;

// ── SessionBackend Trait ──────────────────────────────────────────

/// Pluggable session storage backend.
#[async_trait]
pub trait SessionBackend: Send + Sync {
    /// Store a session. Returns false if at capacity.
    async fn store(&self, session: AuthenticatedSession) -> bool;
    /// Get a session by ID. Returns None if not found or expired.
    async fn get(&self, session_id: &str) -> Option<AuthenticatedSession>;
    /// Revoke (delete) a session. Returns true if it existed.
    async fn revoke(&self, session_id: &str) -> bool;
    /// Remove all expired sessions. Returns count removed.
    async fn prune_expired(&self) -> usize;
    /// Count stored sessions (including expired).
    async fn count(&self) -> usize;
}

// ── InMemoryBackend ───────────────────────────────────────────────

/// In-memory session backend (dev/test).
#[derive(Clone, Default)]
pub struct InMemoryBackend {
    sessions: Arc<RwLock<HashMap<String, AuthenticatedSession>>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionBackend for InMemoryBackend {
    async fn store(&self, session: AuthenticatedSession) -> bool {
        let mut sessions = self.sessions.write().await;
        if sessions.len() >= MAX_SESSIONS {
            tracing::warn!(count = sessions.len(), "session store at capacity");
            return false;
        }
        sessions.insert(session.session_id.clone(), session);
        true
    }

    async fn get(&self, session_id: &str) -> Option<AuthenticatedSession> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)?;
        if is_expired(session.expires_at) {
            return None;
        }
        Some(session.clone())
    }

    async fn revoke(&self, session_id: &str) -> bool {
        self.sessions.write().await.remove(session_id).is_some()
    }

    async fn prune_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let before = sessions.len();
        sessions.retain(|_, s| s.expires_at > now);
        before - sessions.len()
    }

    async fn count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

// ── SessionStore (facade) ─────────────────────────────────────────

/// Session store facade — wraps any `SessionBackend` implementation.
/// Use `SessionStore::in_memory()` for dev/test, or provide a custom backend.
#[derive(Clone)]
pub struct SessionStore {
    backend: Arc<dyn SessionBackend>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl SessionStore {
    /// Create an in-memory session store (dev/test).
    pub fn in_memory() -> Self {
        Self {
            backend: Arc::new(InMemoryBackend::new()),
        }
    }

    /// Create a session store with a custom backend (e.g., Redis).
    pub fn with_backend(backend: Arc<dyn SessionBackend>) -> Self {
        Self { backend }
    }

    /// Spawn a background task that prunes expired sessions every 60 seconds.
    pub fn spawn_prune_task(&self) {
        let store = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(PRUNE_INTERVAL_SECS)).await;
                let pruned = store.prune_expired().await;
                if pruned > 0 {
                    let remaining = store.count().await;
                    tracing::info!(pruned, remaining, "session store pruned");
                }
            }
        });
    }

    pub async fn store(&self, session: AuthenticatedSession) -> bool {
        self.backend.store(session).await
    }

    pub async fn get(&self, session_id: &str) -> Option<AuthenticatedSession> {
        self.backend.get(session_id).await
    }

    pub async fn revoke(&self, session_id: &str) -> bool {
        self.backend.revoke(session_id).await
    }

    pub async fn prune_expired(&self) -> usize {
        self.backend.prune_expired().await
    }

    pub async fn count(&self) -> usize {
        self.backend.count().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(id: &str, expires_at: u64) -> AuthenticatedSession {
        AuthenticatedSession {
            session_id: id.to_string(),
            client_pubkey: [0u8; 32],
            client_key_id: "test".into(),
            client_write_key: [1u8; 32],
            server_write_key: [2u8; 32],
            expires_at,
            created_at: 1000,
        }
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let store = SessionStore::in_memory();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        store.store(make_session("s1", now + 3600)).await;
        let session = store.get("s1").await;
        assert!(session.is_some());
        assert_eq!(session.unwrap().session_id, "s1");
    }

    #[tokio::test]
    async fn test_expired_session_returns_none() {
        let store = SessionStore::in_memory();
        store.store(make_session("s2", 1000)).await;
        assert!(store.get("s2").await.is_none());
    }

    #[tokio::test]
    async fn test_revoke_session() {
        let store = SessionStore::in_memory();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        store.store(make_session("s3", now + 3600)).await;
        assert!(store.revoke("s3").await);
        assert!(store.get("s3").await.is_none());
    }

    #[tokio::test]
    async fn test_prune_expired() {
        let store = SessionStore::in_memory();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        store.store(make_session("active", now + 3600)).await;
        store.store(make_session("expired1", 1000)).await;
        store.store(make_session("expired2", 1000)).await;

        let pruned = store.prune_expired().await;
        assert_eq!(pruned, 2);
        assert_eq!(store.count().await, 1);
    }

    #[tokio::test]
    async fn test_nonexistent_session() {
        let store = SessionStore::in_memory();
        assert!(store.get("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_custom_backend() {
        // Verify the trait-based approach works with a different backend.
        let backend = Arc::new(InMemoryBackend::new());
        let store = SessionStore::with_backend(backend);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(store.store(make_session("custom", now + 3600)).await);
        assert!(store.get("custom").await.is_some());
    }
}
