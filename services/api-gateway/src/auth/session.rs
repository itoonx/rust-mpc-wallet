//! Session store for authenticated sessions.
//!
//! Provides an in-memory session store with automatic expiration,
//! size cap, and background pruning.
//! Production deployments should back this with Redis or a distributed store.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use super::types::AuthenticatedSession;

/// Maximum number of sessions stored before rejecting new ones.
pub const MAX_SESSIONS: usize = 100_000;

/// Background prune interval (seconds).
const PRUNE_INTERVAL_SECS: u64 = 60;

/// In-memory session store with size cap and background pruning.
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, AuthenticatedSession>>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
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

    /// Store an authenticated session. Returns false if at capacity (DoS protection).
    pub async fn store(&self, session: AuthenticatedSession) -> bool {
        let mut sessions = self.sessions.write().await;

        // Lazy prune when approaching capacity.
        if sessions.len() >= MAX_SESSIONS / 2 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            sessions.retain(|_, s| s.expires_at > now);
        }

        if sessions.len() >= MAX_SESSIONS {
            tracing::warn!(
                count = sessions.len(),
                "session store at capacity — rejecting new session"
            );
            return false;
        }

        sessions.insert(session.session_id.clone(), session);
        true
    }

    /// Retrieve a session by ID. Returns None if not found or expired.
    pub async fn get(&self, session_id: &str) -> Option<AuthenticatedSession> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > session.expires_at {
            return None;
        }

        Some(session.clone())
    }

    /// Remove an expired session or revoke a session.
    pub async fn revoke(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id).is_some()
    }

    /// Prune all expired sessions.
    pub async fn prune_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let before = sessions.len();
        sessions.retain(|_, s| s.expires_at > now);
        before - sessions.len()
    }

    /// Count active sessions.
    pub async fn count(&self) -> usize {
        self.sessions.read().await.len()
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
        let store = SessionStore::new();
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
        let store = SessionStore::new();
        store.store(make_session("s2", 1000)).await; // expired
        assert!(store.get("s2").await.is_none());
    }

    #[tokio::test]
    async fn test_revoke_session() {
        let store = SessionStore::new();
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
        let store = SessionStore::new();
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
        let store = SessionStore::new();
        assert!(store.get("nonexistent").await.is_none());
    }
}
