//! Shared application state for all route handlers.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use tokio::sync::RwLock;

use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::identity::JwtValidator;
use mpc_wallet_core::rbac::ApiRole;

use crate::auth::mtls::{MtlsServiceEntry, MtlsServiceRegistry};
use crate::auth::session::SessionStore;
use crate::config::AppConfig;
use crate::middleware::rate_limit::RateLimiter;

/// Trusted client public key entry.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ClientKeyEntry {
    /// Hex-encoded Ed25519 public key (64 hex chars = 32 bytes).
    pub pubkey: String,
    /// Key ID (first 8 bytes of pubkey, hex).
    pub key_id: String,
    /// Role assigned to this client.
    pub role: String,
    /// Human-readable label.
    pub label: String,
}

impl ClientKeyEntry {
    pub fn api_role(&self) -> ApiRole {
        crate::auth::types::parse_role(&self.role)
    }
}

/// Trusted client key registry.
#[derive(Clone, Default)]
pub struct ClientKeyRegistry {
    pub keys: HashMap<String, ClientKeyEntry>,
}

impl ClientKeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entries(entries: Vec<ClientKeyEntry>) -> Self {
        let mut keys = HashMap::new();
        for entry in entries {
            keys.insert(entry.key_id.clone(), entry);
        }
        Self { keys }
    }

    /// Verify a client key_id is trusted and pubkey matches.
    pub fn verify_trusted(&self, key_id: &str, pubkey_hex: &str) -> Option<&ClientKeyEntry> {
        let entry = self.keys.get(key_id)?;
        if entry.pubkey == pubkey_hex {
            Some(entry)
        } else {
            None
        }
    }

    /// Check if a key_id is registered (regardless of pubkey match).
    pub fn contains(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }
}

// ── ReplayCacheBackend Trait ─────────────────────────────────────────

/// Pluggable replay cache backend.
///
/// Implementations track nonces that have been seen within a TTL window
/// to prevent replay attacks on handshake messages.
#[async_trait]
pub trait ReplayCacheBackend: Send + Sync {
    /// Check if a nonce has been seen. If not, record it with TTL.
    /// Returns `true` if replay detected (nonce already seen).
    async fn check_and_record(&self, nonce: &str, ttl_secs: u64) -> bool;

    /// Remove expired entries. Returns count removed.
    async fn prune(&self) -> usize;
}

// ── InMemoryReplayBackend ───────────────────────────────────────────

/// In-memory replay cache backend (dev/test, single-instance).
#[derive(Clone, Default)]
pub struct InMemoryReplayBackend {
    /// Maps nonce → expiry timestamp.
    cache: Arc<RwLock<HashMap<String, u64>>>,
}

impl InMemoryReplayBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ReplayCacheBackend for InMemoryReplayBackend {
    async fn check_and_record(&self, nonce: &str, ttl_secs: u64) -> bool {
        let mut cache = self.cache.write().await;
        let now = crate::auth::types::unix_now();

        if cache.contains_key(nonce) {
            return true; // replay detected
        }

        // Prune only when approaching capacity (avoid O(n) on every request).
        if cache.len() >= crate::auth::types::MAX_CACHE_ENTRIES / 2 {
            cache.retain(|_, expiry| *expiry > now);
        }

        if cache.len() >= crate::auth::types::MAX_CACHE_ENTRIES {
            return false; // capacity exceeded — silently drop (rate limiter catches abuse)
        }

        cache.insert(nonce.to_string(), now + ttl_secs);
        false
    }

    async fn prune(&self) -> usize {
        let mut cache = self.cache.write().await;
        let now = crate::auth::types::unix_now();
        let before = cache.len();
        cache.retain(|_, expiry| *expiry > now);
        before - cache.len()
    }
}

// ── ReplayCache Facade ──────────────────────────────────────────────

/// Replay cache facade — wraps any `ReplayCacheBackend` implementation.
/// Use `ReplayCache::in_memory()` for dev/test, or provide a custom backend.
#[derive(Clone)]
pub struct ReplayCache {
    backend: Arc<dyn ReplayCacheBackend>,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl ReplayCache {
    /// Create an in-memory replay cache (dev/test).
    pub fn in_memory() -> Self {
        Self {
            backend: Arc::new(InMemoryReplayBackend::new()),
        }
    }

    /// Create a replay cache with a custom backend (e.g., Redis).
    pub fn with_backend(backend: Arc<dyn ReplayCacheBackend>) -> Self {
        Self { backend }
    }

    pub fn new() -> Self {
        Self::in_memory()
    }

    /// Check if a nonce has been seen. If not, record it with TTL.
    /// Returns true if replay detected (nonce already seen).
    /// Capped at MAX_CACHE_ENTRIES to prevent DoS.
    pub async fn check_and_record(&self, nonce: &str, ttl_secs: u64) -> bool {
        self.backend.check_and_record(nonce, ttl_secs).await
    }

    /// Remove expired entries. Returns count removed.
    pub async fn prune(&self) -> usize {
        self.backend.prune().await
    }
}

// ── RevocationBackend Trait ─────────────────────────────────────────

/// Pluggable key revocation backend.
///
/// Tracks which client key IDs have been revoked and should be denied
/// access during handshake and session refresh.
#[async_trait]
pub trait RevocationBackend: Send + Sync {
    /// Check if a key_id is revoked.
    async fn is_revoked(&self, key_id: &str) -> bool;

    /// Revoke a key_id. Returns `true` if it was newly added (not already revoked).
    async fn revoke(&self, key_id: String) -> bool;

    /// List all revoked key IDs.
    async fn list(&self) -> Vec<String>;
}

// ── InMemoryRevocationBackend ───────────────────────────────────────

/// In-memory revocation backend (dev/test, single-instance).
#[derive(Clone, Default)]
pub struct InMemoryRevocationBackend {
    revoked: Arc<RwLock<HashSet<String>>>,
}

impl InMemoryRevocationBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from an initial set of revoked key IDs.
    pub fn from_set(keys: HashSet<String>) -> Self {
        Self {
            revoked: Arc::new(RwLock::new(keys)),
        }
    }
}

#[async_trait]
impl RevocationBackend for InMemoryRevocationBackend {
    async fn is_revoked(&self, key_id: &str) -> bool {
        self.revoked.read().await.contains(key_id)
    }

    async fn revoke(&self, key_id: String) -> bool {
        self.revoked.write().await.insert(key_id)
    }

    async fn list(&self) -> Vec<String> {
        self.revoked.read().await.iter().cloned().collect()
    }
}

// ── RevocationStore Facade ──────────────────────────────────────────

/// Revocation store facade — wraps any `RevocationBackend` implementation.
/// Use `RevocationStore::in_memory()` for dev/test, or provide a custom backend.
#[derive(Clone)]
pub struct RevocationStore {
    backend: Arc<dyn RevocationBackend>,
}

impl Default for RevocationStore {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl RevocationStore {
    /// Create an in-memory revocation store (dev/test).
    pub fn in_memory() -> Self {
        Self {
            backend: Arc::new(InMemoryRevocationBackend::new()),
        }
    }

    /// Create an in-memory revocation store pre-populated with revoked keys.
    pub fn in_memory_with(keys: HashSet<String>) -> Self {
        Self {
            backend: Arc::new(InMemoryRevocationBackend::from_set(keys)),
        }
    }

    /// Create a revocation store with a custom backend (e.g., Redis).
    pub fn with_backend(backend: Arc<dyn RevocationBackend>) -> Self {
        Self { backend }
    }

    /// Check if a key_id is revoked.
    pub async fn is_revoked(&self, key_id: &str) -> bool {
        self.backend.is_revoked(key_id).await
    }

    /// Revoke a key_id. Returns `true` if it was newly added.
    pub async fn revoke(&self, key_id: String) -> bool {
        self.backend.revoke(key_id).await
    }

    /// List all revoked key IDs.
    pub async fn list(&self) -> Vec<String> {
        self.backend.list().await
    }
}

// ── Metrics ─────────────────────────────────────────────────────────

/// Prometheus metrics for the API gateway.
pub struct Metrics {
    pub requests_total: prometheus::IntCounterVec,
    pub request_duration: prometheus::HistogramVec,
    pub keygen_total: prometheus::IntCounter,
    pub sign_total: prometheus::IntCounter,
    pub broadcast_errors: prometheus::IntCounter,
    pub auth_failures: prometheus::IntCounter,
    pub handshake_total: prometheus::IntCounter,
    pub handshake_failures: prometheus::IntCounter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests_total: prometheus::IntCounterVec::new(
                prometheus::Opts::new("mpc_api_requests_total", "Total API requests"),
                &["method", "path", "status"],
            )
            .expect("metric creation"),
            request_duration: prometheus::HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "mpc_api_request_duration_seconds",
                    "Request duration in seconds",
                ),
                &["method", "path"],
            )
            .expect("metric creation"),
            keygen_total: prometheus::IntCounter::new(
                "mpc_keygen_total",
                "Total keygen operations",
            )
            .expect("metric creation"),
            sign_total: prometheus::IntCounter::new("mpc_sign_total", "Total sign operations")
                .expect("metric creation"),
            broadcast_errors: prometheus::IntCounter::new(
                "mpc_broadcast_errors_total",
                "Total broadcast errors",
            )
            .expect("metric creation"),
            auth_failures: prometheus::IntCounter::new(
                "mpc_auth_failures_total",
                "Total authentication failures",
            )
            .expect("metric creation"),
            handshake_total: prometheus::IntCounter::new(
                "mpc_handshake_total",
                "Total handshake attempts",
            )
            .expect("metric creation"),
            handshake_failures: prometheus::IntCounter::new(
                "mpc_handshake_failures_total",
                "Total failed handshakes",
            )
            .expect("metric creation"),
        }
    }

    /// Register all metrics with the default Prometheus registry.
    pub fn register(&self) {
        let r = prometheus::default_registry();
        let _ = r.register(Box::new(self.requests_total.clone()));
        let _ = r.register(Box::new(self.request_duration.clone()));
        let _ = r.register(Box::new(self.keygen_total.clone()));
        let _ = r.register(Box::new(self.sign_total.clone()));
        let _ = r.register(Box::new(self.broadcast_errors.clone()));
        let _ = r.register(Box::new(self.auth_failures.clone()));
        let _ = r.register(Box::new(self.handshake_total.clone()));
        let _ = r.register(Box::new(self.handshake_failures.clone()));
    }
}

// ── AppState ────────────────────────────────────────────────────────

/// Shared application state passed to all Axum handlers.
#[derive(Clone)]
pub struct AppState {
    /// Chain registry for provider instantiation.
    pub chain_registry: Arc<ChainRegistry>,
    /// JWT validator for Bearer token auth.
    pub jwt_validator: Arc<JwtValidator>,
    /// Server Ed25519 signing key for handshake auth.
    pub server_signing_key: Arc<SigningKey>,
    /// Authenticated session store.
    pub session_store: SessionStore,
    /// Trusted client key registry.
    pub client_registry: Arc<ClientKeyRegistry>,
    /// Revoked key IDs store.
    pub revoked_keys: RevocationStore,
    /// Replay cache for handshake nonces.
    pub replay_cache: ReplayCache,
    /// Rate limiter for handshake endpoints.
    pub handshake_limiter: RateLimiter,
    /// mTLS service identity registry (service-to-service auth).
    pub mtls_registry: Arc<MtlsServiceRegistry>,
    /// Session TTL in seconds.
    pub session_ttl: u64,
    /// Prometheus metrics registry.
    pub metrics: Arc<Metrics>,
}

impl AppState {
    /// Build `AppState` from configuration.
    /// Async because Redis backend requires connection establishment.
    pub async fn from_config(config: &AppConfig) -> Self {
        let chain_registry = match config.network.as_str() {
            "mainnet" => ChainRegistry::default_mainnet(),
            "devnet" => ChainRegistry::default_testnet(),
            _ => ChainRegistry::default_testnet(),
        };

        let jwt_validator = JwtValidator::from_hmac_secret_strict(
            config.jwt_secret.as_bytes(),
            &config.jwt_issuer,
            &config.jwt_audience,
        );

        // Load or generate server signing key.
        let server_signing_key = if let Some(ref key_hex) = config.server_signing_key {
            let key_bytes = hex::decode(key_hex).expect("SERVER_SIGNING_KEY must be valid hex");
            assert_eq!(
                key_bytes.len(),
                32,
                "SERVER_SIGNING_KEY must be 32 bytes (64 hex chars)"
            );
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);
            SigningKey::from_bytes(&arr)
        } else {
            // Auto-generate for dev/test.
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            SigningKey::from_bytes(&bytes)
        };

        // Load client key registry.
        let client_registry = if let Some(ref path) = config.client_keys_file {
            let content = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("failed to read CLIENT_KEYS_FILE at {path}: {e}"));
            let entries: Vec<ClientKeyEntry> = serde_json::from_str(&content)
                .unwrap_or_else(|e| panic!("failed to parse CLIENT_KEYS_FILE: {e}"));
            ClientKeyRegistry::from_entries(entries)
        } else {
            ClientKeyRegistry::new()
        };

        // Load mTLS service registry.
        let mtls_registry = if let Some(ref path) = config.mtls_services_file {
            let content = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("failed to read MTLS_SERVICES_FILE at {path}: {e}"));
            let entries: Vec<MtlsServiceEntry> = serde_json::from_str(&content)
                .unwrap_or_else(|e| panic!("failed to parse MTLS_SERVICES_FILE: {e}"));
            tracing::info!(count = entries.len(), "mTLS service registry loaded");
            MtlsServiceRegistry::from_entries(entries)
        } else {
            MtlsServiceRegistry::new()
        };

        let metrics = Metrics::new();
        metrics.register();

        // Warn if client registry is empty on mainnet.
        if config.network == "mainnet" && client_registry.keys.is_empty() {
            tracing::warn!(
                "CLIENT_KEYS_FILE not set on mainnet — open enrollment mode (any Ed25519 key can authenticate)"
            );
        }

        // Build backends based on SESSION_BACKEND config.
        let (session_store, replay_cache, revoked_keys) = if config.session_backend
            == crate::config::BackendType::Redis
        {
            let redis_url = config.redis_url.as_ref().expect("REDIS_URL required");
            let redis_client = crate::auth::redis_backend::RealRedisClient::connect(redis_url)
                .await
                .expect("failed to connect to Redis");

            // Parse session encryption key.
            let kek_hex = config
                .session_encryption_key
                .as_ref()
                .expect("SESSION_ENCRYPTION_KEY required");
            let kek_bytes = hex::decode(kek_hex).expect("SESSION_ENCRYPTION_KEY must be valid hex");
            assert_eq!(
                kek_bytes.len(),
                32,
                "SESSION_ENCRYPTION_KEY must be 32 bytes"
            );
            let mut kek = [0u8; 32];
            kek.copy_from_slice(&kek_bytes);

            // Redis session backend with encrypted keys.
            let redis_arc = Arc::new(redis_client.clone());
            let session_backend = Arc::new(crate::auth::session_redis::RedisSessionBackend::new(
                redis_arc, kek,
            ));
            let session_store = SessionStore::with_backend(session_backend);

            // Redis replay cache.
            let replay_backend = Arc::new(crate::auth::redis_backend::RedisReplayBackend::new(
                redis_client.conn.clone(),
            ));
            let replay_cache = ReplayCache::with_backend(replay_backend);

            // Redis revocation store.
            let revocation_backend = Arc::new(
                crate::auth::redis_backend::RedisRevocationBackend::new(redis_client.conn.clone()),
            );

            // Load initial revoked keys from file into Redis.
            if let Some(ref path) = config.revoked_keys_file {
                let content = std::fs::read_to_string(path)
                    .unwrap_or_else(|e| panic!("failed to read REVOKED_KEYS_FILE at {path}: {e}"));
                let keys: Vec<String> = serde_json::from_str(&content)
                    .unwrap_or_else(|e| panic!("failed to parse REVOKED_KEYS_FILE: {e}"));
                revocation_backend
                    .load_initial(&keys)
                    .await
                    .expect("failed to load revoked keys into Redis");
            }
            let revoked_keys_store = RevocationStore::with_backend(revocation_backend);

            tracing::info!("using Redis backend for sessions, replay cache, and revocation");
            (session_store, replay_cache, revoked_keys_store)
        } else {
            // In-memory backends (dev/test).
            let revoked_keys_store = if let Some(ref path) = config.revoked_keys_file {
                let content = std::fs::read_to_string(path)
                    .unwrap_or_else(|e| panic!("failed to read REVOKED_KEYS_FILE at {path}: {e}"));
                let keys: Vec<String> = serde_json::from_str(&content)
                    .unwrap_or_else(|e| panic!("failed to parse REVOKED_KEYS_FILE: {e}"));
                RevocationStore::in_memory_with(keys.into_iter().collect())
            } else {
                RevocationStore::in_memory()
            };
            (
                SessionStore::in_memory(),
                ReplayCache::in_memory(),
                revoked_keys_store,
            )
        };

        Self {
            chain_registry: Arc::new(chain_registry),
            jwt_validator: Arc::new(jwt_validator),
            server_signing_key: Arc::new(server_signing_key),
            session_store,
            client_registry: Arc::new(client_registry),
            revoked_keys,
            replay_cache,
            handshake_limiter: RateLimiter::new(10),
            mtls_registry: Arc::new(mtls_registry),
            session_ttl: config.session_ttl,
            metrics: Arc::new(metrics),
        }
    }

    /// Check if a key_id is revoked.
    pub async fn is_key_revoked(&self, key_id: &str) -> bool {
        self.revoked_keys.is_revoked(key_id).await
    }

    /// Dynamically revoke a key (adds to the revoked set).
    pub async fn revoke_key(&self, key_id: String) -> bool {
        self.revoked_keys.revoke(key_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ReplayCache Tests ───────────────────────────────────────────

    #[tokio::test]
    async fn test_replay_cache_in_memory_no_replay() {
        let cache = ReplayCache::in_memory();
        assert!(!cache.check_and_record("nonce1", 60).await);
    }

    #[tokio::test]
    async fn test_replay_cache_in_memory_detects_replay() {
        let cache = ReplayCache::in_memory();
        assert!(!cache.check_and_record("nonce1", 60).await);
        assert!(cache.check_and_record("nonce1", 60).await);
    }

    #[tokio::test]
    async fn test_replay_cache_different_nonces_ok() {
        let cache = ReplayCache::in_memory();
        assert!(!cache.check_and_record("nonce1", 60).await);
        assert!(!cache.check_and_record("nonce2", 60).await);
    }

    #[tokio::test]
    async fn test_replay_cache_prune() {
        let backend = InMemoryReplayBackend::new();
        // Insert an already-expired entry
        {
            let mut cache = backend.cache.write().await;
            cache.insert("expired".to_string(), 1); // epoch 1 = expired
        }
        let pruned = backend.prune().await;
        assert_eq!(pruned, 1);
    }

    #[tokio::test]
    async fn test_replay_cache_with_custom_backend() {
        let backend = Arc::new(InMemoryReplayBackend::new());
        let cache = ReplayCache::with_backend(backend);
        assert!(!cache.check_and_record("n1", 60).await);
        assert!(cache.check_and_record("n1", 60).await);
    }

    // ── RevocationStore Tests ───────────────────────────────────────

    #[tokio::test]
    async fn test_revocation_store_empty() {
        let store = RevocationStore::in_memory();
        assert!(!store.is_revoked("key1").await);
        assert!(store.list().await.is_empty());
    }

    #[tokio::test]
    async fn test_revocation_store_revoke_and_check() {
        let store = RevocationStore::in_memory();
        assert!(store.revoke("key1".to_string()).await); // newly added
        assert!(store.is_revoked("key1").await);
        assert!(!store.revoke("key1".to_string()).await); // already revoked
    }

    #[tokio::test]
    async fn test_revocation_store_list() {
        let store = RevocationStore::in_memory();
        store.revoke("key1".to_string()).await;
        store.revoke("key2".to_string()).await;
        let mut list = store.list().await;
        list.sort();
        assert_eq!(list, vec!["key1", "key2"]);
    }

    #[tokio::test]
    async fn test_revocation_store_pre_populated() {
        let keys: HashSet<String> = ["k1", "k2"].iter().map(|s| s.to_string()).collect();
        let store = RevocationStore::in_memory_with(keys);
        assert!(store.is_revoked("k1").await);
        assert!(store.is_revoked("k2").await);
        assert!(!store.is_revoked("k3").await);
    }

    #[tokio::test]
    async fn test_revocation_store_with_custom_backend() {
        let backend = Arc::new(InMemoryRevocationBackend::new());
        let store = RevocationStore::with_backend(backend);
        assert!(store.revoke("key1".to_string()).await);
        assert!(store.is_revoked("key1").await);
    }

    // ── AppState backward compat tests ──────────────────────────────

    #[tokio::test]
    async fn test_app_state_is_key_revoked() {
        let config = AppConfig::for_test();
        let state = AppState::from_config(&config).await;
        assert!(!state.is_key_revoked("nonexistent").await);
        state.revoke_key("k1".to_string()).await;
        assert!(state.is_key_revoked("k1").await);
    }
}
