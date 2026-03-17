//! Shared application state for all route handlers.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::identity::JwtValidator;
use mpc_wallet_core::rbac::{AbacAttributes, ApiRole, AuthContext};

use crate::auth::session::SessionStore;
use crate::config::{ApiKeyConfig, AppConfig};

type HmacSha256 = Hmac<Sha256>;

/// A hashed, scoped API key entry stored in AppState.
#[derive(Clone)]
pub struct ApiKeyEntry {
    /// HMAC-SHA256 hash of the raw key.
    pub key_hash: [u8; 32],
    /// Human-readable label for audit logging.
    pub label: String,
    /// Maximum role this key can assume.
    pub role: ApiRole,
    /// Optional: restrict to specific wallet IDs.
    pub allowed_wallets: Option<Vec<String>>,
    /// Optional: restrict to specific chains.
    pub allowed_chains: Option<Vec<String>>,
    /// Expiration timestamp (UNIX seconds), None = no expiry.
    pub expires_at: Option<u64>,
}

impl ApiKeyEntry {
    /// Check whether this key has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now > exp
        } else {
            false
        }
    }

    /// Build an `AuthContext` from this key's metadata.
    pub fn auth_context(&self) -> AuthContext {
        AuthContext::with_attributes(
            format!("api-key:{}", self.label),
            vec![self.role.clone()],
            AbacAttributes::default(),
            false, // API keys don't have MFA
        )
    }
}

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
        match self.role.as_str() {
            "admin" => ApiRole::Admin,
            "initiator" => ApiRole::Initiator,
            "approver" => ApiRole::Approver,
            _ => ApiRole::Viewer,
        }
    }
}

/// Trusted client key registry.
#[derive(Clone)]
pub struct ClientKeyRegistry {
    pub keys: HashMap<String, ClientKeyEntry>,
}

impl ClientKeyRegistry {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
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

/// Replay cache for handshake nonces.
#[derive(Clone)]
pub struct ReplayCache {
    /// Maps client_nonce (hex) → expiry timestamp.
    cache: Arc<RwLock<HashMap<String, u64>>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if a nonce has been seen. If not, record it with TTL.
    /// Returns true if replay detected (nonce already seen).
    pub async fn check_and_record(&self, nonce: &str, ttl_secs: u64) -> bool {
        let mut cache = self.cache.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Prune expired entries.
        cache.retain(|_, expiry| *expiry > now);

        if cache.contains_key(nonce) {
            return true; // replay detected
        }
        cache.insert(nonce.to_string(), now + ttl_secs);
        false
    }
}

/// Shared application state passed to all Axum handlers.
#[derive(Clone)]
pub struct AppState {
    /// Chain registry for provider instantiation.
    pub chain_registry: Arc<ChainRegistry>,
    /// JWT validator for Bearer token auth.
    pub jwt_validator: Arc<JwtValidator>,
    /// HMAC key for API key hashing (derived from JWT secret).
    hmac_key: Arc<Vec<u8>>,
    /// Hashed, scoped API keys.
    pub api_keys: Vec<ApiKeyEntry>,
    /// Server Ed25519 signing key for handshake auth.
    pub server_signing_key: Arc<SigningKey>,
    /// Authenticated session store.
    pub session_store: SessionStore,
    /// Trusted client key registry.
    pub client_registry: Arc<ClientKeyRegistry>,
    /// Revoked key IDs.
    pub revoked_keys: Arc<HashSet<String>>,
    /// Replay cache for handshake nonces.
    pub replay_cache: ReplayCache,
    /// Prometheus metrics registry.
    pub metrics: Arc<Metrics>,
}

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

impl AppState {
    /// Build `AppState` from configuration.
    pub fn from_config(config: &AppConfig) -> Self {
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

        let hmac_key = config.jwt_secret.as_bytes().to_vec();
        let api_keys = config
            .api_keys
            .iter()
            .map(|k| Self::hash_api_key(&hmac_key, k))
            .collect();

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

        // Load revoked keys.
        let revoked_keys = if let Some(ref path) = config.revoked_keys_file {
            let content = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("failed to read REVOKED_KEYS_FILE at {path}: {e}"));
            let keys: Vec<String> = serde_json::from_str(&content)
                .unwrap_or_else(|e| panic!("failed to parse REVOKED_KEYS_FILE: {e}"));
            keys.into_iter().collect()
        } else {
            HashSet::new()
        };

        let metrics = Metrics::new();
        metrics.register();

        Self {
            chain_registry: Arc::new(chain_registry),
            jwt_validator: Arc::new(jwt_validator),
            hmac_key: Arc::new(hmac_key),
            api_keys,
            server_signing_key: Arc::new(server_signing_key),
            session_store: SessionStore::new(),
            client_registry: Arc::new(client_registry),
            revoked_keys: Arc::new(revoked_keys),
            replay_cache: ReplayCache::new(),
            metrics: Arc::new(metrics),
        }
    }

    /// Hash a raw API key config into an `ApiKeyEntry` with HMAC-SHA256 digest.
    fn hash_api_key(hmac_key: &[u8], config: &ApiKeyConfig) -> ApiKeyEntry {
        let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC can take key of any size");
        mac.update(config.key.as_bytes());
        let result = mac.finalize();
        let hash: [u8; 32] = result.into_bytes().into();

        ApiKeyEntry {
            key_hash: hash,
            label: config.label.clone(),
            role: config.api_role(),
            allowed_wallets: config.allowed_wallets.clone(),
            allowed_chains: config.allowed_chains.clone(),
            expires_at: config.expires_at,
        }
    }

    /// Verify an incoming API key against stored hashes using constant-time comparison.
    pub fn verify_api_key(&self, raw_key: &str) -> Option<&ApiKeyEntry> {
        let mut mac =
            HmacSha256::new_from_slice(&self.hmac_key).expect("HMAC can take key of any size");
        mac.update(raw_key.as_bytes());
        let incoming_hash: [u8; 32] = mac.finalize().into_bytes().into();

        for entry in &self.api_keys {
            if incoming_hash.ct_eq(&entry.key_hash).into() {
                if entry.is_expired() {
                    return None;
                }
                return Some(entry);
            }
        }
        None
    }

    /// Check if a key_id is revoked.
    pub fn is_key_revoked(&self, key_id: &str) -> bool {
        self.revoked_keys.contains(key_id)
    }
}
