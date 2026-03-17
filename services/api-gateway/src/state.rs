//! Shared application state for all route handlers.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::identity::JwtValidator;
use mpc_wallet_core::rbac::{AbacAttributes, ApiRole, AuthContext};

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

        let metrics = Metrics::new();
        metrics.register();

        Self {
            chain_registry: Arc::new(chain_registry),
            jwt_validator: Arc::new(jwt_validator),
            hmac_key: Arc::new(hmac_key),
            api_keys,
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
    /// Returns the matching `ApiKeyEntry` if found and not expired.
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
}
