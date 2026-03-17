//! Shared application state for all route handlers.

use std::sync::Arc;

use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::identity::JwtValidator;

use crate::config::AppConfig;

/// Shared application state passed to all Axum handlers.
#[derive(Clone)]
pub struct AppState {
    /// Chain registry for provider instantiation.
    pub chain_registry: Arc<ChainRegistry>,
    /// JWT validator for Bearer token auth.
    pub jwt_validator: Arc<JwtValidator>,
    /// Valid API keys for X-API-Key auth.
    pub api_keys: Vec<String>,
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

        let jwt_validator = JwtValidator::from_hmac_secret(config.jwt_secret.as_bytes());

        let metrics = Metrics::new();
        metrics.register();

        Self {
            chain_registry: Arc::new(chain_registry),
            jwt_validator: Arc::new(jwt_validator),
            api_keys: config.api_keys.clone(),
            metrics: Arc::new(metrics),
        }
    }
}
