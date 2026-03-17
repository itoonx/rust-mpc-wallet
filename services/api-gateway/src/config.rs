//! Environment configuration for the API gateway.

use mpc_wallet_core::rbac::ApiRole;
use serde::Deserialize;

/// API gateway configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// HTTP listen port.
    pub port: u16,
    /// JWT HMAC secret for token validation (>= 32 bytes required).
    pub jwt_secret: String,
    /// Expected JWT issuer (`iss` claim).
    pub jwt_issuer: String,
    /// Expected JWT audience (`aud` claim).
    pub jwt_audience: String,
    /// Scoped API keys with role-based permissions.
    pub api_keys: Vec<ApiKeyConfig>,
    /// Network environment: "mainnet", "testnet", "devnet".
    pub network: String,
    /// Rate limit: max requests per second per IP.
    pub rate_limit_rps: u32,
    /// CORS allowed origins (comma-separated). Empty = block all cross-origin.
    pub cors_origins: Vec<String>,
    /// Server Ed25519 signing key (hex-encoded 32-byte secret). Auto-generated for tests.
    pub server_signing_key: Option<String>,
    /// Trusted client public keys file (JSON array of ClientKeyEntry).
    pub client_keys_file: Option<String>,
    /// Revoked key IDs file (JSON array of hex key_id strings).
    pub revoked_keys_file: Option<String>,
}

/// Configuration for a single scoped API key.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiKeyConfig {
    /// The raw API key secret (only used during startup to compute hash).
    pub key: String,
    /// Human-readable label for audit logging.
    pub label: String,
    /// Maximum role this key can assume.
    pub role: String,
    /// Optional: restrict to specific wallet IDs.
    #[serde(default)]
    pub allowed_wallets: Option<Vec<String>>,
    /// Optional: restrict to specific chains.
    #[serde(default)]
    pub allowed_chains: Option<Vec<String>>,
    /// Expiration timestamp (UNIX seconds). Null = no expiry.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl ApiKeyConfig {
    /// Parse the role string into an `ApiRole`.
    pub fn api_role(&self) -> ApiRole {
        match self.role.as_str() {
            "admin" => ApiRole::Admin,
            "initiator" => ApiRole::Initiator,
            "approver" => ApiRole::Approver,
            _ => ApiRole::Viewer,
        }
    }
}

impl AppConfig {
    /// Load configuration from environment variables.
    ///
    /// # Panics
    /// Panics if `JWT_SECRET` is not set or < 32 bytes.
    pub fn from_env() -> Self {
        let jwt_secret =
            std::env::var("JWT_SECRET").expect("JWT_SECRET environment variable must be set");

        let api_keys = Self::load_api_keys();

        let config = Self {
            port: std::env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3000),
            jwt_secret,
            jwt_issuer: std::env::var("JWT_ISSUER").unwrap_or_else(|_| "mpc-wallet".into()),
            jwt_audience: std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "mpc-wallet-api".into()),
            api_keys,
            network: std::env::var("NETWORK").unwrap_or_else(|_| "testnet".into()),
            rate_limit_rps: std::env::var("RATE_LIMIT_RPS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            cors_origins: std::env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            server_signing_key: std::env::var("SERVER_SIGNING_KEY").ok(),
            client_keys_file: std::env::var("CLIENT_KEYS_FILE").ok(),
            revoked_keys_file: std::env::var("REVOKED_KEYS_FILE").ok(),
        };
        config.validate();
        config
    }

    /// Load API keys from `API_KEYS_FILE` (JSON array) or fall back to
    /// `API_KEYS` (comma-separated plaintext, all get Viewer role).
    fn load_api_keys() -> Vec<ApiKeyConfig> {
        if let Ok(path) = std::env::var("API_KEYS_FILE") {
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read API_KEYS_FILE at {path}: {e}"));
            serde_json::from_str(&content)
                .unwrap_or_else(|e| panic!("failed to parse API_KEYS_FILE as JSON array: {e}"))
        } else {
            // Legacy fallback: comma-separated keys, all get Viewer role.
            std::env::var("API_KEYS")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.is_empty())
                .enumerate()
                .map(|(i, key)| ApiKeyConfig {
                    key: key.to_string(),
                    label: format!("legacy-key-{i}"),
                    role: "viewer".into(),
                    allowed_wallets: None,
                    allowed_chains: None,
                    expires_at: None,
                })
                .collect()
        }
    }

    /// Validate configuration invariants. Panics on invalid config.
    pub fn validate(&self) {
        assert!(
            self.jwt_secret.len() >= 32,
            "JWT_SECRET must be at least 32 bytes (got {})",
            self.jwt_secret.len()
        );
        assert!(
            matches!(self.network.as_str(), "mainnet" | "testnet" | "devnet"),
            "NETWORK must be one of: mainnet, testnet, devnet (got '{}')",
            self.network
        );
    }

    /// Create a test configuration (bypasses env var requirements).
    #[cfg(test)]
    pub fn for_test() -> Self {
        Self {
            port: 3000,
            jwt_secret: "test-secret-for-unit-tests-only-32b".into(),
            jwt_issuer: "test-issuer".into(),
            jwt_audience: "test-audience".into(),
            api_keys: vec![
                ApiKeyConfig {
                    key: "test-admin-key".into(),
                    label: "test-admin".into(),
                    role: "admin".into(),
                    allowed_wallets: None,
                    allowed_chains: None,
                    expires_at: None,
                },
                ApiKeyConfig {
                    key: "test-viewer-key".into(),
                    label: "test-viewer".into(),
                    role: "viewer".into(),
                    allowed_wallets: None,
                    allowed_chains: None,
                    expires_at: None,
                },
                ApiKeyConfig {
                    key: "test-initiator-key".into(),
                    label: "test-initiator".into(),
                    role: "initiator".into(),
                    allowed_wallets: None,
                    allowed_chains: None,
                    expires_at: None,
                },
            ],
            network: "testnet".into(),
            rate_limit_rps: 100,
            cors_origins: vec![],
            server_signing_key: None, // auto-generated in AppState for tests
            client_keys_file: None,
            revoked_keys_file: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config_passes_validation() {
        let config = AppConfig::for_test();
        config.validate(); // should not panic
    }

    #[test]
    #[should_panic(expected = "JWT_SECRET must be at least 32 bytes")]
    fn test_short_jwt_secret_panics() {
        let mut config = AppConfig::for_test();
        config.jwt_secret = "too-short".into();
        config.validate();
    }

    #[test]
    #[should_panic(expected = "NETWORK must be one of")]
    fn test_invalid_network_panics() {
        let mut config = AppConfig::for_test();
        config.network = "invalid".into();
        config.validate();
    }

    #[test]
    fn test_api_key_role_parsing() {
        let key = ApiKeyConfig {
            key: "k".into(),
            label: "l".into(),
            role: "admin".into(),
            allowed_wallets: None,
            allowed_chains: None,
            expires_at: None,
        };
        assert_eq!(key.api_role(), ApiRole::Admin);

        let key2 = ApiKeyConfig {
            key: "k".into(),
            label: "l".into(),
            role: "unknown".into(),
            allowed_wallets: None,
            allowed_chains: None,
            expires_at: None,
        };
        assert_eq!(key2.api_role(), ApiRole::Viewer);
    }
}
