//! Environment configuration for the API gateway.

/// Backend type for sessions, replay cache, and revocation store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    /// In-memory storage (dev/test, single-instance).
    Memory,
    /// Redis storage (production, horizontally scalable).
    Redis,
}

impl BackendType {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "redis" => Self::Redis,
            _ => Self::Memory,
        }
    }
}

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
    /// Session TTL in seconds. Default: 3600 (1 hour).
    pub session_ttl: u64,
    /// mTLS service registry file (JSON array of MtlsServiceEntry).
    pub mtls_services_file: Option<String>,
    /// Session/cache backend type.
    pub session_backend: BackendType,
    /// Redis URL (required when session_backend = "redis").
    /// Supports `redis://` and `rediss://` (TLS).
    pub redis_url: Option<String>,
    /// Session encryption key (hex-encoded 32 bytes). Required for Redis backend.
    pub session_encryption_key: Option<String>,
}

impl AppConfig {
    /// Load configuration from environment variables.
    ///
    /// # Panics
    /// Panics if `JWT_SECRET` is not set or < 32 bytes.
    pub fn from_env() -> Self {
        let jwt_secret =
            std::env::var("JWT_SECRET").expect("JWT_SECRET environment variable must be set");

        let config = Self {
            port: std::env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3000),
            jwt_secret,
            jwt_issuer: std::env::var("JWT_ISSUER").unwrap_or_else(|_| "mpc-wallet".into()),
            jwt_audience: std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "mpc-wallet-api".into()),
            network: std::env::var("NETWORK")
                .unwrap_or_else(|_| "testnet".into())
                .to_lowercase(),
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
            session_ttl: std::env::var("SESSION_TTL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            mtls_services_file: std::env::var("MTLS_SERVICES_FILE").ok(),
            session_backend: BackendType::parse(
                &std::env::var("SESSION_BACKEND").unwrap_or_else(|_| "memory".into()),
            ),
            redis_url: std::env::var("REDIS_URL").ok(),
            session_encryption_key: std::env::var("SESSION_ENCRYPTION_KEY").ok(),
        };
        config.validate();
        config
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
        assert!(
            self.session_ttl >= 60,
            "SESSION_TTL must be at least 60 seconds (got {})",
            self.session_ttl
        );
        // Redis backend requires URL and encryption key.
        if self.session_backend == BackendType::Redis {
            assert!(
                self.redis_url.is_some(),
                "REDIS_URL is required when SESSION_BACKEND=redis"
            );
            assert!(
                self.session_encryption_key.is_some(),
                "SESSION_ENCRYPTION_KEY is required when SESSION_BACKEND=redis (hex-encoded 32 bytes)"
            );
        }
        // Mainnet safety: require explicit keys, no auto-generation.
        if self.network == "mainnet" {
            assert!(
                self.server_signing_key.is_some(),
                "SERVER_SIGNING_KEY is required on mainnet (auto-generation disabled)"
            );
            assert!(
                self.client_keys_file.is_some(),
                "CLIENT_KEYS_FILE is required on mainnet (open enrollment disabled)"
            );
        }
    }

    /// Create a test configuration (bypasses env var requirements).
    #[doc(hidden)]
    pub fn for_test() -> Self {
        Self {
            port: 3000,
            jwt_secret: "test-secret-for-unit-tests-only-32b".into(),
            jwt_issuer: "test-issuer".into(),
            jwt_audience: "test-audience".into(),
            network: "testnet".into(),
            rate_limit_rps: 100,
            cors_origins: vec![],
            server_signing_key: None, // auto-generated in AppState for tests
            client_keys_file: None,
            revoked_keys_file: None,
            session_ttl: 3600,
            mtls_services_file: None,
            session_backend: BackendType::Memory,
            redis_url: None,
            session_encryption_key: None,
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
}
