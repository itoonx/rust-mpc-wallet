//! Environment configuration for the API gateway.
//!
//! Secrets can be loaded from environment variables (dev) or HashiCorp Vault (production).
//! Set `SECRETS_BACKEND=vault` + `VAULT_ADDR` to use Vault.

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

/// Secrets backend — where sensitive values come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsBackend {
    /// Environment variables (dev/test).
    Env,
    /// HashiCorp Vault KV v2 (production).
    Vault,
}

impl SecretsBackend {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "vault" => Self::Vault,
            _ => Self::Env,
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
    /// MPC node verifying keys file (JSON array of PeerKeyEntry).
    /// Required for keygen/sign — nodes verify each other's SignedEnvelope with these keys.
    pub node_verifying_keys_file: Option<String>,
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
    /// Secrets backend type (env vars or Vault).
    pub secrets_backend: SecretsBackend,
}

impl AppConfig {
    /// Load configuration from environment variables.
    /// If `SECRETS_BACKEND=vault`, secrets are fetched from HashiCorp Vault first.
    ///
    /// # Panics
    /// Panics if `JWT_SECRET` is not set (either via env or Vault) or < 32 bytes.
    pub fn from_env() -> Self {
        Self::from_env_sync(None)
    }

    /// Async version that loads secrets from Vault if configured.
    pub async fn from_env_with_vault() -> Self {
        let secrets_backend = SecretsBackend::parse(
            &std::env::var("SECRETS_BACKEND").unwrap_or_else(|_| "env".into()),
        );

        let vault_secrets = if secrets_backend == SecretsBackend::Vault {
            let vault_config = crate::vault::VaultConfig::from_env()
                .expect("SECRETS_BACKEND=vault but VAULT_ADDR not set");
            tracing::info!(
                addr = %vault_config.addr,
                mount = %vault_config.mount,
                path = %vault_config.secrets_path,
                "loading secrets from HashiCorp Vault"
            );
            let client = crate::vault::VaultClient::new(vault_config);
            let secrets = client
                .read_secrets()
                .await
                .expect("failed to read secrets from Vault");
            tracing::info!("secrets loaded from Vault successfully");
            Some(secrets)
        } else {
            None
        };

        Self::from_env_sync(vault_secrets)
    }

    /// Internal: build config, optionally overlaying Vault secrets.
    fn from_env_sync(vault_secrets: Option<crate::vault::VaultSecrets>) -> Self {
        // Vault secrets take precedence over env vars for sensitive fields.
        // Extract inner String from Zeroizing<String> for AppConfig fields.
        let jwt_secret = vault_secrets
            .as_ref()
            .and_then(|v| v.jwt_secret.as_deref().map(String::from))
            .or_else(|| std::env::var("JWT_SECRET").ok())
            .expect("JWT_SECRET must be set (via Vault or JWT_SECRET env var)");

        let server_signing_key = vault_secrets
            .as_ref()
            .and_then(|v| v.server_signing_key.as_deref().map(String::from))
            .or_else(|| std::env::var("SERVER_SIGNING_KEY").ok());

        let session_encryption_key = vault_secrets
            .as_ref()
            .and_then(|v| v.session_encryption_key.as_deref().map(String::from))
            .or_else(|| std::env::var("SESSION_ENCRYPTION_KEY").ok());

        let redis_url = vault_secrets
            .as_ref()
            .and_then(|v| v.redis_url.as_deref().map(String::from))
            .or_else(|| std::env::var("REDIS_URL").ok());

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
            server_signing_key,
            client_keys_file: std::env::var("CLIENT_KEYS_FILE").ok(),
            revoked_keys_file: std::env::var("REVOKED_KEYS_FILE").ok(),
            node_verifying_keys_file: std::env::var("NODE_VERIFYING_KEYS_FILE").ok(),
            session_ttl: std::env::var("SESSION_TTL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            mtls_services_file: std::env::var("MTLS_SERVICES_FILE").ok(),
            session_backend: BackendType::parse(
                &std::env::var("SESSION_BACKEND").unwrap_or_else(|_| "memory".into()),
            ),
            redis_url,
            session_encryption_key,
            secrets_backend: SecretsBackend::parse(
                &std::env::var("SECRETS_BACKEND").unwrap_or_else(|_| "env".into()),
            ),
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
        assert!(
            self.rate_limit_rps > 0,
            "RATE_LIMIT_RPS must be > 0 (got {})",
            self.rate_limit_rps
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
        // Mainnet safety: CORS wildcard disallowed + require explicit keys.
        if self.network == "mainnet" {
            let has_wildcard = self.cors_origins.iter().any(|o| o == "*");
            assert!(
                !has_wildcard,
                "CORS_ALLOWED_ORIGINS must not contain wildcard '*' on mainnet"
            );
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
            node_verifying_keys_file: None,
            session_ttl: 3600,
            mtls_services_file: None,
            session_backend: BackendType::Memory,
            redis_url: None,
            session_encryption_key: None,
            secrets_backend: SecretsBackend::Env,
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
    #[should_panic(expected = "RATE_LIMIT_RPS must be > 0")]
    fn test_zero_rate_limit_panics() {
        let mut config = AppConfig::for_test();
        config.rate_limit_rps = 0;
        config.validate();
    }

    #[test]
    #[should_panic(expected = "SESSION_ENCRYPTION_KEY is required")]
    fn test_redis_without_encryption_key_panics() {
        let mut config = AppConfig::for_test();
        config.session_backend = BackendType::Redis;
        config.redis_url = Some("redis://localhost:6379".into());
        config.session_encryption_key = None;
        config.validate();
    }

    #[test]
    #[should_panic(expected = "REDIS_URL is required")]
    fn test_redis_without_url_panics() {
        let mut config = AppConfig::for_test();
        config.session_backend = BackendType::Redis;
        config.redis_url = None;
        config.validate();
    }

    #[test]
    #[should_panic(expected = "CORS_ALLOWED_ORIGINS must not contain wildcard")]
    fn test_cors_wildcard_on_mainnet_panics() {
        let mut config = AppConfig::for_test();
        config.network = "mainnet".into();
        config.cors_origins = vec!["*".into()];
        config.server_signing_key = Some("aa".repeat(32));
        config.client_keys_file = Some("/tmp/keys.json".into());
        config.validate();
    }

    #[test]
    #[should_panic(expected = "SESSION_TTL must be at least 60 seconds")]
    fn test_session_ttl_too_low_panics() {
        let mut config = AppConfig::for_test();
        config.session_ttl = 10;
        config.validate();
    }

    #[test]
    #[should_panic(expected = "SERVER_SIGNING_KEY is required on mainnet")]
    fn test_mainnet_requires_server_signing_key() {
        let mut config = AppConfig::for_test();
        config.network = "mainnet".into();
        config.server_signing_key = None;
        config.validate();
    }

    #[test]
    fn test_backend_type_parse() {
        assert_eq!(BackendType::parse("redis"), BackendType::Redis);
        assert_eq!(BackendType::parse("REDIS"), BackendType::Redis);
        assert_eq!(BackendType::parse("memory"), BackendType::Memory);
        assert_eq!(BackendType::parse("anything"), BackendType::Memory);
    }

    #[test]
    fn test_secrets_backend_parse() {
        assert_eq!(SecretsBackend::parse("vault"), SecretsBackend::Vault);
        assert_eq!(SecretsBackend::parse("VAULT"), SecretsBackend::Vault);
        assert_eq!(SecretsBackend::parse("env"), SecretsBackend::Env);
        assert_eq!(SecretsBackend::parse("anything"), SecretsBackend::Env);
    }
}
