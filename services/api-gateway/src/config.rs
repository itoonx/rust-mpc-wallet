//! Environment configuration for the API gateway.

/// API gateway configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// HTTP listen port.
    pub port: u16,
    /// JWT HMAC secret for token validation.
    pub jwt_secret: String,
    /// API keys for service-to-service auth (comma-separated).
    pub api_keys: Vec<String>,
    /// Network environment: "mainnet", "testnet", "devnet".
    pub network: String,
    /// Rate limit: max requests per second per IP.
    pub rate_limit_rps: u32,
}

impl AppConfig {
    /// Load configuration from environment variables with sensible defaults.
    pub fn from_env() -> Self {
        Self {
            port: std::env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3000),
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "dev-secret-change-in-production".into()),
            api_keys: std::env::var("API_KEYS")
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            network: std::env::var("NETWORK").unwrap_or_else(|_| "testnet".into()),
            rate_limit_rps: std::env::var("RATE_LIMIT_RPS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
        }
    }
}
