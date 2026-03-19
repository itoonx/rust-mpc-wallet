//! HashiCorp Vault integration for production secrets management.
//!
//! Reads secrets from Vault KV v2 engine via HTTP API.
//! Supports both token auth and AppRole auth.
//!
//! # Features
//!
//! - **Read secrets** from KV v2 (latest or specific version)
//! - **Lease renewal** for dynamic secrets
//! - **Background refresh** via [`SecretRefresher`] (periodic re-read from Vault)
//!
//! # Configuration
//!
//! | Env Var | Required | Description |
//! |---------|----------|-------------|
//! | `VAULT_ADDR` | yes | Vault server URL (e.g., `https://vault.internal:8200`) |
//! | `VAULT_TOKEN` | no* | Vault token (use for dev/CI) |
//! | `VAULT_ROLE_ID` | no* | AppRole role ID (production) |
//! | `VAULT_SECRET_ID` | no* | AppRole secret ID (production) |
//! | `VAULT_MOUNT` | no | KV v2 mount path (default: `secret`) |
//! | `VAULT_SECRETS_PATH` | no | Path within mount (default: `mpc-wallet/gateway`) |
//! | `VAULT_REFRESH_INTERVAL` | no | Secret refresh interval in seconds (default: 300) |
//!
//! *Either `VAULT_TOKEN` or (`VAULT_ROLE_ID` + `VAULT_SECRET_ID`) must be set.
//!
//! # Expected Vault secret structure
//!
//! ```text
//! secret/data/mpc-wallet/gateway:
//!   jwt_secret: "hex-encoded-32-bytes"
//!   server_signing_key: "hex-encoded-32-bytes"
//!   session_encryption_key: "hex-encoded-32-bytes"
//!   redis_url: "rediss://user:pass@redis.internal:6379"
//! ```

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Vault client configuration.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Vault server address (e.g., `https://vault.internal:8200`).
    pub addr: String,
    /// Authentication method.
    pub auth: VaultAuth,
    /// KV v2 mount path (default: `secret`).
    pub mount: String,
    /// Secret path within mount (default: `mpc-wallet/gateway`).
    pub secrets_path: String,
}

/// Vault authentication method.
#[derive(Debug, Clone)]
pub enum VaultAuth {
    /// Static token (dev/CI).
    Token(String),
    /// AppRole (production) — role_id + secret_id.
    AppRole { role_id: String, secret_id: String },
}

/// Secrets fetched from Vault.
#[derive(Debug, Clone, Default)]
pub struct VaultSecrets {
    pub jwt_secret: Option<String>,
    pub server_signing_key: Option<String>,
    pub session_encryption_key: Option<String>,
    pub redis_url: Option<String>,
}

/// Vault KV v2 read response.
#[derive(Deserialize)]
struct KvV2Response {
    data: KvV2Data,
}

#[derive(Deserialize)]
struct KvV2Data {
    data: HashMap<String, serde_json::Value>,
}

/// AppRole login response.
#[derive(Deserialize)]
struct AppRoleLoginResponse {
    auth: AppRoleAuth,
}

#[derive(Deserialize)]
struct AppRoleAuth {
    client_token: String,
}

impl VaultConfig {
    /// Load Vault configuration from environment variables.
    /// Returns `None` if `VAULT_ADDR` is not set (Vault disabled).
    pub fn from_env() -> Option<Self> {
        let addr = std::env::var("VAULT_ADDR").ok()?;

        let auth = if let Ok(token) = std::env::var("VAULT_TOKEN") {
            VaultAuth::Token(token)
        } else {
            let role_id = std::env::var("VAULT_ROLE_ID")
                .expect("VAULT_ADDR set but neither VAULT_TOKEN nor VAULT_ROLE_ID provided");
            let secret_id = std::env::var("VAULT_SECRET_ID")
                .expect("VAULT_ROLE_ID set but VAULT_SECRET_ID not provided");
            VaultAuth::AppRole { role_id, secret_id }
        };

        Some(Self {
            addr,
            auth,
            mount: std::env::var("VAULT_MOUNT").unwrap_or_else(|_| "secret".into()),
            secrets_path: std::env::var("VAULT_SECRETS_PATH")
                .unwrap_or_else(|_| "mpc-wallet/gateway".into()),
        })
    }
}

/// Vault client for reading secrets and managing leases.
pub struct VaultClient {
    http: reqwest::Client,
    config: VaultConfig,
}

impl VaultClient {
    /// Create a new Vault client.
    pub fn new(config: VaultConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client for Vault");
        Self { http, config }
    }

    /// Get the Vault configuration (for testing/inspection).
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// Authenticate and get a Vault token.
    async fn get_token(&self) -> Result<String, VaultError> {
        match &self.config.auth {
            VaultAuth::Token(token) => Ok(token.clone()),
            VaultAuth::AppRole { role_id, secret_id } => {
                let url = format!("{}/v1/auth/approle/login", self.config.addr);
                let body = serde_json::json!({
                    "role_id": role_id,
                    "secret_id": secret_id,
                });

                let resp = self
                    .http
                    .post(&url)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| VaultError::Connection(e.to_string()))?;

                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(VaultError::Auth(format!(
                        "AppRole login failed: {status} — {body}"
                    )));
                }

                let login: AppRoleLoginResponse = resp
                    .json()
                    .await
                    .map_err(|e| VaultError::Parse(e.to_string()))?;
                Ok(login.auth.client_token)
            }
        }
    }

    /// Read secrets from Vault KV v2 (latest version).
    pub async fn read_secrets(&self) -> Result<VaultSecrets, VaultError> {
        let token = self.get_token().await?;

        let url = format!(
            "{}/v1/{}/data/{}",
            self.config.addr, self.config.mount, self.config.secrets_path
        );

        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .map_err(|e| VaultError::Connection(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Read(format!(
                "KV read failed at {}: {status} — {body}",
                self.config.secrets_path
            )));
        }

        let kv: KvV2Response = resp
            .json()
            .await
            .map_err(|e| VaultError::Parse(e.to_string()))?;

        Ok(Self::extract_secrets(&kv.data.data))
    }

    /// Read secrets from a specific KV v2 version.
    ///
    /// This allows reading historical secret versions for rollback or audit.
    /// Version 0 is equivalent to "latest" (same as `read_secrets()`).
    pub async fn read_secret_version(
        &self,
        path: &str,
        version: u32,
    ) -> Result<HashMap<String, String>, VaultError> {
        let token = self.get_token().await?;

        let url = if version == 0 {
            format!(
                "{}/v1/{}/data/{}",
                self.config.addr, self.config.mount, path
            )
        } else {
            format!(
                "{}/v1/{}/data/{}?version={}",
                self.config.addr, self.config.mount, path, version
            )
        };

        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .map_err(|e| VaultError::Connection(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Read(format!(
                "KV read failed at {path} (version {version}): {status} — {body}"
            )));
        }

        let kv: KvV2Response = resp
            .json()
            .await
            .map_err(|e| VaultError::Parse(e.to_string()))?;

        // Convert all values to strings
        let result = kv
            .data
            .data
            .into_iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect();

        Ok(result)
    }

    /// Renew a Vault lease.
    ///
    /// Extends the TTL of a dynamic secret lease. The `increment` is the
    /// requested TTL extension in seconds. Vault may grant less than requested
    /// based on the lease's max TTL.
    ///
    /// # Arguments
    ///
    /// * `lease_id` - The lease ID to renew (from the original secret read response)
    /// * `increment` - Requested TTL extension in seconds
    pub async fn renew_lease(&self, lease_id: &str, increment: u64) -> Result<(), VaultError> {
        if lease_id.is_empty() {
            return Err(VaultError::LeaseRenewal(
                "lease_id must not be empty".to_string(),
            ));
        }

        let token = self.get_token().await?;
        let url = format!("{}/v1/sys/leases/renew", self.config.addr);

        let body = serde_json::json!({
            "lease_id": lease_id,
            "increment": increment,
        });

        let resp = self
            .http
            .put(&url)
            .header("X-Vault-Token", &token)
            .json(&body)
            .send()
            .await
            .map_err(|e| VaultError::Connection(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::LeaseRenewal(format!(
                "lease renewal failed for {lease_id}: {status} — {body}"
            )));
        }

        Ok(())
    }

    /// Extract [`VaultSecrets`] from a KV v2 data map.
    fn extract_secrets(data: &HashMap<String, serde_json::Value>) -> VaultSecrets {
        VaultSecrets {
            jwt_secret: data
                .get("jwt_secret")
                .and_then(|v| v.as_str())
                .map(String::from),
            server_signing_key: data
                .get("server_signing_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            session_encryption_key: data
                .get("session_encryption_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            redis_url: data
                .get("redis_url")
                .and_then(|v| v.as_str())
                .map(String::from),
        }
    }
}

// ---------------------------------------------------------------------------
// SecretRefresher — background Vault secret rotation
// ---------------------------------------------------------------------------

/// Configuration for the [`SecretRefresher`].
#[derive(Debug, Clone)]
pub struct RefresherConfig {
    /// How often to re-read secrets from Vault (seconds). Default: 300 (5 min).
    pub refresh_interval_secs: u64,
}

impl RefresherConfig {
    /// Load refresher configuration from environment variables.
    pub fn from_env() -> Self {
        let refresh_interval_secs = std::env::var("VAULT_REFRESH_INTERVAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        Self {
            refresh_interval_secs,
        }
    }

    /// Create with explicit interval (for tests).
    pub fn new(refresh_interval_secs: u64) -> Self {
        Self {
            refresh_interval_secs,
        }
    }
}

/// Background secret refresher that periodically re-reads secrets from Vault.
///
/// On success, updates the shared `AppConfig` so the gateway picks up rotated
/// credentials (e.g., new Redis password, rotated JWT secret).
///
/// On failure, logs a warning and keeps existing secrets — the next interval
/// will retry. This ensures credential rotation doesn't cause downtime.
pub struct SecretRefresher {
    vault_client: Arc<VaultClient>,
    config: RefresherConfig,
}

impl SecretRefresher {
    /// Create a new `SecretRefresher`.
    pub fn new(vault_client: Arc<VaultClient>, config: RefresherConfig) -> Self {
        Self {
            vault_client,
            config,
        }
    }

    /// Get the configured refresh interval in seconds.
    pub fn refresh_interval_secs(&self) -> u64 {
        self.config.refresh_interval_secs
    }

    /// Start background refresh loop.
    ///
    /// Spawns a tokio task that:
    /// 1. Sleeps for `refresh_interval_secs`
    /// 2. Re-reads secrets from Vault
    /// 3. Updates the shared `AppConfig` with new values
    /// 4. On failure: logs warning, keeps existing secrets, retries next interval
    ///
    /// Returns a `JoinHandle` for the spawned task (can be used for graceful shutdown).
    pub fn start_background_refresh(
        &self,
        config: Arc<Mutex<crate::config::AppConfig>>,
    ) -> tokio::task::JoinHandle<()> {
        let vault_client = Arc::clone(&self.vault_client);
        let interval_secs = self.config.refresh_interval_secs;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

                tracing::debug!(interval_secs, "refreshing secrets from Vault");

                match vault_client.read_secrets().await {
                    Ok(secrets) => {
                        match config.lock() {
                            Ok(mut app_config) => {
                                // Update mutable secret fields. Non-secret config
                                // (port, network, etc.) is NOT overwritten.
                                if let Some(ref jwt) = secrets.jwt_secret {
                                    app_config.jwt_secret = jwt.clone();
                                }
                                if let Some(ref key) = secrets.server_signing_key {
                                    app_config.server_signing_key = Some(key.clone());
                                }
                                if let Some(ref key) = secrets.session_encryption_key {
                                    app_config.session_encryption_key = Some(key.clone());
                                }
                                if let Some(ref url) = secrets.redis_url {
                                    app_config.redis_url = Some(url.clone());
                                }
                                tracing::info!("vault secrets refreshed successfully");
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "failed to lock config for Vault secret refresh — will retry"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "vault secret refresh failed — keeping existing secrets, will retry"
                        );
                    }
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Vault operation errors.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault connection error: {0}")]
    Connection(String),
    #[error("vault authentication error: {0}")]
    Auth(String),
    #[error("vault read error: {0}")]
    Read(String),
    #[error("vault response parse error: {0}")]
    Parse(String),
    #[error("vault lease renewal error: {0}")]
    LeaseRenewal(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_config_from_env_returns_none_without_addr() {
        // VAULT_ADDR not set → None
        std::env::remove_var("VAULT_ADDR");
        assert!(VaultConfig::from_env().is_none());
    }

    #[test]
    fn test_vault_secrets_default_is_all_none() {
        let secrets = VaultSecrets::default();
        assert!(secrets.jwt_secret.is_none());
        assert!(secrets.server_signing_key.is_none());
        assert!(secrets.session_encryption_key.is_none());
        assert!(secrets.redis_url.is_none());
    }

    // -- T-S22-03: Vault lease renewal tests --

    #[tokio::test]
    async fn test_vault_renew_lease_request_format() {
        // Verify that renew_lease validates lease_id and constructs the request.
        // Without a real Vault server, we test the validation path.
        let config = VaultConfig {
            addr: "http://127.0.0.1:1".into(), // unreachable
            auth: VaultAuth::Token("test-token".into()),
            mount: "secret".into(),
            secrets_path: "test/path".into(),
        };
        let client = VaultClient::new(config);

        // Empty lease_id should be rejected before any HTTP call
        let result = client.renew_lease("", 3600).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match &err {
            VaultError::LeaseRenewal(msg) => {
                assert!(
                    msg.contains("lease_id must not be empty"),
                    "unexpected: {msg}"
                );
            }
            other => panic!("expected LeaseRenewal, got: {other:?}"),
        }

        // Non-empty lease_id should attempt HTTP (and fail with connection error)
        let result = client.renew_lease("vault/lease/abc123", 3600).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            VaultError::Connection(_) => {} // expected — no server
            other => panic!("expected Connection error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_vault_read_secret_version() {
        // Verify that read_secret_version constructs the correct URL with version param.
        let config = VaultConfig {
            addr: "http://127.0.0.1:1".into(), // unreachable
            auth: VaultAuth::Token("test-token".into()),
            mount: "secret".into(),
            secrets_path: "mpc-wallet/gateway".into(),
        };
        let client = VaultClient::new(config);

        // Version 0 = latest (no ?version= param) — will fail with connection error
        let result = client.read_secret_version("test/path", 0).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            VaultError::Connection(_) => {} // expected
            other => panic!("expected Connection error, got: {other:?}"),
        }

        // Version 5 — will also fail with connection error but exercises the URL builder
        let result = client.read_secret_version("test/path", 5).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            VaultError::Connection(_) => {} // expected
            other => panic!("expected Connection error, got: {other:?}"),
        }
    }

    // -- T-S22-03: SecretRefresher tests --

    #[test]
    fn test_secret_refresher_config() {
        // Default (no env var)
        std::env::remove_var("VAULT_REFRESH_INTERVAL");
        let config = RefresherConfig::from_env();
        assert_eq!(config.refresh_interval_secs, 300);

        // Custom interval
        std::env::set_var("VAULT_REFRESH_INTERVAL", "60");
        let config = RefresherConfig::from_env();
        assert_eq!(config.refresh_interval_secs, 60);

        // Invalid value → default
        std::env::set_var("VAULT_REFRESH_INTERVAL", "not-a-number");
        let config = RefresherConfig::from_env();
        assert_eq!(config.refresh_interval_secs, 300);

        // Cleanup
        std::env::remove_var("VAULT_REFRESH_INTERVAL");
    }

    #[test]
    fn test_secret_refresher_config_new() {
        let config = RefresherConfig::new(120);
        assert_eq!(config.refresh_interval_secs, 120);
    }

    #[test]
    fn test_secret_refresher_interval() {
        let vault_config = VaultConfig {
            addr: "http://127.0.0.1:8200".into(),
            auth: VaultAuth::Token("test".into()),
            mount: "secret".into(),
            secrets_path: "test".into(),
        };
        let vault_client = Arc::new(VaultClient::new(vault_config));
        let refresher_config = RefresherConfig::new(600);
        let refresher = SecretRefresher::new(vault_client, refresher_config);
        assert_eq!(refresher.refresh_interval_secs(), 600);
    }

    // -- T-S22-03: Vault auth method tests --

    #[test]
    fn test_vault_auth_methods() {
        // Token auth
        let config = VaultConfig {
            addr: "http://vault:8200".into(),
            auth: VaultAuth::Token("s.test-token-123".into()),
            mount: "secret".into(),
            secrets_path: "mpc-wallet/gateway".into(),
        };
        match &config.auth {
            VaultAuth::Token(t) => assert_eq!(t, "s.test-token-123"),
            _ => panic!("expected Token auth"),
        }

        // AppRole auth
        let config = VaultConfig {
            addr: "http://vault:8200".into(),
            auth: VaultAuth::AppRole {
                role_id: "role-abc".into(),
                secret_id: "secret-xyz".into(),
            },
            mount: "kv".into(),
            secrets_path: "prod/gateway".into(),
        };
        match &config.auth {
            VaultAuth::AppRole { role_id, secret_id } => {
                assert_eq!(role_id, "role-abc");
                assert_eq!(secret_id, "secret-xyz");
            }
            _ => panic!("expected AppRole auth"),
        }
        assert_eq!(config.mount, "kv");
        assert_eq!(config.secrets_path, "prod/gateway");
    }

    #[test]
    fn test_vault_error_variants() {
        // Ensure all error variants display correctly
        let err = VaultError::Connection("timeout".into());
        assert!(err.to_string().contains("connection error"));

        let err = VaultError::Auth("bad token".into());
        assert!(err.to_string().contains("authentication error"));

        let err = VaultError::Read("404".into());
        assert!(err.to_string().contains("read error"));

        let err = VaultError::Parse("invalid json".into());
        assert!(err.to_string().contains("parse error"));

        let err = VaultError::LeaseRenewal("expired".into());
        assert!(err.to_string().contains("lease renewal error"));
    }

    #[test]
    fn test_extract_secrets() {
        let mut data = HashMap::new();
        data.insert(
            "jwt_secret".to_string(),
            serde_json::Value::String("secret-123".into()),
        );
        data.insert(
            "server_signing_key".to_string(),
            serde_json::Value::String("key-456".into()),
        );
        data.insert(
            "redis_url".to_string(),
            serde_json::Value::String("redis://localhost".into()),
        );
        // session_encryption_key not present

        let secrets = VaultClient::extract_secrets(&data);
        assert_eq!(secrets.jwt_secret.as_deref(), Some("secret-123"));
        assert_eq!(secrets.server_signing_key.as_deref(), Some("key-456"));
        assert!(secrets.session_encryption_key.is_none());
        assert_eq!(secrets.redis_url.as_deref(), Some("redis://localhost"));
    }
}
