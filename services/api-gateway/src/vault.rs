//! HashiCorp Vault integration for production secrets management.
//!
//! Reads secrets from Vault KV v2 engine via HTTP API.
//! Supports both token auth and AppRole auth.
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

/// Vault client for reading secrets.
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

    /// Read secrets from Vault KV v2.
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

        let data = &kv.data.data;

        Ok(VaultSecrets {
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
        })
    }
}

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
}

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
}
