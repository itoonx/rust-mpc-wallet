//! Webhook notification system for MPC Wallet operations.
//!
//! Provides HMAC-SHA256 signed webhook payloads with constant-time
//! signature verification and a trait-based store for webhook configurations.

use std::sync::RwLock;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Events that can trigger webhook notifications.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WebhookEvent {
    /// A signing request has been submitted.
    SigningRequested,
    /// A signing request has been approved.
    SigningApproved,
    /// A signing operation completed successfully.
    SigningCompleted,
    /// A signing request was denied.
    SigningDenied,
    /// A policy violation was detected.
    PolicyViolated,
    /// The address whitelist was modified.
    WhitelistChanged,
}

/// Configuration for a registered webhook endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Unique identifier for this webhook registration.
    pub id: String,
    /// The URL to POST webhook payloads to.
    pub url: String,
    /// Shared secret used to sign payloads (HMAC-SHA256).
    pub secret: String,
    /// Which events this webhook subscribes to.
    pub events: Vec<WebhookEvent>,
    /// Whether this webhook is currently active.
    pub active: bool,
}

/// A webhook payload sent to registered endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// The event that triggered this notification.
    pub event: WebhookEvent,
    /// Unix timestamp (seconds) when the event occurred.
    pub timestamp: u64,
    /// Event-specific data.
    pub data: serde_json::Value,
    /// HMAC-SHA256 hex signature over the canonical JSON of this payload
    /// (computed over the payload bytes excluding this field).
    pub signature: String,
}

/// Compute HMAC-SHA256 over `payload` bytes using `secret`, returning hex-encoded signature.
pub fn sign_payload(payload: &[u8], secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify an HMAC-SHA256 signature using constant-time comparison.
///
/// Returns `true` if `signature` matches the expected HMAC-SHA256 of `payload` with `secret`.
pub fn verify_signature(payload: &[u8], secret: &str, signature: &str) -> bool {
    let expected = sign_payload(payload, secret);
    let expected_bytes = expected.as_bytes();
    let sig_bytes = signature.as_bytes();

    if expected_bytes.len() != sig_bytes.len() {
        return false;
    }

    expected_bytes.ct_eq(sig_bytes).into()
}

/// Errors returned by webhook operations.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// A webhook with this ID already exists.
    #[error("webhook already registered: {0}")]
    AlreadyRegistered(String),
    /// No webhook found with this ID.
    #[error("webhook not found: {0}")]
    NotFound(String),
    /// Delivery failed.
    #[error("delivery error: {0}")]
    DeliveryError(String),
}

/// Trait for webhook configuration storage backends.
pub trait WebhookStore: Send + Sync {
    /// Register a new webhook configuration.
    fn register(&self, config: WebhookConfig) -> Result<(), WebhookError>;
    /// Unregister a webhook by ID.
    fn unregister(&self, id: &str) -> Result<(), WebhookError>;
    /// List all registered webhooks.
    fn list(&self) -> Vec<WebhookConfig>;
    /// Get all active webhooks subscribed to a given event.
    fn get_for_event(&self, event: &WebhookEvent) -> Vec<WebhookConfig>;
}

/// In-memory webhook store backed by `RwLock<Vec<WebhookConfig>>`.
pub struct InMemoryWebhookStore {
    configs: RwLock<Vec<WebhookConfig>>,
}

impl InMemoryWebhookStore {
    /// Create a new empty webhook store.
    pub fn new() -> Self {
        Self {
            configs: RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryWebhookStore {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookStore for InMemoryWebhookStore {
    fn register(&self, config: WebhookConfig) -> Result<(), WebhookError> {
        let mut configs = self.configs.write().unwrap();
        if configs.iter().any(|c| c.id == config.id) {
            return Err(WebhookError::AlreadyRegistered(config.id.clone()));
        }
        configs.push(config);
        Ok(())
    }

    fn unregister(&self, id: &str) -> Result<(), WebhookError> {
        let mut configs = self.configs.write().unwrap();
        let len_before = configs.len();
        configs.retain(|c| c.id != id);
        if configs.len() == len_before {
            return Err(WebhookError::NotFound(id.to_string()));
        }
        Ok(())
    }

    fn list(&self) -> Vec<WebhookConfig> {
        self.configs.read().unwrap().clone()
    }

    fn get_for_event(&self, event: &WebhookEvent) -> Vec<WebhookConfig> {
        self.configs
            .read()
            .unwrap()
            .iter()
            .filter(|c| c.active && c.events.contains(event))
            .cloned()
            .collect()
    }
}

/// Deliver a webhook payload to a registered endpoint.
///
/// This is a stub implementation that validates the URL format but does not
/// perform a real HTTP POST. Real HTTP delivery is future work.
pub async fn deliver(
    config: &WebhookConfig,
    _payload: &WebhookPayload,
) -> Result<(), WebhookError> {
    // Validate URL format
    if !config.url.starts_with("http://") && !config.url.starts_with("https://") {
        return Err(WebhookError::DeliveryError(format!(
            "invalid URL scheme: {}",
            config.url
        )));
    }
    // Stub: real HTTP POST will be implemented when reqwest integration is wired.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(id: &str, events: Vec<WebhookEvent>) -> WebhookConfig {
        WebhookConfig {
            id: id.to_string(),
            url: "https://example.com/webhook".to_string(),
            secret: "test-secret-key".to_string(),
            events,
            active: true,
        }
    }

    #[test]
    fn test_register_and_list() {
        let store = InMemoryWebhookStore::new();
        store
            .register(make_config("wh-1", vec![WebhookEvent::SigningRequested]))
            .unwrap();
        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "wh-1");
    }

    #[test]
    fn test_unregister() {
        let store = InMemoryWebhookStore::new();
        store
            .register(make_config("wh-1", vec![WebhookEvent::SigningRequested]))
            .unwrap();
        store.unregister("wh-1").unwrap();
        assert!(store.list().is_empty());
    }

    #[test]
    fn test_unregister_not_found() {
        let store = InMemoryWebhookStore::new();
        let err = store.unregister("nonexistent").unwrap_err();
        assert!(matches!(err, WebhookError::NotFound(_)));
    }

    #[test]
    fn test_sign_and_verify_payload() {
        let payload = b"hello world";
        let secret = "my-secret";
        let sig = sign_payload(payload, secret);
        assert!(verify_signature(payload, secret, &sig));
    }

    #[test]
    fn test_hmac_tamper_detection() {
        let payload = b"original data";
        let secret = "my-secret";
        let sig = sign_payload(payload, secret);
        // Tamper with payload
        assert!(!verify_signature(b"tampered data", secret, &sig));
    }

    #[test]
    fn test_hmac_wrong_secret() {
        let payload = b"some data";
        let sig = sign_payload(payload, "correct-secret");
        assert!(!verify_signature(payload, "wrong-secret", &sig));
    }

    #[test]
    fn test_event_filtering() {
        let store = InMemoryWebhookStore::new();
        store
            .register(make_config(
                "wh-1",
                vec![
                    WebhookEvent::SigningRequested,
                    WebhookEvent::SigningCompleted,
                ],
            ))
            .unwrap();
        store
            .register(make_config("wh-2", vec![WebhookEvent::PolicyViolated]))
            .unwrap();

        let signing = store.get_for_event(&WebhookEvent::SigningRequested);
        assert_eq!(signing.len(), 1);
        assert_eq!(signing[0].id, "wh-1");

        let policy = store.get_for_event(&WebhookEvent::PolicyViolated);
        assert_eq!(policy.len(), 1);
        assert_eq!(policy[0].id, "wh-2");

        // Event with no subscribers
        let denied = store.get_for_event(&WebhookEvent::SigningDenied);
        assert!(denied.is_empty());
    }

    #[test]
    fn test_constant_time_verify_length_mismatch() {
        let payload = b"data";
        let secret = "secret";
        // Short signature should return false, not panic
        assert!(!verify_signature(payload, secret, "abc"));
    }

    #[tokio::test]
    async fn test_deliver_stub_valid_url() {
        let config = make_config("wh-1", vec![WebhookEvent::SigningCompleted]);
        let payload = WebhookPayload {
            event: WebhookEvent::SigningCompleted,
            timestamp: 1234567890,
            data: serde_json::json!({"tx_id": "abc"}),
            signature: "dummy".to_string(),
        };
        assert!(deliver(&config, &payload).await.is_ok());
    }

    #[tokio::test]
    async fn test_deliver_stub_invalid_url() {
        let mut config = make_config("wh-1", vec![WebhookEvent::SigningCompleted]);
        config.url = "ftp://bad-scheme.com".to_string();
        let payload = WebhookPayload {
            event: WebhookEvent::SigningCompleted,
            timestamp: 1234567890,
            data: serde_json::json!({}),
            signature: "dummy".to_string(),
        };
        let err = deliver(&config, &payload).await.unwrap_err();
        assert!(matches!(err, WebhookError::DeliveryError(_)));
    }

    #[test]
    fn test_inactive_webhook_not_returned_for_event() {
        let store = InMemoryWebhookStore::new();
        let mut config = make_config("wh-inactive", vec![WebhookEvent::SigningRequested]);
        config.active = false;
        store.register(config).unwrap();

        let result = store.get_for_event(&WebhookEvent::SigningRequested);
        assert!(result.is_empty());
    }
}
