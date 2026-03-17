//! mTLS (Mutual TLS) authentication for service-to-service communication.
//!
//! The TLS terminator (nginx, envoy, or axum-server with rustls) verifies the
//! client certificate and passes identity via headers:
//!
//! ```text
//! Service A                 TLS Terminator              API Gateway
//! ┌─────────┐  client cert  ┌────────────┐  headers    ┌───────────┐
//! │ presents │──────────────│ verify CA  │────────────│ extract   │
//! │ cert +   │  TLS handshk │ extract CN │            │ identity  │
//! │ key      │              │ fingerprint│            │ map role  │
//! └─────────┘              └────────────┘            └───────────┘
//! ```
//!
//! **Headers set by TLS terminator:**
//! - `X-Client-Cert-CN` — Common Name (e.g., `trading-service.internal`)
//! - `X-Client-Cert-Fingerprint` — SHA-256 fingerprint of the certificate
//! - `X-Client-Cert-Serial` — Certificate serial number
//! - `X-Client-Cert-Verified` — `SUCCESS` or `NONE` (nginx: `$ssl_client_verify`)
//!
//! The gateway maps the CN or fingerprint to a service identity + RBAC role
//! via the `MtlsServiceRegistry`.

use std::collections::HashMap;

use serde::Deserialize;

use mpc_wallet_core::rbac::{AbacAttributes, ApiRole, AuthContext};

use super::types::parse_role;

/// A registered mTLS service identity.
#[derive(Debug, Clone, Deserialize)]
pub struct MtlsServiceEntry {
    /// Certificate Common Name (e.g., `trading-service.internal`).
    pub cn: String,
    /// SHA-256 fingerprint of the expected certificate (hex, optional).
    /// If set, both CN and fingerprint must match.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// RBAC role for this service.
    pub role: String,
    /// Human-readable label for audit logs.
    pub label: String,
}

impl MtlsServiceEntry {
    pub fn api_role(&self) -> ApiRole {
        parse_role(&self.role)
    }

    pub fn auth_context(&self) -> AuthContext {
        AuthContext::with_attributes(
            format!("mtls:{}", self.cn),
            vec![self.api_role()],
            AbacAttributes::default(),
            false,
        )
    }
}

/// Registry of trusted mTLS service identities.
#[derive(Clone, Default)]
pub struct MtlsServiceRegistry {
    /// Map from CN → service entry.
    pub services: HashMap<String, MtlsServiceEntry>,
}

impl MtlsServiceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entries(entries: Vec<MtlsServiceEntry>) -> Self {
        let mut services = HashMap::new();
        for entry in entries {
            services.insert(entry.cn.clone(), entry);
        }
        Self { services }
    }

    /// Verify a client certificate identity.
    ///
    /// - If the registry is empty, mTLS auth is disabled (returns None).
    /// - If CN is not registered, returns None.
    /// - If fingerprint is configured and doesn't match, returns None.
    pub fn verify(&self, cn: &str, fingerprint: Option<&str>) -> Option<&MtlsServiceEntry> {
        if self.services.is_empty() {
            return None;
        }

        let entry = self.services.get(cn)?;

        // If fingerprint pinning is configured, verify it matches.
        if let Some(expected_fp) = &entry.fingerprint {
            match fingerprint {
                Some(actual_fp) if actual_fp == expected_fp => {}
                _ => return None, // fingerprint mismatch or missing
            }
        }

        Some(entry)
    }

    pub fn is_enabled(&self) -> bool {
        !self.services.is_empty()
    }
}

/// Extract mTLS identity from request headers (set by TLS terminator).
pub struct MtlsIdentity {
    pub cn: String,
    pub fingerprint: Option<String>,
    pub verified: bool,
}

impl MtlsIdentity {
    /// Extract from HTTP headers.
    pub fn from_headers(headers: &axum::http::HeaderMap) -> Option<Self> {
        // Check if TLS terminator verified the cert.
        let verified = headers
            .get("x-client-cert-verified")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "SUCCESS")
            .unwrap_or(false);

        if !verified {
            return None;
        }

        let cn = headers
            .get("x-client-cert-cn")
            .and_then(|v| v.to_str().ok())
            .map(String::from)?;

        let fingerprint = headers
            .get("x-client-cert-fingerprint")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        Some(Self {
            cn,
            fingerprint,
            verified,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> MtlsServiceRegistry {
        MtlsServiceRegistry::from_entries(vec![
            MtlsServiceEntry {
                cn: "trading-service.internal".into(),
                fingerprint: Some("sha256:abcdef1234567890".into()),
                role: "initiator".into(),
                label: "Trading Service".into(),
            },
            MtlsServiceEntry {
                cn: "monitoring.internal".into(),
                fingerprint: None, // no fingerprint pinning
                role: "viewer".into(),
                label: "Monitoring".into(),
            },
        ])
    }

    #[test]
    fn test_verify_cn_and_fingerprint() {
        let reg = test_registry();
        let entry = reg
            .verify("trading-service.internal", Some("sha256:abcdef1234567890"))
            .unwrap();
        assert_eq!(entry.role, "initiator");
        assert_eq!(entry.label, "Trading Service");
    }

    #[test]
    fn test_wrong_fingerprint_rejected() {
        let reg = test_registry();
        assert!(reg
            .verify("trading-service.internal", Some("sha256:wrong"))
            .is_none());
    }

    #[test]
    fn test_missing_fingerprint_rejected_when_required() {
        let reg = test_registry();
        assert!(reg.verify("trading-service.internal", None).is_none());
    }

    #[test]
    fn test_cn_without_fingerprint_pinning() {
        let reg = test_registry();
        let entry = reg.verify("monitoring.internal", None).unwrap();
        assert_eq!(entry.role, "viewer");
    }

    #[test]
    fn test_unknown_cn_rejected() {
        let reg = test_registry();
        assert!(reg.verify("unknown.internal", None).is_none());
    }

    #[test]
    fn test_empty_registry_disabled() {
        let reg = MtlsServiceRegistry::new();
        assert!(!reg.is_enabled());
        assert!(reg.verify("anything", None).is_none());
    }

    #[test]
    fn test_auth_context() {
        let reg = test_registry();
        let entry = reg.verify("monitoring.internal", None).unwrap();
        let ctx = entry.auth_context();
        assert_eq!(ctx.user_id, "mtls:monitoring.internal");
        assert_eq!(ctx.roles, vec![ApiRole::Viewer]);
    }
}
