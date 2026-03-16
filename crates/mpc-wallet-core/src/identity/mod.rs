//! JWT token validation and identity extraction (Epic A1, FR-A.1).
//!
//! Validates RS256 and ES256 JWT tokens, extracts claims, and produces
//! an [`AuthContext`](crate::rbac::AuthContext) for RBAC permission checks.
//!
//! # Sprint 8 scope
//! - JWT parsing and signature verification with pre-loaded keys
//! - Claims extraction: `sub`, `exp`, `roles`
//! - Integration with RBAC `AuthContext`
//!
//! # Not in Sprint 8
//! - JWKS HTTP fetching (Epic A1 full -- requires `reqwest`)
//! - ABAC attribute extraction (Epic A3)
//! - MFA claim checking (Epic A4)

use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::rbac::{ApiRole, AuthContext};

/// Standard JWT claims extracted from validated tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject -- unique user identifier (maps to `AuthContext.user_id`).
    pub sub: String,
    /// Expiration time (Unix timestamp, seconds).
    pub exp: u64,
    /// Issued-at time (Unix timestamp, seconds).
    #[serde(default)]
    pub iat: u64,
    /// Issuer identifier (OIDC provider URL).
    #[serde(default)]
    pub iss: String,
    /// Audience (expected service identifier).
    #[serde(default)]
    pub aud: Option<String>,
    /// Roles claim -- maps to RBAC `ApiRole` values.
    /// Expected values: "initiator", "approver", "admin"
    #[serde(default)]
    pub roles: Vec<String>,
}

/// JWT validator that verifies tokens against pre-loaded keys.
///
/// Supports RS256 (RSA), ES256 (ECDSA P-256), and HS256 (HMAC, testing only).
/// After validation, produces an [`AuthContext`] with the user identity and
/// mapped RBAC roles.
pub struct JwtValidator {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtValidator {
    /// Create a validator from an RSA public key in PEM format (for RS256).
    pub fn from_rsa_pem(pem: &[u8]) -> Result<Self, CoreError> {
        let key = DecodingKey::from_rsa_pem(pem)
            .map_err(|e| CoreError::Unauthorized(format!("invalid RSA PEM key: {e}")))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.validate_aud = false; // audience validation optional
        Ok(Self {
            decoding_key: key,
            validation,
        })
    }

    /// Create a validator from an EC public key in PEM format (for ES256).
    pub fn from_ec_pem(pem: &[u8]) -> Result<Self, CoreError> {
        let key = DecodingKey::from_ec_pem(pem)
            .map_err(|e| CoreError::Unauthorized(format!("invalid EC PEM key: {e}")))?;
        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = true;
        validation.validate_aud = false;
        Ok(Self {
            decoding_key: key,
            validation,
        })
    }

    /// Create a validator from an HMAC secret (for HS256, testing only).
    ///
    /// **WARNING:** HS256 is symmetric -- use only for testing. Production
    /// should use RS256 or ES256 with asymmetric keys.
    pub fn from_hmac_secret(secret: &[u8]) -> Self {
        let key = DecodingKey::from_secret(secret);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_aud = false;
        Self {
            decoding_key: key,
            validation,
        }
    }

    /// Set the expected issuer for validation.
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.validation.set_issuer(&[issuer]);
        self
    }

    /// Set the expected audience for validation.
    pub fn with_audience(mut self, audience: &str) -> Self {
        self.validation.set_audience(&[audience]);
        self
    }

    /// Validate a JWT token and extract an `AuthContext`.
    ///
    /// # Returns
    /// - `Ok(AuthContext)` with user_id from `sub` claim and mapped roles
    /// - `Err(CoreError::Unauthorized)` if token is invalid, expired, or signature fails
    ///
    /// # Security
    /// - Signature is verified before claims are trusted
    /// - Expiration (`exp`) is always checked
    /// - No JWT payload details are included in error messages (leak prevention)
    pub fn validate(&self, token: &str) -> Result<AuthContext, CoreError> {
        let token_data: TokenData<TokenClaims> =
            decode(token, &self.decoding_key, &self.validation)
                .map_err(|e| CoreError::Unauthorized(format!("JWT validation failed: {e}")))?;

        let claims = token_data.claims;
        let roles = map_roles(&claims.roles);

        Ok(AuthContext::new(claims.sub, roles))
    }

    /// Validate a JWT token and return the raw claims (for advanced use).
    pub fn validate_claims(&self, token: &str) -> Result<TokenClaims, CoreError> {
        let token_data: TokenData<TokenClaims> =
            decode(token, &self.decoding_key, &self.validation)
                .map_err(|e| CoreError::Unauthorized(format!("JWT validation failed: {e}")))?;
        Ok(token_data.claims)
    }
}

/// Map string role names from JWT claims to `ApiRole` enum values.
///
/// Unknown role strings are silently ignored (logged in production).
fn map_roles(role_strings: &[String]) -> Vec<ApiRole> {
    role_strings
        .iter()
        .filter_map(|s| match s.as_str() {
            "initiator" => Some(ApiRole::Initiator),
            "approver" => Some(ApiRole::Approver),
            "admin" => Some(ApiRole::Admin),
            _ => None, // Unknown roles ignored
        })
        .collect()
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn make_token(claims: &TokenClaims, secret: &[u8]) -> String {
        encode(
            &Header::default(), // HS256
            claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn future_exp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600 // 1 hour from now
    }

    fn past_exp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600 // 1 hour ago
    }

    #[test]
    fn test_validate_valid_token() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "alice".into(),
            exp: future_exp(),
            iat: 0,
            iss: "".into(),
            aud: None,
            roles: vec!["initiator".into()],
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret(secret);
        let ctx = validator.validate(&token).unwrap();
        assert_eq!(ctx.user_id, "alice");
        assert!(ctx.has_role(ApiRole::Initiator));
    }

    #[test]
    fn test_validate_multiple_roles() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "admin-user".into(),
            exp: future_exp(),
            iat: 0,
            iss: "".into(),
            aud: None,
            roles: vec!["initiator".into(), "admin".into()],
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret(secret);
        let ctx = validator.validate(&token).unwrap();
        assert!(ctx.has_role(ApiRole::Initiator));
        assert!(ctx.has_role(ApiRole::Admin));
        assert!(!ctx.has_role(ApiRole::Approver));
    }

    #[test]
    fn test_expired_token_rejected() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "alice".into(),
            exp: past_exp(),
            iat: 0,
            iss: "".into(),
            aud: None,
            roles: vec!["initiator".into()],
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret(secret);
        let result = validator.validate(&token);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("JWT validation failed"));
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "alice".into(),
            exp: future_exp(),
            iat: 0,
            iss: "".into(),
            aud: None,
            roles: vec!["initiator".into()],
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret(b"wrong-secret-completely-different");
        assert!(validator.validate(&token).is_err());
    }

    #[test]
    fn test_unknown_roles_ignored() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "bob".into(),
            exp: future_exp(),
            iat: 0,
            iss: "".into(),
            aud: None,
            roles: vec![
                "initiator".into(),
                "unknown_role".into(),
                "super_admin".into(),
            ],
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret(secret);
        let ctx = validator.validate(&token).unwrap();
        assert_eq!(ctx.roles.len(), 1); // only "initiator" mapped
        assert!(ctx.has_role(ApiRole::Initiator));
    }

    #[test]
    fn test_map_roles_all_variants() {
        let roles = vec!["initiator".into(), "approver".into(), "admin".into()];
        let mapped = map_roles(&roles);
        assert_eq!(mapped.len(), 3);
        assert!(mapped.contains(&ApiRole::Initiator));
        assert!(mapped.contains(&ApiRole::Approver));
        assert!(mapped.contains(&ApiRole::Admin));
    }

    #[test]
    fn test_validate_claims_returns_raw() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "alice".into(),
            exp: future_exp(),
            iat: 12345,
            iss: "test-issuer".into(),
            aud: Some("my-app".into()),
            roles: vec!["admin".into()],
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret(secret);
        let raw = validator.validate_claims(&token).unwrap();
        assert_eq!(raw.sub, "alice");
        assert_eq!(raw.iss, "test-issuer");
        assert_eq!(raw.iat, 12345);
    }

    #[test]
    fn test_invalid_token_format_rejected() {
        let validator = JwtValidator::from_hmac_secret(b"secret");
        assert!(validator.validate("not.a.valid.jwt.token").is_err());
        assert!(validator.validate("").is_err());
        assert!(validator.validate("garbage").is_err());
    }

    #[test]
    fn test_with_issuer_validation() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "alice".into(),
            exp: future_exp(),
            iat: 0,
            iss: "https://auth.example.com".into(),
            aud: None,
            roles: vec![],
        };
        let token = make_token(&claims, secret);

        // Correct issuer passes
        let validator =
            JwtValidator::from_hmac_secret(secret).with_issuer("https://auth.example.com");
        assert!(validator.validate(&token).is_ok());

        // Wrong issuer fails
        let validator =
            JwtValidator::from_hmac_secret(secret).with_issuer("https://wrong.example.com");
        assert!(validator.validate(&token).is_err());
    }
}
