//! JWT-based identity validation (Epic A).
//!
//! Provides [`JwtValidator`] to decode and validate JWTs, extracting RBAC roles
//! and ABAC attributes into an [`AuthContext`](crate::rbac::AuthContext).

use jsonwebtoken::{decode, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::rbac::{map_roles, AbacAttributes, AuthContext};

/// Claims expected in a JWT issued to MPC Wallet SDK users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (user identifier).
    pub sub: String,
    /// Expiration time (UNIX timestamp).
    pub exp: usize,
    /// Issued-at time (UNIX timestamp).
    pub iat: usize,
    /// Issuer.
    pub iss: String,
    /// Audience (optional).
    #[serde(default)]
    pub aud: Option<String>,
    /// RBAC role strings (e.g. "admin", "initiator").
    #[serde(default)]
    pub roles: Vec<String>,
    /// Department (ABAC attribute, Epic A3).
    #[serde(default)]
    pub dept: Option<String>,
    /// Cost center (ABAC attribute, Epic A3).
    #[serde(default)]
    pub cost_center: Option<String>,
    /// Risk tier: "low", "medium", "high" (ABAC attribute, Epic A3).
    #[serde(default)]
    pub risk_tier: Option<String>,
    /// MFA verified flag (Epic A4 prep).
    #[serde(default)]
    pub mfa_verified: bool,
}

/// Validates JWTs and produces [`AuthContext`] instances.
pub struct JwtValidator {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtValidator {
    /// Create a validator using an HMAC-SHA256 secret (permissive mode).
    ///
    /// Does NOT validate issuer or audience claims. Suitable for tests and
    /// backward-compatible usage. For production, use [`from_hmac_secret_strict`].
    pub fn from_hmac_secret(secret: &[u8]) -> Self {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        // Disable issuer/audience checks by default; callers can refine.
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        Self {
            decoding_key: DecodingKey::from_secret(secret),
            validation,
        }
    }

    /// Create a strict validator that enforces issuer and audience claims.
    ///
    /// Requires `exp`, `sub`, `iss`, and `aud` claims. Rejects tokens that
    /// don't match the expected issuer and audience. Use this for production.
    pub fn from_hmac_secret_strict(secret: &[u8], issuer: &str, audience: &str) -> Self {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_aud = true;
        validation.set_audience(&[audience]);
        validation.set_issuer(&[issuer]);
        validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);
        Self {
            decoding_key: DecodingKey::from_secret(secret),
            validation,
        }
    }

    /// Validate a JWT token and return an [`AuthContext`] with RBAC roles and ABAC attributes.
    pub fn validate(&self, token: &str) -> Result<AuthContext, CoreError> {
        let token_data: TokenData<TokenClaims> =
            decode(token, &self.decoding_key, &self.validation)
                .map_err(|e| CoreError::Unauthorized(format!("JWT validation failed: {e}")))?;

        let claims = token_data.claims;
        let roles = map_roles(&claims.roles);
        let attributes = AbacAttributes {
            dept: claims.dept,
            cost_center: claims.cost_center,
            risk_tier: claims.risk_tier,
        };

        Ok(AuthContext::with_attributes(
            claims.sub,
            roles,
            attributes,
            claims.mfa_verified,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    /// Helper: create a signed JWT from claims (for testing).
    fn make_token(claims: &TokenClaims, secret: &[u8]) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(secret),
        )
        .expect("encoding should not fail in tests")
    }

    /// Return an `exp` value 1 hour in the future.
    fn future_exp() -> usize {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        now + 3600
    }

    #[test]
    fn test_abac_attributes_extracted_from_jwt() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "alice".into(),
            exp: future_exp(),
            iat: 0,
            iss: "".into(),
            aud: None,
            roles: vec!["initiator".into()],
            dept: Some("engineering".into()),
            cost_center: Some("CC-001".into()),
            risk_tier: Some("low".into()),
            mfa_verified: true,
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret(secret);
        let ctx = validator.validate(&token).unwrap();
        assert_eq!(ctx.user_id, "alice");
        assert_eq!(ctx.attributes.dept.as_deref(), Some("engineering"));
        assert_eq!(ctx.attributes.cost_center.as_deref(), Some("CC-001"));
        assert_eq!(ctx.attributes.risk_tier.as_deref(), Some("low"));
        assert!(ctx.mfa_verified);
    }

    #[test]
    fn test_missing_abac_attributes_default_to_none() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "bob".into(),
            exp: future_exp(),
            iat: 0,
            iss: "".into(),
            aud: None,
            roles: vec![],
            dept: None,
            cost_center: None,
            risk_tier: None,
            mfa_verified: false,
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret(secret);
        let ctx = validator.validate(&token).unwrap();
        assert!(ctx.attributes.dept.is_none());
        assert!(ctx.attributes.cost_center.is_none());
        assert!(ctx.attributes.risk_tier.is_none());
        assert!(!ctx.mfa_verified);
    }

    #[test]
    fn test_expired_token_rejected() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "carol".into(),
            exp: 1000, // far in the past
            iat: 0,
            iss: "".into(),
            aud: None,
            roles: vec!["admin".into()],
            dept: None,
            cost_center: None,
            risk_tier: None,
            mfa_verified: false,
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret(secret);
        let result = validator.validate(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_validator_accepts_correct_iss_aud() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "alice".into(),
            exp: future_exp(),
            iat: 0,
            iss: "my-issuer".into(),
            aud: Some("my-audience".into()),
            roles: vec!["admin".into()],
            dept: None,
            cost_center: None,
            risk_tier: None,
            mfa_verified: false,
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret_strict(secret, "my-issuer", "my-audience");
        let ctx = validator.validate(&token).unwrap();
        assert_eq!(ctx.user_id, "alice");
    }

    #[test]
    fn test_strict_validator_rejects_wrong_issuer() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "alice".into(),
            exp: future_exp(),
            iat: 0,
            iss: "wrong-issuer".into(),
            aud: Some("my-audience".into()),
            roles: vec![],
            dept: None,
            cost_center: None,
            risk_tier: None,
            mfa_verified: false,
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret_strict(secret, "my-issuer", "my-audience");
        assert!(validator.validate(&token).is_err());
    }

    #[test]
    fn test_strict_validator_rejects_wrong_audience() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "alice".into(),
            exp: future_exp(),
            iat: 0,
            iss: "my-issuer".into(),
            aud: Some("wrong-audience".into()),
            roles: vec![],
            dept: None,
            cost_center: None,
            risk_tier: None,
            mfa_verified: false,
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret_strict(secret, "my-issuer", "my-audience");
        assert!(validator.validate(&token).is_err());
    }

    #[test]
    fn test_strict_validator_rejects_missing_aud() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let claims = TokenClaims {
            sub: "alice".into(),
            exp: future_exp(),
            iat: 0,
            iss: "my-issuer".into(),
            aud: None,
            roles: vec![],
            dept: None,
            cost_center: None,
            risk_tier: None,
            mfa_verified: false,
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret_strict(secret, "my-issuer", "my-audience");
        assert!(validator.validate(&token).is_err());
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let secret = b"test-secret-key-for-hmac-256-validation";
        let wrong = b"wrong-secret-key-for-hmac-256-00000000";
        let claims = TokenClaims {
            sub: "dave".into(),
            exp: future_exp(),
            iat: 0,
            iss: "".into(),
            aud: None,
            roles: vec!["viewer".into()],
            dept: None,
            cost_center: None,
            risk_tier: None,
            mfa_verified: false,
        };
        let token = make_token(&claims, secret);
        let validator = JwtValidator::from_hmac_secret(wrong);
        let result = validator.validate(&token);
        assert!(result.is_err());
    }
}
