//! Role-based and attribute-based access control (Epic A).
//!
//! Provides [`ApiRole`] for RBAC, [`AbacAttributes`] for attribute-based checks,
//! [`AuthContext`] combining both, and [`Permissions`] for authorization gates.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// API roles assignable to users (FR-A.1 RBAC).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiRole {
    /// Full administrative access.
    Admin,
    /// Can initiate signing requests.
    Initiator,
    /// Can approve signing requests (checker role).
    Approver,
    /// Read-only viewer.
    Viewer,
}

/// ABAC attributes extracted from JWT claims (Epic A3, FR-A.3).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AbacAttributes {
    /// Department the user belongs to.
    pub dept: Option<String>,
    /// Cost center code.
    pub cost_center: Option<String>,
    /// Risk tier: "low", "medium", "high".
    pub risk_tier: Option<String>,
}

/// Combined authentication/authorization context for a request.
///
/// Built from a validated JWT by [`crate::identity::JwtValidator`].
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The `sub` claim from the JWT.
    pub user_id: String,
    /// RBAC roles mapped from JWT `roles` claim.
    pub roles: Vec<ApiRole>,
    /// ABAC attributes from JWT (Epic A3).
    pub attributes: AbacAttributes,
    /// MFA verification status (Epic A4).
    pub mfa_verified: bool,
    /// Team-scoped roles: team_id -> roles granted in that team.
    pub team_roles: HashMap<String, Vec<ApiRole>>,
}

impl AuthContext {
    /// Create an `AuthContext` with default (empty) ABAC attributes and no MFA.
    ///
    /// Backward-compatible constructor used by existing code that only needs RBAC.
    pub fn new(user_id: impl Into<String>, roles: Vec<ApiRole>) -> Self {
        Self {
            user_id: user_id.into(),
            roles,
            attributes: AbacAttributes::default(),
            mfa_verified: false,
            team_roles: HashMap::new(),
        }
    }

    /// Create with full ABAC attributes and MFA status.
    pub fn with_attributes(
        user_id: impl Into<String>,
        roles: Vec<ApiRole>,
        attributes: AbacAttributes,
        mfa_verified: bool,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            roles,
            attributes,
            mfa_verified,
            team_roles: HashMap::new(),
        }
    }

    /// Check whether this user has the given role in a specific team.
    ///
    /// Global admins implicitly have access to every team.
    pub fn has_team_role(&self, team_id: &str, role: ApiRole) -> bool {
        // Global admin overrides — admin has every role in every team.
        if self.roles.contains(&ApiRole::Admin) {
            return true;
        }
        self.team_roles
            .get(team_id)
            .map(|roles| roles.contains(&role))
            .unwrap_or(false)
    }
}

/// Authorization permission checks.
pub struct Permissions;

impl Permissions {
    /// Check whether a user has any of the required roles.
    pub fn require_role(ctx: &AuthContext, required: &[ApiRole]) -> Result<(), CoreError> {
        if ctx.roles.iter().any(|r| required.contains(r)) {
            Ok(())
        } else {
            Err(CoreError::Unauthorized(format!(
                "user '{}' lacks required role",
                ctx.user_id
            )))
        }
    }

    /// Check: does the user's risk tier allow high-value operations?
    /// Users with risk_tier "high" are blocked from large transactions.
    pub fn check_risk_tier_for_signing(ctx: &AuthContext) -> Result<(), CoreError> {
        if ctx.attributes.risk_tier.as_deref() == Some("high") {
            return Err(CoreError::Unauthorized(
                "high risk-tier users cannot initiate signing".into(),
            ));
        }
        Ok(())
    }

    /// Check whether the user has the required role in a specific team.
    ///
    /// Global admins pass this check for any team.
    pub fn check_team_access(
        ctx: &AuthContext,
        team_id: &str,
        required: ApiRole,
    ) -> Result<(), CoreError> {
        if ctx.has_team_role(team_id, required) {
            Ok(())
        } else {
            Err(CoreError::Unauthorized(format!(
                "user '{}' lacks required role in team '{}'",
                ctx.user_id, team_id
            )))
        }
    }

    /// Admin + MFA: manage signing policy (Epic A4).
    pub fn can_manage_policy_mfa(ctx: &AuthContext) -> Result<(), CoreError> {
        Self::require_role(ctx, &[ApiRole::Admin])?;
        require_mfa(ctx)
    }

    /// Admin + MFA: freeze/unfreeze key groups (Epic A4).
    pub fn can_freeze_key_mfa(ctx: &AuthContext) -> Result<(), CoreError> {
        Self::require_role(ctx, &[ApiRole::Admin])?;
        require_mfa(ctx)
    }

    /// Admin + MFA: export audit evidence packs (Epic A4).
    pub fn can_export_evidence_mfa(ctx: &AuthContext) -> Result<(), CoreError> {
        Self::require_role(ctx, &[ApiRole::Admin])?;
        require_mfa(ctx)
    }
}

/// Require the authenticated user to have completed MFA verification (Epic A4).
pub fn require_mfa(ctx: &AuthContext) -> Result<(), CoreError> {
    if ctx.mfa_verified {
        Ok(())
    } else {
        Err(CoreError::Unauthorized(
            "MFA verification required for this operation".into(),
        ))
    }
}

/// Map raw string role names from JWT to [`ApiRole`] variants.
///
/// Unknown role strings are silently ignored.
pub fn map_roles(raw: &[String]) -> Vec<ApiRole> {
    raw.iter()
        .filter_map(|s| match s.as_str() {
            "admin" => Some(ApiRole::Admin),
            "initiator" => Some(ApiRole::Initiator),
            "approver" => Some(ApiRole::Approver),
            "viewer" => Some(ApiRole::Viewer),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_risk_tier_blocked_from_signing() {
        let ctx = AuthContext::with_attributes(
            "alice",
            vec![ApiRole::Initiator],
            AbacAttributes {
                dept: None,
                cost_center: None,
                risk_tier: Some("high".into()),
            },
            false,
        );
        assert!(Permissions::check_risk_tier_for_signing(&ctx).is_err());
    }

    #[test]
    fn test_low_risk_tier_allowed_signing() {
        let ctx = AuthContext::with_attributes(
            "bob",
            vec![ApiRole::Initiator],
            AbacAttributes {
                dept: None,
                cost_center: None,
                risk_tier: Some("low".into()),
            },
            false,
        );
        assert!(Permissions::check_risk_tier_for_signing(&ctx).is_ok());
    }

    #[test]
    fn test_auth_context_new_has_default_attributes() {
        let ctx = AuthContext::new("alice", vec![ApiRole::Admin]);
        assert!(ctx.attributes.dept.is_none());
        assert!(ctx.attributes.cost_center.is_none());
        assert!(ctx.attributes.risk_tier.is_none());
        assert!(!ctx.mfa_verified);
    }

    #[test]
    fn test_map_roles_known_and_unknown() {
        let raw = vec![
            "admin".into(),
            "initiator".into(),
            "unknown_role".into(),
            "viewer".into(),
        ];
        let roles = map_roles(&raw);
        assert_eq!(
            roles,
            vec![ApiRole::Admin, ApiRole::Initiator, ApiRole::Viewer]
        );
    }

    #[test]
    fn test_require_role_pass() {
        let ctx = AuthContext::new("alice", vec![ApiRole::Admin]);
        assert!(Permissions::require_role(&ctx, &[ApiRole::Admin, ApiRole::Viewer]).is_ok());
    }

    #[test]
    fn test_require_role_fail() {
        let ctx = AuthContext::new("bob", vec![ApiRole::Viewer]);
        assert!(Permissions::require_role(&ctx, &[ApiRole::Admin]).is_err());
    }

    #[test]
    fn test_require_mfa_passes() {
        let ctx = AuthContext::with_attributes(
            "alice",
            vec![ApiRole::Admin],
            AbacAttributes::default(),
            true,
        );
        assert!(require_mfa(&ctx).is_ok());
    }

    #[test]
    fn test_require_mfa_fails() {
        let ctx = AuthContext::new("alice", vec![ApiRole::Admin]);
        assert!(require_mfa(&ctx).is_err());
    }

    #[test]
    fn test_admin_with_mfa_can_manage_policy() {
        let ctx = AuthContext::with_attributes(
            "admin",
            vec![ApiRole::Admin],
            AbacAttributes::default(),
            true,
        );
        assert!(Permissions::can_manage_policy_mfa(&ctx).is_ok());
    }

    #[test]
    fn test_admin_without_mfa_cannot_manage_policy() {
        let ctx = AuthContext::new("admin", vec![ApiRole::Admin]);
        assert!(Permissions::can_manage_policy_mfa(&ctx).is_err());
    }

    #[test]
    fn test_non_admin_with_mfa_cannot_manage_policy() {
        let ctx = AuthContext::with_attributes(
            "alice",
            vec![ApiRole::Initiator],
            AbacAttributes::default(),
            true,
        );
        assert!(Permissions::can_manage_policy_mfa(&ctx).is_err());
    }

    // -----------------------------------------------------------------------
    // Team-scoped RBAC tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_team_role_check_pass() {
        let mut ctx = AuthContext::new("alice", vec![ApiRole::Viewer]);
        ctx.team_roles
            .insert("team-1".into(), vec![ApiRole::Initiator]);
        assert!(ctx.has_team_role("team-1", ApiRole::Initiator));
        assert!(Permissions::check_team_access(&ctx, "team-1", ApiRole::Initiator).is_ok());
    }

    #[test]
    fn test_team_role_check_fail() {
        let mut ctx = AuthContext::new("bob", vec![ApiRole::Viewer]);
        ctx.team_roles
            .insert("team-1".into(), vec![ApiRole::Viewer]);
        assert!(!ctx.has_team_role("team-1", ApiRole::Admin));
        assert!(Permissions::check_team_access(&ctx, "team-1", ApiRole::Admin).is_err());
    }

    #[test]
    fn test_team_role_different_team() {
        let mut ctx = AuthContext::new("carol", vec![ApiRole::Viewer]);
        ctx.team_roles
            .insert("team-a".into(), vec![ApiRole::Initiator]);
        // Role in team-a does NOT grant access to team-b.
        assert!(!ctx.has_team_role("team-b", ApiRole::Initiator));
        assert!(Permissions::check_team_access(&ctx, "team-b", ApiRole::Initiator).is_err());
    }

    #[test]
    fn test_team_role_admin_overrides() {
        // Global admin should have access to ANY team, even without explicit team_roles.
        let ctx = AuthContext::new("super-admin", vec![ApiRole::Admin]);
        assert!(ctx.has_team_role("team-x", ApiRole::Initiator));
        assert!(ctx.has_team_role("team-x", ApiRole::Approver));
        assert!(ctx.has_team_role("team-x", ApiRole::Admin));
        assert!(Permissions::check_team_access(&ctx, "team-x", ApiRole::Initiator).is_ok());
    }

    #[test]
    fn test_empty_team_roles_default() {
        // User with no team roles should fail team access checks.
        let ctx = AuthContext::new("dave", vec![ApiRole::Initiator]);
        assert!(!ctx.has_team_role("team-1", ApiRole::Initiator));
        assert!(Permissions::check_team_access(&ctx, "team-1", ApiRole::Initiator).is_err());
    }

    #[test]
    fn test_admin_mfa_freeze_and_export() {
        let ctx_mfa = AuthContext::with_attributes(
            "admin",
            vec![ApiRole::Admin],
            AbacAttributes::default(),
            true,
        );
        let ctx_no_mfa = AuthContext::new("admin", vec![ApiRole::Admin]);

        assert!(Permissions::can_freeze_key_mfa(&ctx_mfa).is_ok());
        assert!(Permissions::can_freeze_key_mfa(&ctx_no_mfa).is_err());
        assert!(Permissions::can_export_evidence_mfa(&ctx_mfa).is_ok());
        assert!(Permissions::can_export_evidence_mfa(&ctx_no_mfa).is_err());
    }
}
