//! Role-Based Access Control (RBAC) with MFA step-up enforcement.
//!
//! Provides [`AuthContext`] for authenticated request context, [`ApiRole`] for
//! role definitions, [`Permissions`] for role-gated checks, and [`require_mfa`]
//! for MFA step-up enforcement on admin-level operations.

use crate::error::CoreError;

/// API roles that can be assigned to users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiRole {
    /// Full administrative access — policy management, key freeze, evidence export.
    Admin,
    /// Can initiate signing requests.
    Initiator,
    /// Can approve signing requests (checker role in maker/checker flow).
    Approver,
    /// Read-only access to audit logs and status.
    Viewer,
}

/// Authenticated request context extracted from a JWT or equivalent token.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The authenticated user's identifier.
    pub user_id: String,
    /// Roles assigned to the user.
    pub roles: Vec<ApiRole>,
    /// Whether the user has completed MFA verification for this session.
    /// Defaults to `false`; must be explicitly set to `true` when MFA is verified.
    pub mfa_verified: bool,
}

impl AuthContext {
    /// Create a new `AuthContext` with MFA defaulting to `false`.
    pub fn new(user_id: &str, roles: Vec<ApiRole>) -> Self {
        Self {
            user_id: user_id.to_string(),
            roles,
            mfa_verified: false,
        }
    }
}

/// Check that the user holds a specific role.
pub fn require_role(ctx: &AuthContext, role: ApiRole) -> Result<(), CoreError> {
    if ctx.roles.contains(&role) {
        Ok(())
    } else {
        Err(CoreError::Unauthorized(format!(
            "required role {:?} not found for user {}",
            role, ctx.user_id
        )))
    }
}

/// Require the authenticated user to have completed MFA verification.
///
/// Returns `Ok(())` if `mfa_verified` is true, or `Err(CoreError::Unauthorized)`
/// with HTTP 403-style messaging if MFA is required but not verified.
pub fn require_mfa(ctx: &AuthContext) -> Result<(), CoreError> {
    if ctx.mfa_verified {
        Ok(())
    } else {
        Err(CoreError::Unauthorized(
            "MFA verification required for this operation".into(),
        ))
    }
}

/// Permission checks combining role requirements and MFA step-up.
pub struct Permissions;

impl Permissions {
    /// Check: user can initiate signing (Initiator or Admin).
    pub fn can_initiate_signing(ctx: &AuthContext) -> Result<(), CoreError> {
        if ctx.roles.contains(&ApiRole::Admin) || ctx.roles.contains(&ApiRole::Initiator) {
            Ok(())
        } else {
            Err(CoreError::Unauthorized(
                "signing initiation requires Initiator or Admin role".into(),
            ))
        }
    }

    /// Check: user can approve signing (Approver or Admin).
    pub fn can_approve_signing(ctx: &AuthContext) -> Result<(), CoreError> {
        if ctx.roles.contains(&ApiRole::Admin) || ctx.roles.contains(&ApiRole::Approver) {
            Ok(())
        } else {
            Err(CoreError::Unauthorized(
                "signing approval requires Approver or Admin role".into(),
            ))
        }
    }

    /// Check: user can manage policy (Admin only).
    pub fn can_manage_policy(ctx: &AuthContext) -> Result<(), CoreError> {
        require_role(ctx, ApiRole::Admin)
    }

    /// Check: user can freeze/unfreeze keys (Admin only).
    pub fn can_freeze_key(ctx: &AuthContext) -> Result<(), CoreError> {
        require_role(ctx, ApiRole::Admin)
    }

    /// Check: user can export audit evidence (Admin only).
    pub fn can_export_evidence(ctx: &AuthContext) -> Result<(), CoreError> {
        require_role(ctx, ApiRole::Admin)
    }

    /// Admin + MFA: manage signing policy.
    pub fn can_manage_policy_mfa(ctx: &AuthContext) -> Result<(), CoreError> {
        require_role(ctx, ApiRole::Admin)?;
        require_mfa(ctx)
    }

    /// Admin + MFA: freeze/unfreeze key groups.
    pub fn can_freeze_key_mfa(ctx: &AuthContext) -> Result<(), CoreError> {
        require_role(ctx, ApiRole::Admin)?;
        require_mfa(ctx)
    }

    /// Admin + MFA: export audit evidence packs.
    pub fn can_export_evidence_mfa(ctx: &AuthContext) -> Result<(), CoreError> {
        require_role(ctx, ApiRole::Admin)?;
        require_mfa(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MFA guard tests ──────────────────────────────────────────────

    #[test]
    fn test_require_mfa_passes_when_verified() {
        let mut ctx = AuthContext::new("alice", vec![ApiRole::Admin]);
        ctx.mfa_verified = true;
        assert!(require_mfa(&ctx).is_ok());
    }

    #[test]
    fn test_require_mfa_fails_when_not_verified() {
        let ctx = AuthContext::new("alice", vec![ApiRole::Admin]);
        // mfa_verified defaults to false
        let err = require_mfa(&ctx).unwrap_err();
        assert!(err.to_string().contains("MFA"));
    }

    #[test]
    fn test_admin_with_mfa_can_manage_policy() {
        let mut ctx = AuthContext::new("admin", vec![ApiRole::Admin]);
        ctx.mfa_verified = true;
        assert!(Permissions::can_manage_policy_mfa(&ctx).is_ok());
    }

    #[test]
    fn test_admin_without_mfa_cannot_manage_policy() {
        let ctx = AuthContext::new("admin", vec![ApiRole::Admin]);
        assert!(Permissions::can_manage_policy_mfa(&ctx).is_err());
    }

    #[test]
    fn test_non_admin_with_mfa_cannot_manage_policy() {
        let mut ctx = AuthContext::new("alice", vec![ApiRole::Initiator]);
        ctx.mfa_verified = true;
        assert!(Permissions::can_manage_policy_mfa(&ctx).is_err());
    }

    #[test]
    fn test_admin_mfa_freeze_key() {
        let mut ctx = AuthContext::new("admin", vec![ApiRole::Admin]);
        ctx.mfa_verified = true;
        assert!(Permissions::can_freeze_key_mfa(&ctx).is_ok());

        ctx.mfa_verified = false;
        assert!(Permissions::can_freeze_key_mfa(&ctx).is_err());
    }

    #[test]
    fn test_admin_mfa_export_evidence() {
        let mut ctx = AuthContext::new("admin", vec![ApiRole::Admin]);
        ctx.mfa_verified = true;
        assert!(Permissions::can_export_evidence_mfa(&ctx).is_ok());

        ctx.mfa_verified = false;
        assert!(Permissions::can_export_evidence_mfa(&ctx).is_err());
    }

    // ── Basic RBAC tests (non-MFA) ──────────────────────────────────

    #[test]
    fn test_require_role_admin() {
        let ctx = AuthContext::new("admin", vec![ApiRole::Admin]);
        assert!(require_role(&ctx, ApiRole::Admin).is_ok());
        assert!(require_role(&ctx, ApiRole::Initiator).is_err());
    }

    #[test]
    fn test_can_manage_policy_requires_admin() {
        let admin = AuthContext::new("admin", vec![ApiRole::Admin]);
        assert!(Permissions::can_manage_policy(&admin).is_ok());

        let viewer = AuthContext::new("viewer", vec![ApiRole::Viewer]);
        assert!(Permissions::can_manage_policy(&viewer).is_err());
    }

    #[test]
    fn test_can_initiate_signing() {
        let initiator = AuthContext::new("init", vec![ApiRole::Initiator]);
        assert!(Permissions::can_initiate_signing(&initiator).is_ok());

        let admin = AuthContext::new("admin", vec![ApiRole::Admin]);
        assert!(Permissions::can_initiate_signing(&admin).is_ok());

        let viewer = AuthContext::new("viewer", vec![ApiRole::Viewer]);
        assert!(Permissions::can_initiate_signing(&viewer).is_err());
    }

    #[test]
    fn test_auth_context_defaults_mfa_false() {
        let ctx = AuthContext::new("user", vec![ApiRole::Viewer]);
        assert!(!ctx.mfa_verified);
    }
}
