//! Role-Based Access Control (RBAC) for MPC Wallet API operations (Epic A, FR-A.2).
//!
//! Defines three API-level roles — [`ApiRole::Initiator`], [`ApiRole::Approver`],
//! and [`ApiRole::Admin`] — and provides guard functions that check an
//! [`AuthContext`] before allowing an operation to proceed.
//!
//! # Relationship to approvals module
//!
//! The approvals module defines *session-level* roles (`Maker` / `Checker` / `Approver`)
//! for separation-of-duty within a single signing session. RBAC defines *API-level*
//! roles that control which endpoints a user can access at all.

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// API-level role for access control.
///
/// These roles are distinct from the session-level roles in the approvals module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiRole {
    /// Can create signing sessions and view audit ledger.
    Initiator,
    /// Can submit approvals for pending signing sessions.
    Approver,
    /// Full access: policy management, key freeze/unfreeze, evidence pack export.
    Admin,
}

impl std::fmt::Display for ApiRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiRole::Initiator => write!(f, "initiator"),
            ApiRole::Approver => write!(f, "approver"),
            ApiRole::Admin => write!(f, "admin"),
        }
    }
}

/// Authenticated user context for RBAC checks.
///
/// Constructed from JWT claims (Sprint 8, Epic A1) or manually for testing.
/// Passed to [`require_role`] and [`require_any_role`] guards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// Unique user identifier (e.g. from JWT `sub` claim).
    pub user_id: String,
    /// Roles assigned to this user.
    pub roles: Vec<ApiRole>,
}

impl AuthContext {
    /// Create a new auth context.
    pub fn new(user_id: impl Into<String>, roles: Vec<ApiRole>) -> Self {
        Self {
            user_id: user_id.into(),
            roles,
        }
    }

    /// Check if this context has a specific role.
    pub fn has_role(&self, role: ApiRole) -> bool {
        self.roles.contains(&role)
    }
}

/// Require the authenticated user to have a specific role.
///
/// Returns `Ok(())` if the user has the role, or `Err(CoreError::Unauthorized)`
/// with a message identifying the missing role (without leaking the user's
/// current role list).
pub fn require_role(ctx: &AuthContext, role: ApiRole) -> Result<(), CoreError> {
    if ctx.has_role(role) {
        Ok(())
    } else {
        Err(CoreError::Unauthorized(format!(
            "user '{}' requires role '{}'",
            ctx.user_id, role
        )))
    }
}

/// Require the authenticated user to have at least one of the specified roles.
///
/// Returns `Ok(())` if the user has any of the roles.
pub fn require_any_role(ctx: &AuthContext, roles: &[ApiRole]) -> Result<(), CoreError> {
    if roles.iter().any(|r| ctx.has_role(*r)) {
        Ok(())
    } else {
        let role_names: Vec<String> = roles.iter().map(|r| r.to_string()).collect();
        Err(CoreError::Unauthorized(format!(
            "user '{}' requires one of: {}",
            ctx.user_id,
            role_names.join(", ")
        )))
    }
}

/// RBAC permission definitions for standard operations.
///
/// Use these with [`require_role`] or [`require_any_role`] to guard API endpoints.
pub struct Permissions;

impl Permissions {
    /// Check: can this user create a signing session?
    /// Allowed: Initiator, Admin
    pub fn can_create_session(ctx: &AuthContext) -> Result<(), CoreError> {
        require_any_role(ctx, &[ApiRole::Initiator, ApiRole::Admin])
    }

    /// Check: can this user submit an approval?
    /// Allowed: Approver only
    pub fn can_submit_approval(ctx: &AuthContext) -> Result<(), CoreError> {
        require_role(ctx, ApiRole::Approver)
    }

    /// Check: can this user load or update a signing policy?
    /// Allowed: Admin only
    pub fn can_manage_policy(ctx: &AuthContext) -> Result<(), CoreError> {
        require_role(ctx, ApiRole::Admin)
    }

    /// Check: can this user freeze or unfreeze a key group?
    /// Allowed: Admin only
    pub fn can_freeze_key(ctx: &AuthContext) -> Result<(), CoreError> {
        require_role(ctx, ApiRole::Admin)
    }

    /// Check: can this user view the audit ledger?
    /// Allowed: Initiator, Approver, Admin
    pub fn can_view_audit(ctx: &AuthContext) -> Result<(), CoreError> {
        require_any_role(ctx, &[ApiRole::Initiator, ApiRole::Approver, ApiRole::Admin])
    }

    /// Check: can this user export an evidence pack?
    /// Allowed: Admin only
    pub fn can_export_evidence(ctx: &AuthContext) -> Result<(), CoreError> {
        require_role(ctx, ApiRole::Admin)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_require_role_allows_matching_role() {
        let ctx = AuthContext::new("alice", vec![ApiRole::Initiator]);
        assert!(require_role(&ctx, ApiRole::Initiator).is_ok());
    }

    #[test]
    fn test_require_role_rejects_non_matching_role() {
        let ctx = AuthContext::new("bob", vec![ApiRole::Initiator]);
        let err = require_role(&ctx, ApiRole::Admin).unwrap_err();
        assert!(err.to_string().contains("requires role 'admin'"));
        // Error should NOT leak user's current roles
        assert!(!err.to_string().contains("initiator"));
    }

    #[test]
    fn test_require_any_role_allows_if_any_matches() {
        let ctx = AuthContext::new("carol", vec![ApiRole::Approver]);
        assert!(require_any_role(&ctx, &[ApiRole::Initiator, ApiRole::Approver]).is_ok());
    }

    #[test]
    fn test_require_any_role_rejects_if_none_match() {
        let ctx = AuthContext::new("dave", vec![ApiRole::Initiator]);
        let err = require_any_role(&ctx, &[ApiRole::Approver, ApiRole::Admin]).unwrap_err();
        assert!(err.to_string().contains("requires one of"));
    }

    #[test]
    fn test_permissions_create_session_initiator() {
        let ctx = AuthContext::new("alice", vec![ApiRole::Initiator]);
        assert!(Permissions::can_create_session(&ctx).is_ok());
    }

    #[test]
    fn test_permissions_create_session_admin() {
        let ctx = AuthContext::new("admin", vec![ApiRole::Admin]);
        assert!(Permissions::can_create_session(&ctx).is_ok());
    }

    #[test]
    fn test_permissions_create_session_rejected_for_approver() {
        let ctx = AuthContext::new("bob", vec![ApiRole::Approver]);
        assert!(Permissions::can_create_session(&ctx).is_err());
    }

    #[test]
    fn test_permissions_submit_approval_only_approver() {
        let init = AuthContext::new("alice", vec![ApiRole::Initiator]);
        let appr = AuthContext::new("bob", vec![ApiRole::Approver]);
        let admin = AuthContext::new("admin", vec![ApiRole::Admin]);

        assert!(Permissions::can_submit_approval(&init).is_err());
        assert!(Permissions::can_submit_approval(&appr).is_ok());
        assert!(Permissions::can_submit_approval(&admin).is_err());
    }

    #[test]
    fn test_permissions_admin_only_operations() {
        let init = AuthContext::new("alice", vec![ApiRole::Initiator]);
        let admin = AuthContext::new("admin", vec![ApiRole::Admin]);

        // Policy management
        assert!(Permissions::can_manage_policy(&init).is_err());
        assert!(Permissions::can_manage_policy(&admin).is_ok());

        // Key freeze
        assert!(Permissions::can_freeze_key(&init).is_err());
        assert!(Permissions::can_freeze_key(&admin).is_ok());

        // Evidence export
        assert!(Permissions::can_export_evidence(&init).is_err());
        assert!(Permissions::can_export_evidence(&admin).is_ok());
    }

    #[test]
    fn test_permissions_view_audit_all_roles() {
        let init = AuthContext::new("alice", vec![ApiRole::Initiator]);
        let appr = AuthContext::new("bob", vec![ApiRole::Approver]);
        let admin = AuthContext::new("admin", vec![ApiRole::Admin]);

        assert!(Permissions::can_view_audit(&init).is_ok());
        assert!(Permissions::can_view_audit(&appr).is_ok());
        assert!(Permissions::can_view_audit(&admin).is_ok());
    }

    #[test]
    fn test_multi_role_user() {
        // A user can hold multiple roles
        let ctx = AuthContext::new(
            "superuser",
            vec![ApiRole::Initiator, ApiRole::Approver, ApiRole::Admin],
        );
        assert!(Permissions::can_create_session(&ctx).is_ok());
        assert!(Permissions::can_submit_approval(&ctx).is_ok());
        assert!(Permissions::can_manage_policy(&ctx).is_ok());
        assert!(Permissions::can_view_audit(&ctx).is_ok());
    }

    #[test]
    fn test_no_roles_user_rejected_everywhere() {
        let ctx = AuthContext::new("nobody", vec![]);
        assert!(Permissions::can_create_session(&ctx).is_err());
        assert!(Permissions::can_submit_approval(&ctx).is_err());
        assert!(Permissions::can_manage_policy(&ctx).is_err());
        assert!(Permissions::can_view_audit(&ctx).is_err());
    }

    #[test]
    fn test_api_role_display() {
        assert_eq!(ApiRole::Initiator.to_string(), "initiator");
        assert_eq!(ApiRole::Approver.to_string(), "approver");
        assert_eq!(ApiRole::Admin.to_string(), "admin");
    }

    #[test]
    fn test_auth_context_has_role() {
        let ctx = AuthContext::new("alice", vec![ApiRole::Initiator, ApiRole::Approver]);
        assert!(ctx.has_role(ApiRole::Initiator));
        assert!(ctx.has_role(ApiRole::Approver));
        assert!(!ctx.has_role(ApiRole::Admin));
    }

    #[test]
    fn test_sod_initiator_cannot_approve_own_session() {
        // Separation of Duties: a user who creates a session (Initiator)
        // cannot also be an Approver for that same session.
        // This is enforced at the API level by requiring different roles.
        let initiator = AuthContext::new("alice", vec![ApiRole::Initiator]);

        // Alice can create sessions
        assert!(Permissions::can_create_session(&initiator).is_ok());
        // Alice cannot submit approvals (doesn't have Approver role)
        assert!(Permissions::can_submit_approval(&initiator).is_err());
    }
}
