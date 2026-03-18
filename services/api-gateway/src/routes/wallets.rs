//! Wallet management endpoints: create, list, get, freeze, unfreeze, refresh.
//!
//! Every handler extracts `AuthContext` from request extensions and enforces
//! RBAC permissions before processing the request.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};

use mpc_wallet_core::rbac::{ApiRole, AuthContext, Permissions};

use crate::errors::{ApiError, ErrorCode};
use crate::models::request::{CreateWalletRequest, SignRequest};
use crate::models::response::{
    ApiResponse, SignResponse, WalletDetailResponse, WalletListResponse, WalletResponse,
};
use crate::state::AppState;

/// Helper: extract AuthContext and check required roles.
fn require_roles(ctx: &AuthContext, roles: &[ApiRole]) -> Result<(), ApiError> {
    Permissions::require_role(ctx, roles).map_err(|e| {
        tracing::warn!(
            user_id = %ctx.user_id,
            required = ?roles,
            actual = ?ctx.roles,
            "RBAC denied: {e}"
        );
        ApiError::forbidden("insufficient permissions")
    })
}

/// Helper: require Admin + MFA.
fn require_admin_mfa(ctx: &AuthContext) -> Result<(), ApiError> {
    Permissions::can_freeze_key_mfa(ctx).map_err(|e| {
        tracing::warn!(
            user_id = %ctx.user_id,
            mfa = ctx.mfa_verified,
            "RBAC denied (admin+MFA): {e}"
        );
        ApiError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::MfaRequired,
            "insufficient permissions",
        )
    })
}

/// `POST /v1/wallets` — create a new MPC wallet (keygen).
/// Requires: Admin + MFA
pub async fn create_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<CreateWalletRequest>,
) -> Result<(StatusCode, Json<ApiResponse<WalletResponse>>), ApiError> {
    require_admin_mfa(&ctx)?;

    // Validate scheme.
    let _scheme: mpc_wallet_core::types::CryptoScheme = req
        .scheme
        .parse()
        .map_err(|e: String| ApiError::bad_request(ErrorCode::InvalidInput, e))?;

    // Validate threshold config.
    mpc_wallet_core::types::ThresholdConfig::new(req.threshold, req.total_parties)
        .map_err(|e| ApiError::bad_request(ErrorCode::InvalidConfig, e.to_string()))?;

    state.metrics.keygen_total.inc();

    let group_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::ok(WalletResponse {
            id: group_id,
            label: req.label,
            scheme: req.scheme,
            threshold: req.threshold,
            total_parties: req.total_parties,
            created_at: now,
        })),
    ))
}

/// `GET /v1/wallets` — list all wallets.
/// Requires: Viewer+
pub async fn list_wallets(
    State(_state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<ApiResponse<WalletListResponse>>, ApiError> {
    require_roles(
        &ctx,
        &[
            ApiRole::Viewer,
            ApiRole::Initiator,
            ApiRole::Approver,
            ApiRole::Admin,
        ],
    )?;
    Ok(Json(ApiResponse::ok(WalletListResponse {
        wallets: vec![],
    })))
}

/// `GET /v1/wallets/:id` — get wallet details.
/// Requires: Viewer+
pub async fn get_wallet(
    State(_state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<WalletDetailResponse>>, ApiError> {
    require_roles(
        &ctx,
        &[
            ApiRole::Viewer,
            ApiRole::Initiator,
            ApiRole::Approver,
            ApiRole::Admin,
        ],
    )?;
    Err(ApiError::not_found(format!("wallet {wallet_id} not found")))
}

/// `POST /v1/wallets/:id/sign` — sign a message.
/// Requires: Initiator or Admin + risk tier check
pub async fn sign_message(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
    Json(req): Json<SignRequest>,
) -> Result<Json<ApiResponse<SignResponse>>, ApiError> {
    require_roles(&ctx, &[ApiRole::Initiator, ApiRole::Admin])?;
    Permissions::check_risk_tier_for_signing(&ctx)
        .map_err(|e| ApiError::forbidden(e.to_string()))?;

    let _message_bytes = hex::decode(&req.message).map_err(|e| {
        ApiError::bad_request(ErrorCode::InvalidInput, format!("invalid hex message: {e}"))
    })?;

    state.metrics.sign_total.inc();

    Err(ApiError::not_found(format!(
        "wallet {wallet_id} not found — MPC signing requires key store integration"
    )))
}

/// `POST /v1/wallets/:id/refresh` — proactive key refresh.
/// Requires: Admin + MFA
pub async fn refresh_wallet(
    State(_state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    Err(ApiError::not_found(format!(
        "wallet {wallet_id} not found — key refresh requires key store integration"
    )))
}

/// `POST /v1/wallets/:id/freeze` — freeze wallet.
/// Requires: Admin + MFA
pub async fn freeze_wallet(
    State(_state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    Err(ApiError::not_found(format!(
        "wallet {wallet_id} not found — freeze requires key store integration"
    )))
}

/// `POST /v1/wallets/:id/unfreeze` — unfreeze wallet.
/// Requires: Admin + MFA
pub async fn unfreeze_wallet(
    State(_state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    Err(ApiError::not_found(format!(
        "wallet {wallet_id} not found — unfreeze requires key store integration"
    )))
}
