//! API key management endpoints.
//!
//! - `POST /v1/api-keys` — create a new API key (admin only). Raw key returned once.
//! - `GET  /v1/api-keys` — list all keys (metadata only, no secrets).
//! - `GET  /v1/api-keys/:id` — get a single key's metadata.
//! - `DELETE /v1/api-keys/:id` — revoke and delete a key.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};

use mpc_wallet_core::rbac::{ApiRole, AuthContext, Permissions};

use crate::models::response::ApiResponse;
use crate::state::AppState;

/// Helper: require admin role.
fn require_admin(ctx: &AuthContext) -> Result<(), (StatusCode, Json<ApiResponse<()>>)> {
    Permissions::require_role(ctx, &[ApiRole::Admin]).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            Json(ApiResponse::err("admin role required")),
        )
    })
}

/// Request body for creating an API key.
#[derive(Debug, serde::Deserialize)]
pub struct CreateApiKeyRequest {
    /// Human-readable label for the key.
    pub label: String,
    /// Role: `admin`, `initiator`, `approver`, or `viewer`.
    pub role: String,
    /// Optional: restrict to specific wallet IDs.
    #[serde(default)]
    pub allowed_wallets: Option<Vec<String>>,
    /// Optional: restrict to specific chains.
    #[serde(default)]
    pub allowed_chains: Option<Vec<String>>,
    /// Optional: expiration timestamp (UNIX seconds).
    #[serde(default)]
    pub expires_at: Option<u64>,
}

/// Response for key creation — includes the raw key (shown once).
#[derive(Debug, serde::Serialize)]
pub struct CreateApiKeyResponse {
    /// Unique key ID for management operations.
    pub key_id: String,
    /// The raw API key — **save this now, it will not be shown again**.
    pub raw_key: String,
    /// Human-readable label.
    pub label: String,
    /// Assigned role.
    pub role: String,
    /// When the key was created.
    pub created_at: u64,
    /// When the key expires (null = never).
    pub expires_at: Option<u64>,
}

/// `POST /v1/api-keys` — Create a new API key (admin only).
///
/// The raw key is returned **once** in the response. It is never stored — only
/// the HMAC-SHA256 hash is kept. If the caller loses the key, they must create a new one.
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<
    (StatusCode, Json<ApiResponse<CreateApiKeyResponse>>),
    (StatusCode, Json<ApiResponse<()>>),
> {
    require_admin(&ctx)?;

    // Validate role against known variants.
    if !crate::auth::types::VALID_ROLES.contains(&req.role.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(format!(
                "invalid role '{}' — must be one of: {}",
                req.role,
                crate::auth::types::VALID_ROLES.join(", ")
            ))),
        ));
    }

    let (key_id, raw_key) = state
        .api_key_store
        .create_key(
            req.label.clone(),
            req.role.clone(),
            ctx.user_id.clone(),
            req.allowed_wallets,
            req.allowed_chains,
            req.expires_at,
        )
        .await;

    tracing::info!(
        key_id = %key_id,
        label = %req.label,
        role = %req.role,
        created_by = %ctx.user_id,
        "API key created"
    );

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::ok(CreateApiKeyResponse {
            key_id,
            raw_key,
            label: req.label,
            role: req.role,
            created_at: crate::auth::types::unix_now(),
            expires_at: req.expires_at,
        })),
    ))
}

/// `GET /v1/api-keys` — List all API keys (admin only, metadata only).
pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    require_admin(&ctx)?;

    let keys = state.api_key_store.list().await;
    let active_count = state.api_key_store.count_active().await;

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "keys": keys,
        "total": keys.len(),
        "active": active_count,
    }))))
}

/// `GET /v1/api-keys/:id` — Get a single key's metadata (admin only).
pub async fn get_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(key_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    require_admin(&ctx)?;

    match state.api_key_store.get(&key_id).await {
        Some(meta) => Ok(Json(ApiResponse::ok(serde_json::json!(meta)))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::err("API key not found")),
        )),
    }
}

/// `DELETE /v1/api-keys/:id` — Revoke and delete a key (admin only).
pub async fn delete_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(key_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    require_admin(&ctx)?;

    let existed = state.api_key_store.delete(&key_id).await;
    if !existed {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::err("API key not found")),
        ));
    }

    tracing::info!(
        key_id = %key_id,
        deleted_by = %ctx.user_id,
        "API key deleted"
    );

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "key_id": key_id,
        "deleted": true,
    }))))
}
