//! Authentication middleware: JWT Bearer tokens and scoped API key validation.
//!
//! Security features:
//! - API keys are HMAC-SHA256 hashed and compared in constant time
//! - JWT tokens validate issuer, audience, and expiration
//! - AuthContext is propagated to route handlers for RBAC enforcement
//! - Error messages are sanitized (no auth details leaked to clients)
//! - All auth events are logged for audit trail

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::models::response::ApiResponse;
use crate::state::AppState;

/// Authentication middleware that checks for either:
/// - `X-API-Key: <key>` header (service-to-service, scoped by role)
/// - `Authorization: Bearer <jwt>` header (user-facing, full RBAC + ABAC)
///
/// On success, inserts an `AuthContext` into request extensions for downstream
/// RBAC enforcement in route handlers.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();

    // Check X-API-Key first (service-to-service).
    if let Some(api_key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        match state.verify_api_key(api_key) {
            Some(entry) => {
                tracing::info!(
                    key_label = %entry.label,
                    role = ?entry.role,
                    "API key auth success"
                );
                let ctx = entry.auth_context();
                request.extensions_mut().insert(ctx);
                return next.run(request).await;
            }
            None => {
                state.metrics.auth_failures.inc();
                tracing::warn!(
                    key_prefix = &api_key[..api_key.len().min(8)],
                    "API key auth failed: invalid or expired"
                );
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ApiResponse::<()>::err("authentication failed")),
                )
                    .into_response();
            }
        }
    }

    // Check Authorization: Bearer <jwt>.
    if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            match state.jwt_validator.validate(token) {
                Ok(ctx) => {
                    tracing::info!(
                        user_id = %ctx.user_id,
                        roles = ?ctx.roles,
                        "JWT auth success"
                    );
                    request.extensions_mut().insert(ctx);
                    return next.run(request).await;
                }
                Err(e) => {
                    state.metrics.auth_failures.inc();
                    tracing::warn!("JWT auth failed: {e}");
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(ApiResponse::<()>::err("authentication failed")),
                    )
                        .into_response();
                }
            }
        }
    }

    state.metrics.auth_failures.inc();
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiResponse::<()>::err("authentication failed")),
    )
        .into_response()
}
