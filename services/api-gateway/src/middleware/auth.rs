//! Authentication middleware: JWT, API key, and session token validation.
//!
//! Priority order: X-Session-Token → X-API-Key → Authorization: Bearer.
//! If a header is PRESENT but invalid, auth fails immediately — no fall-through.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};

use mpc_wallet_core::rbac::{AbacAttributes, ApiRole, AuthContext};

use crate::auth::types::auth_failed;
use crate::state::AppState;

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();

    // Path 1: X-Session-Token (key-exchange handshake session).
    // If the header is PRESENT (even if malformed), we must resolve here — no fall-through.
    if headers.contains_key("x-session-token") {
        let session_id = headers
            .get("x-session-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if session_id.is_empty() {
            state.metrics.auth_failures.inc();
            tracing::warn!("session token auth failed: empty or non-UTF8 header");
            return auth_failed().into_response();
        }

        match state.session_store.get(session_id).await {
            Some(session) => {
                tracing::debug!(
                    session_id = %session.session_id,
                    client_key_id = %session.client_key_id,
                    "session token auth success"
                );
                let role = state
                    .client_registry
                    .keys
                    .get(&session.client_key_id)
                    .map(|e| e.api_role())
                    .unwrap_or(ApiRole::Viewer);
                let ctx = AuthContext::with_attributes(
                    format!("session:{}", session.client_key_id),
                    vec![role],
                    AbacAttributes::default(),
                    false,
                );
                request.extensions_mut().insert(ctx);
                return next.run(request).await;
            }
            None => {
                state.metrics.auth_failures.inc();
                tracing::warn!("session token auth failed: invalid or expired");
                return auth_failed().into_response();
            }
        }
    }

    // Path 2: X-API-Key (service-to-service or user-created).
    if let Some(api_key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        match state.api_key_store.verify(api_key).await {
            Some(meta) => {
                tracing::debug!(
                    key_label = %meta.label,
                    key_id = %meta.key_id,
                    role = ?meta.role,
                    origin = ?meta.origin,
                    "API key auth success"
                );
                let ctx = meta.auth_context();
                request.extensions_mut().insert(ctx);
                return next.run(request).await;
            }
            None => {
                state.metrics.auth_failures.inc();
                tracing::warn!(
                    key_prefix = &api_key[..api_key.len().min(8)],
                    "API key auth failed"
                );
                return auth_failed().into_response();
            }
        }
    }

    // Path 3: Authorization: Bearer <jwt>.
    if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            match state.jwt_validator.validate(token) {
                Ok(ctx) => {
                    tracing::debug!(user_id = %ctx.user_id, "JWT auth success");
                    request.extensions_mut().insert(ctx);
                    return next.run(request).await;
                }
                Err(e) => {
                    state.metrics.auth_failures.inc();
                    tracing::warn!("JWT auth failed: {e}");
                    return auth_failed().into_response();
                }
            }
        }
    }

    state.metrics.auth_failures.inc();
    auth_failed().into_response()
}
