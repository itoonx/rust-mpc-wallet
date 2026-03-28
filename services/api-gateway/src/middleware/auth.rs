//! Authentication middleware: mTLS, session JWT, and external JWT validation.
//!
//! Priority order: mTLS → X-Session-Token (JWT) → Authorization: Bearer.
//! If a header is PRESENT but invalid, auth fails immediately — no fall-through.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};

use mpc_wallet_core::rbac::{AbacAttributes, ApiRole, AuthContext};

use crate::auth::mtls::MtlsIdentity;
use crate::auth::session_jwt::{extract_session_id, verify_session_jwt_with_key};
use crate::auth::types::auth_failed;
use crate::state::AppState;

/// Build AuthContext from a session's client_key_id.
fn session_auth_context(state: &AppState, client_key_id: &str) -> AuthContext {
    let entry = state.client_registry.keys.get(client_key_id);
    let role = entry.map(|e| e.api_role()).unwrap_or(ApiRole::Viewer);
    let mfa = entry.map(|e| e.mfa).unwrap_or(false);
    AuthContext::with_attributes(
        format!("session:{client_key_id}"),
        vec![role],
        AbacAttributes::default(),
        mfa,
    )
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();

    // Path 0: mTLS (service-to-service via client certificate).
    // TLS terminator sets X-Client-Cert-* headers after verifying the cert.
    if state.mtls_registry.is_enabled() {
        if let Some(identity) = MtlsIdentity::from_headers(headers) {
            match state
                .mtls_registry
                .verify(&identity.cn, identity.fingerprint.as_deref())
            {
                Some(entry) => {
                    tracing::debug!(
                        cn = %entry.cn,
                        role = %entry.role,
                        label = %entry.label,
                        "mTLS auth success"
                    );
                    let ctx = entry.auth_context();
                    request.extensions_mut().insert(ctx);
                    return next.run(request).await;
                }
                None => {
                    state.metrics.auth_failures.inc();
                    tracing::warn!(cn = %identity.cn, "mTLS auth failed: unknown service");
                    return auth_failed().into_response();
                }
            }
        }
    }

    // Path 1: X-Session-Token (JWT signed with handshake-derived key).
    if headers.contains_key("x-session-token") {
        let token = headers
            .get("x-session-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if token.is_empty() {
            state.metrics.auth_failures.inc();
            return auth_failed().into_response();
        }

        if token.contains('.') {
            // JWT path: extract session_id → async lookup → verify sig.
            let sid = match extract_session_id(token) {
                Ok(sid) => sid,
                Err(_) => {
                    state.metrics.auth_failures.inc();
                    return auth_failed().into_response();
                }
            };

            // Single async lookup — no block_on(), no double fetch.
            let session = match state.session_store.get(&sid).await {
                Some(s) => s,
                None => {
                    state.metrics.auth_failures.inc();
                    return auth_failed().into_response();
                }
            };

            // Verify HS256 signature with the session's write key.
            match verify_session_jwt_with_key(token, &session.client_write_key) {
                Ok(req_ctx) => {
                    tracing::debug!(
                        session_id = %session.session_id,
                        client_key_id = %session.client_key_id,
                        client_ip = ?req_ctx.client_ip,
                        device_fp = ?req_ctx.device_fingerprint,
                        "session JWT auth success"
                    );
                    let ctx = session_auth_context(&state, &session.client_key_id);
                    request.extensions_mut().insert(ctx);
                    request.extensions_mut().insert(req_ctx);
                    return next.run(request).await;
                }
                Err(e) => {
                    state.metrics.auth_failures.inc();
                    tracing::warn!("session JWT verify failed: {e}");
                    return auth_failed().into_response();
                }
            }
        } else {
            // Legacy opaque session_id (backward compatible).
            match state.session_store.get(token).await {
                Some(session) => {
                    let ctx = session_auth_context(&state, &session.client_key_id);
                    request.extensions_mut().insert(ctx);
                    return next.run(request).await;
                }
                None => {
                    state.metrics.auth_failures.inc();
                    return auth_failed().into_response();
                }
            }
        }
    }

    // Path 2: Authorization: Bearer <jwt>.
    if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            match state.jwt_validator.validate(token) {
                Ok(ctx) => {
                    request.extensions_mut().insert(ctx);
                    return next.run(request).await;
                }
                Err(_) => {
                    state.metrics.auth_failures.inc();
                    return auth_failed().into_response();
                }
            }
        }
    }

    state.metrics.auth_failures.inc();
    auth_failed().into_response()
}
