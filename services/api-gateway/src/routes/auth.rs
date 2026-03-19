//! Key-exchange handshake endpoints.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::auth::handshake::ServerHandshake;
use crate::auth::types::*;
use crate::errors::{ApiError, ErrorCode};
use crate::models::response::ApiResponse;
use crate::state::AppState;

struct PendingHandshake {
    handshake: ServerHandshake,
    client_hello: ClientHello,
    expires_at: u64,
}

/// In-memory store for pending handshakes (between hello and verify).
/// Capped at MAX_CACHE_ENTRIES to prevent DoS.
#[derive(Clone, Default)]
pub struct PendingHandshakes {
    inner: Arc<RwLock<HashMap<String, PendingHandshake>>>,
}

impl PendingHandshakes {
    pub fn new() -> Self {
        Self::default()
    }

    async fn insert(&self, challenge: String, pending: PendingHandshake) -> bool {
        let mut map = self.inner.write().await;
        let now = unix_now();
        // Prune expired only if approaching capacity (avoid O(n) on every insert).
        if map.len() >= MAX_CACHE_ENTRIES / 2 {
            map.retain(|_, v| v.expires_at > now);
        }
        if map.len() >= MAX_CACHE_ENTRIES {
            return false; // capacity exceeded
        }
        map.insert(challenge, pending);
        true
    }

    async fn remove(&self, challenge: &str) -> Option<PendingHandshake> {
        let mut map = self.inner.write().await;
        let pending = map.remove(challenge)?;
        if pending.expires_at <= unix_now() {
            return None;
        }
        Some(pending)
    }
}

/// Shared state for auth routes.
#[derive(Clone)]
pub struct AuthRouteState {
    pub app: AppState,
    pub pending: PendingHandshakes,
}

/// `POST /v1/auth/hello`
pub async fn auth_hello(
    State(state): State<AuthRouteState>,
    Json(client_hello): Json<ClientHello>,
) -> Result<Json<ApiResponse<ServerHello>>, ApiError> {
    state.app.metrics.handshake_total.inc();

    if state
        .app
        .replay_cache
        .check_and_record(&client_hello.client_nonce, 60)
        .await
    {
        state.app.metrics.handshake_failures.inc();
        tracing::warn!(client_key_id = %client_hello.client_key_id, "handshake replay detected");
        return Err(auth_failed());
    }

    // Rate limit per client_key_id.
    if !state
        .app
        .handshake_limiter
        .check(&client_hello.client_key_id)
        .await
    {
        state.app.metrics.handshake_failures.inc();
        tracing::warn!(client_key_id = %client_hello.client_key_id, "handshake rate limited");
        return Err(ApiError::rate_limited());
    }

    if state.app.is_key_revoked(&client_hello.client_key_id).await {
        state.app.metrics.handshake_failures.inc();
        tracing::warn!(client_key_id = %client_hello.client_key_id, "handshake with revoked key");
        return Err(auth_failed());
    }

    // Use Arc to avoid cloning signing key material.
    let mut handshake = ServerHandshake::new_arc(state.app.server_signing_key.clone());

    let server_hello = handshake.process_client_hello(&client_hello).map_err(|e| {
        state.app.metrics.handshake_failures.inc();
        tracing::warn!(error = %e, "handshake ClientHello failed");
        auth_failed()
    })?;

    let ok = state
        .pending
        .insert(
            server_hello.server_challenge.clone(),
            PendingHandshake {
                handshake,
                client_hello,
                expires_at: unix_now() + MAX_TIMESTAMP_DRIFT_SECS,
            },
        )
        .await;
    if !ok {
        state.app.metrics.handshake_failures.inc();
        tracing::warn!("handshake: pending cache full (DoS protection)");
        return Err(auth_failed());
    }

    tracing::debug!("handshake ServerHello sent");
    Ok(Json(ApiResponse::ok(server_hello)))
}

/// Request for `/v1/auth/verify` — uses `#[serde(flatten)]` to embed ClientAuth.
#[derive(Debug, serde::Deserialize)]
pub struct AuthVerifyRequest {
    pub server_challenge: String,
    #[serde(flatten)]
    pub client_auth: ClientAuth,
}

/// `POST /v1/auth/verify`
pub async fn auth_verify(
    State(state): State<AuthRouteState>,
    Json(req): Json<AuthVerifyRequest>,
) -> Result<Json<ApiResponse<SessionEstablished>>, ApiError> {
    let mut pending = state
        .pending
        .remove(&req.server_challenge)
        .await
        .ok_or_else(|| {
            state.app.metrics.handshake_failures.inc();
            tracing::warn!("handshake verify: no pending handshake for challenge");
            auth_failed()
        })?;

    // Verify client is in trusted registry (only if registry has entries).
    if !state.app.client_registry.keys.is_empty()
        && state
            .app
            .client_registry
            .verify_trusted(
                &pending.client_hello.client_key_id,
                &req.client_auth.client_static_pubkey,
            )
            .is_none()
    {
        state.app.metrics.handshake_failures.inc();
        tracing::warn!(
            client_key_id = %pending.client_hello.client_key_id,
            "handshake verify: untrusted client key"
        );
        return Err(auth_failed());
    }

    let session = pending
        .handshake
        .process_client_auth(
            &req.client_auth,
            &pending.client_hello,
            state.app.session_ttl,
        )
        .map_err(|e| {
            state.app.metrics.handshake_failures.inc();
            tracing::warn!(error = %e, "handshake ClientAuth failed");
            auth_failed()
        })?;

    let key_fingerprint = hex::encode(&Sha256::digest(session.client_write_key)[..16]);

    let response = SessionEstablished {
        session_id: session.session_id.clone(),
        expires_at: session.expires_at,
        session_token: session.session_id.clone(),
        key_fingerprint,
    };

    tracing::info!(
        session_id = %session.session_id,
        client_key_id = %session.client_key_id,
        "handshake complete — session established"
    );
    if !state.app.session_store.store(session).await {
        state.app.metrics.handshake_failures.inc();
        tracing::warn!("session store at capacity — cannot create session");
        return Err(auth_failed());
    }

    Ok(Json(ApiResponse::ok(response)))
}

/// Request for session refresh.
#[derive(Debug, serde::Deserialize)]
pub struct RefreshSessionRequest {
    pub session_token: String,
}

/// Response for session refresh.
#[derive(Debug, serde::Serialize)]
pub struct RefreshSessionResponse {
    pub session_id: String,
    pub expires_at: u64,
    pub session_token: String,
}

/// `POST /v1/auth/refresh-session`
pub async fn refresh_session(
    State(state): State<AuthRouteState>,
    Json(req): Json<RefreshSessionRequest>,
) -> Result<Json<ApiResponse<RefreshSessionResponse>>, ApiError> {
    let session = state
        .app
        .session_store
        .get(&req.session_token)
        .await
        .ok_or_else(|| {
            tracing::warn!("session refresh: invalid or expired session");
            auth_failed()
        })?;

    if state.app.is_key_revoked(&session.client_key_id).await {
        state.app.session_store.revoke(&session.session_id).await;
        tracing::warn!(session_id = %session.session_id, "session refresh: key revoked");
        return Err(auth_failed());
    }

    let new_expires_at = unix_now() + state.app.session_ttl;
    let session_id = session.session_id.clone();
    let refreshed = AuthenticatedSession {
        session_id: session.session_id.clone(),
        client_pubkey: session.client_pubkey,
        client_key_id: session.client_key_id.clone(),
        client_write_key: session.client_write_key,
        server_write_key: session.server_write_key,
        expires_at: new_expires_at,
        created_at: session.created_at,
    };

    let _ = state.app.session_store.store(refreshed).await;
    tracing::debug!(session_id = %session_id, new_expires_at, "session refreshed");

    Ok(Json(ApiResponse::ok(RefreshSessionResponse {
        session_id,
        expires_at: new_expires_at,
        session_token: req.session_token,
    })))
}

/// `GET /v1/auth/revoked-keys`
pub async fn revoked_keys(State(state): State<AuthRouteState>) -> Json<ApiResponse<Vec<String>>> {
    let keys = state.app.revoked_keys.list().await;
    Json(ApiResponse::ok(keys))
}

/// Request for dynamic key revocation.
#[derive(Debug, serde::Deserialize)]
pub struct RevokeKeyRequest {
    pub key_id: String,
}

/// `POST /v1/auth/revoke-key` — Admin-only dynamic key revocation.
///
/// This endpoint is behind auth + HMAC middleware (protected route).
/// Only admin role can revoke keys.
pub async fn revoke_key(
    State(state): State<crate::state::AppState>,
    axum::Extension(ctx): axum::Extension<mpc_wallet_core::rbac::AuthContext>,
    Json(req): Json<RevokeKeyRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    // Require admin role.
    mpc_wallet_core::rbac::Permissions::require_role(
        &ctx,
        &[mpc_wallet_core::rbac::ApiRole::Admin],
    )
    .map_err(|_| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::PermissionDenied,
            "admin role required",
        )
    })?;

    let is_new = state.revoke_key(req.key_id.clone()).await;
    tracing::info!(
        key_id = %req.key_id,
        revoked_by = %ctx.user_id,
        is_new,
        "key revoked dynamically"
    );
    Ok(Json(ApiResponse::ok(serde_json::json!({
        "key_id": req.key_id,
        "revoked": true,
        "was_new": is_new,
    }))))
}
