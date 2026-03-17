//! Key-exchange handshake endpoints.
//!
//! `POST /v1/auth/hello`  — receive ClientHello, return ServerHello
//! `POST /v1/auth/verify` — receive ClientAuth, return SessionEstablished
//! `GET  /v1/auth/revoked-keys` — list revoked key IDs

use std::collections::HashMap;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::auth::handshake::ServerHandshake;
use crate::auth::types::*;
use crate::models::response::ApiResponse;
use crate::state::AppState;

/// Pending handshake: stores the ServerHandshake state machine + original ClientHello
/// keyed by server_challenge (hex). Expires after 30 seconds.
struct PendingHandshake {
    handshake: ServerHandshake,
    client_hello: ClientHello,
    expires_at: u64,
}

/// In-memory store for pending handshakes (between hello and verify).
#[derive(Clone, Default)]
pub struct PendingHandshakes {
    inner: Arc<RwLock<HashMap<String, PendingHandshake>>>,
}

impl PendingHandshakes {
    pub fn new() -> Self {
        Self::default()
    }

    async fn insert(&self, challenge: String, pending: PendingHandshake) {
        let mut map = self.inner.write().await;
        // Prune expired entries.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        map.retain(|_, v| v.expires_at > now);
        map.insert(challenge, pending);
    }

    async fn remove(&self, challenge: &str) -> Option<PendingHandshake> {
        let mut map = self.inner.write().await;
        let pending = map.remove(challenge)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if pending.expires_at <= now {
            return None; // expired
        }
        Some(pending)
    }
}

/// Shared state for auth routes (includes pending handshakes).
#[derive(Clone)]
pub struct AuthRouteState {
    pub app: AppState,
    pub pending: PendingHandshakes,
}

/// `POST /v1/auth/hello` — Step 1: receive ClientHello, return ServerHello.
pub async fn auth_hello(
    State(state): State<AuthRouteState>,
    Json(client_hello): Json<ClientHello>,
) -> Result<Json<ApiResponse<ServerHello>>, (StatusCode, Json<ApiResponse<()>>)> {
    state.app.metrics.handshake_total.inc();

    // Check replay: reject if client_nonce has been seen before.
    if state
        .app
        .replay_cache
        .check_and_record(&client_hello.client_nonce, 60)
        .await
    {
        state.app.metrics.handshake_failures.inc();
        tracing::warn!(
            client_key_id = %client_hello.client_key_id,
            "handshake replay detected"
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::err("authentication failed")),
        ));
    }

    // Check if client_key_id is revoked.
    if state.app.is_key_revoked(&client_hello.client_key_id) {
        state.app.metrics.handshake_failures.inc();
        tracing::warn!(
            client_key_id = %client_hello.client_key_id,
            "handshake with revoked key"
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::err("authentication failed")),
        ));
    }

    // Create handshake state machine.
    let mut handshake = ServerHandshake::new(state.app.server_signing_key.as_ref().clone());

    let server_hello = handshake.process_client_hello(&client_hello).map_err(|e| {
        state.app.metrics.handshake_failures.inc();
        tracing::warn!(error = %e, "handshake ClientHello failed");
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("authentication failed")),
        )
    })?;

    // Store pending handshake keyed by server_challenge.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    state
        .pending
        .insert(
            server_hello.server_challenge.clone(),
            PendingHandshake {
                handshake,
                client_hello,
                expires_at: now + MAX_TIMESTAMP_DRIFT_SECS,
            },
        )
        .await;

    tracing::info!("handshake ServerHello sent");
    Ok(Json(ApiResponse::ok(server_hello)))
}

/// Request body for `/v1/auth/verify`.
#[derive(Debug, serde::Deserialize)]
pub struct AuthVerifyRequest {
    /// The server_challenge from ServerHello (used to look up pending handshake).
    pub server_challenge: String,
    /// Client's Ed25519 signature over transcript hash.
    pub client_signature: String,
    /// Client's static Ed25519 public key (hex).
    pub client_static_pubkey: String,
}

/// `POST /v1/auth/verify` — Step 2: receive ClientAuth, return SessionEstablished.
pub async fn auth_verify(
    State(state): State<AuthRouteState>,
    Json(req): Json<AuthVerifyRequest>,
) -> Result<Json<ApiResponse<SessionEstablished>>, (StatusCode, Json<ApiResponse<()>>)> {
    // Look up pending handshake.
    let mut pending = state
        .pending
        .remove(&req.server_challenge)
        .await
        .ok_or_else(|| {
            state.app.metrics.handshake_failures.inc();
            tracing::warn!("handshake verify: no pending handshake for challenge");
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::err("authentication failed")),
            )
        })?;

    let client_auth = ClientAuth {
        client_signature: req.client_signature,
        client_static_pubkey: req.client_static_pubkey.clone(),
    };

    // Verify client is in trusted registry (only if registry has entries).
    if !state.app.client_registry.keys.is_empty()
        && state
            .app
            .client_registry
            .verify_trusted(
                &pending.client_hello.client_key_id,
                &req.client_static_pubkey,
            )
            .is_none()
    {
        state.app.metrics.handshake_failures.inc();
        tracing::warn!(
            client_key_id = %pending.client_hello.client_key_id,
            "handshake verify: untrusted client key"
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::err("authentication failed")),
        ));
    }

    // Process ClientAuth — verify signature, derive session keys.
    let session = pending
        .handshake
        .process_client_auth(&client_auth, &pending.client_hello)
        .map_err(|e| {
            state.app.metrics.handshake_failures.inc();
            tracing::warn!(error = %e, "handshake ClientAuth failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::err("authentication failed")),
            )
        })?;

    let key_fingerprint = hex::encode(&Sha256::digest(session.client_write_key)[..16]);

    let response = SessionEstablished {
        session_id: session.session_id.clone(),
        expires_at: session.expires_at,
        session_token: session.session_id.clone(), // session_id IS the token
        key_fingerprint,
    };

    // Store session.
    tracing::info!(
        session_id = %session.session_id,
        client_key_id = %session.client_key_id,
        "handshake complete — session established"
    );
    state.app.session_store.store(session).await;

    Ok(Json(ApiResponse::ok(response)))
}

/// `GET /v1/auth/revoked-keys` — list revoked key IDs.
pub async fn revoked_keys(State(state): State<AuthRouteState>) -> Json<ApiResponse<Vec<String>>> {
    let keys: Vec<String> = state.app.revoked_keys.iter().cloned().collect();
    Json(ApiResponse::ok(keys))
}
