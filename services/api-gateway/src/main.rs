//! MPC Wallet API Gateway — Axum HTTP service with defense-in-depth auth.
//!
//! Security layers:
//! 1. CORS restriction (configurable allowed origins)
//! 2. Auth middleware (JWT Bearer or scoped API key with HMAC hashing)
//! 3. HMAC request signing for POST mutations (API key auth only)
//! 4. RBAC enforcement per route handler
//! 5. Audit logging of all auth events

pub mod auth;
mod config;
mod middleware;
mod models;
mod routes;
mod state;

use axum::{
    http::{header, HeaderName, Method},
    middleware as axum_mw,
    routing::{get, post},
    Router,
};
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::AppConfig;
use crate::middleware::auth::auth_middleware;
use crate::middleware::hmac::hmac_middleware;
use crate::routes::auth::AuthRouteState;
use crate::state::AppState;

#[tokio::main]
async fn main() {
    // Initialize tracing.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mpc_wallet_api=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = AppConfig::from_env();
    let state = AppState::from_config(&config);

    let app = build_router(state, &config.cors_origins);

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("MPC Wallet API starting on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap();
}

/// Build the Axum router with all routes and security layers.
pub fn build_router(state: AppState, cors_origins: &[String]) -> Router {
    // Auth handshake routes (no auth required — this IS the auth flow).
    let auth_state = AuthRouteState {
        app: state.clone(),
        pending: crate::routes::auth::PendingHandshakes::new(),
    };
    let auth_routes = Router::new()
        .route("/v1/auth/hello", post(routes::auth::auth_hello))
        .route("/v1/auth/verify", post(routes::auth::auth_verify))
        .route("/v1/auth/revoked-keys", get(routes::auth::revoked_keys))
        .with_state(auth_state);

    // Public routes (no auth required) — health, chains, and auth handshake.
    let public_routes = Router::new()
        .route("/v1/health", get(routes::health::health))
        .route("/v1/chains", get(routes::chains::list_chains));

    // Protected routes (auth + RBAC + HMAC signing).
    let protected_routes = Router::new()
        .route("/v1/metrics", get(routes::health::metrics))
        .route("/v1/wallets", post(routes::wallets::create_wallet))
        .route("/v1/wallets", get(routes::wallets::list_wallets))
        .route("/v1/wallets/{id}", get(routes::wallets::get_wallet))
        .route("/v1/wallets/{id}/sign", post(routes::wallets::sign_message))
        .route(
            "/v1/wallets/{id}/transactions",
            post(routes::transactions::create_transaction),
        )
        .route(
            "/v1/wallets/{id}/simulate",
            post(routes::transactions::simulate_transaction),
        )
        .route(
            "/v1/wallets/{id}/refresh",
            post(routes::wallets::refresh_wallet),
        )
        .route(
            "/v1/wallets/{id}/freeze",
            post(routes::wallets::freeze_wallet),
        )
        .route(
            "/v1/wallets/{id}/unfreeze",
            post(routes::wallets::unfreeze_wallet),
        )
        .route(
            "/v1/chains/{chain}/address/{id}",
            get(routes::chains::derive_address),
        )
        .layer(axum_mw::from_fn(hmac_middleware))
        .layer(axum_mw::from_fn_with_state(state.clone(), auth_middleware));

    // CORS configuration — restricted in production.
    let cors = if cors_origins.is_empty() {
        // No origins configured: allow all (dev mode).
        CorsLayer::permissive()
    } else {
        CorsLayer::new()
            .allow_origin(
                cors_origins
                    .iter()
                    .filter_map(|o| o.parse().ok())
                    .collect::<Vec<_>>(),
            )
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                HeaderName::from_static("x-api-key"),
                HeaderName::from_static("x-signature"),
                HeaderName::from_static("x-timestamp"),
            ])
            .max_age(std::time::Duration::from_secs(3600))
    };

    Router::new()
        .merge(auth_routes)
        .merge(public_routes)
        .merge(protected_routes)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    tracing::info!("shutdown signal received, draining connections...");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState::from_config(&AppConfig::for_test())
    }

    fn test_router() -> Router {
        build_router(test_state(), &[])
    }

    // ── Public endpoints ──────────────────────────────────────────

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = test_router();
        let req = Request::builder()
            .uri("/v1/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_chains_endpoint() {
        let app = test_router();
        let req = Request::builder()
            .uri("/v1/chains")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["data"]["total"].as_u64().unwrap(), 50);
    }

    // ── Auth enforcement ──────────────────────────────────────────

    #[tokio::test]
    async fn test_protected_endpoint_requires_auth() {
        let app = test_router();
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invalid_api_key_rejected() {
        let app = test_router();
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("GET")
            .header("x-api-key", "wrong-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_error_message_is_sanitized() {
        let app = test_router();
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("GET")
            .header("x-api-key", "wrong-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Error should NOT leak "invalid API key" or specific auth details.
        assert_eq!(json["error"].as_str().unwrap(), "authentication failed");
    }

    // ── API key auth (GET = no HMAC required) ─────────────────────

    #[tokio::test]
    async fn test_admin_key_can_list_wallets() {
        let app = test_router();
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("GET")
            .header("x-api-key", "test-admin-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_viewer_key_can_list_wallets() {
        let app = test_router();
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("GET")
            .header("x-api-key", "test-viewer-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── RBAC enforcement ──────────────────────────────────────────

    #[tokio::test]
    async fn test_viewer_key_cannot_create_wallet() {
        let app = test_router();
        let body = serde_json::to_string(&serde_json::json!({
            "label": "test", "scheme": "gg20-ecdsa", "threshold": 2, "total_parties": 3
        }))
        .unwrap();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sig = crate::middleware::hmac::compute_signature(
            "test-viewer-key",
            timestamp,
            "POST",
            "/v1/wallets",
            body.as_bytes(),
        );
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("POST")
            .header("x-api-key", "test-viewer-key")
            .header("x-signature", &sig)
            .header("x-timestamp", timestamp.to_string())
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Viewer cannot keygen → 403
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_viewer_key_cannot_sign() {
        let app = test_router();
        let body = serde_json::to_string(&serde_json::json!({
            "message": "deadbeef"
        }))
        .unwrap();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sig = crate::middleware::hmac::compute_signature(
            "test-viewer-key",
            timestamp,
            "POST",
            "/v1/wallets/abc/sign",
            body.as_bytes(),
        );
        let req = Request::builder()
            .uri("/v1/wallets/abc/sign")
            .method("POST")
            .header("x-api-key", "test-viewer-key")
            .header("x-signature", &sig)
            .header("x-timestamp", timestamp.to_string())
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_initiator_key_can_sign_attempt() {
        let app = test_router();
        let body = serde_json::to_string(&serde_json::json!({
            "message": "deadbeef"
        }))
        .unwrap();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sig = crate::middleware::hmac::compute_signature(
            "test-initiator-key",
            timestamp,
            "POST",
            "/v1/wallets/abc/sign",
            body.as_bytes(),
        );
        let req = Request::builder()
            .uri("/v1/wallets/abc/sign")
            .method("POST")
            .header("x-api-key", "test-initiator-key")
            .header("x-signature", &sig)
            .header("x-timestamp", timestamp.to_string())
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Initiator can sign → gets 404 (wallet not found, not 403)
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── HMAC enforcement ──────────────────────────────────────────

    #[tokio::test]
    async fn test_post_without_hmac_rejected() {
        let app = test_router();
        let body = serde_json::to_string(&serde_json::json!({
            "label": "test", "scheme": "gg20-ecdsa", "threshold": 2, "total_parties": 3
        }))
        .unwrap();
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("POST")
            .header("x-api-key", "test-admin-key")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Missing X-Signature → 401
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_post_with_wrong_hmac_rejected() {
        let app = test_router();
        let body = serde_json::to_string(&serde_json::json!({
            "label": "test", "scheme": "gg20-ecdsa", "threshold": 2, "total_parties": 3
        }))
        .unwrap();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("POST")
            .header("x-api-key", "test-admin-key")
            .header(
                "x-signature",
                "v1=0000000000000000000000000000000000000000000000000000000000000000",
            )
            .header("x-timestamp", timestamp.to_string())
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Metrics requires auth ─────────────────────────────────────

    #[tokio::test]
    async fn test_metrics_requires_auth() {
        let app = test_router();
        let req = Request::builder()
            .uri("/v1/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_metrics_with_auth() {
        let app = test_router();
        let req = Request::builder()
            .uri("/v1/metrics")
            .header("x-api-key", "test-viewer-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── Handshake endpoints ─────────────────────────────────────────

    #[tokio::test]
    async fn test_auth_hello_endpoint() {
        let app = test_router();
        let client_eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let client_eph_pub = x25519_dalek::PublicKey::from(&client_eph);
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let body = serde_json::to_string(&serde_json::json!({
            "protocol_version": "mpc-wallet-auth-v1",
            "supported_kex": ["x25519"],
            "supported_sig": ["ed25519"],
            "client_ephemeral_pubkey": hex::encode(client_eph_pub.as_bytes()),
            "client_nonce": hex::encode(nonce),
            "timestamp": now,
            "client_key_id": "0000000000000000"
        }))
        .unwrap();

        let req = Request::builder()
            .uri("/v1/auth/hello")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(
            json["data"]["protocol_version"].as_str().unwrap(),
            "mpc-wallet-auth-v1"
        );
        assert!(!json["data"]["server_signature"]
            .as_str()
            .unwrap()
            .is_empty());
        assert!(!json["data"]["server_challenge"]
            .as_str()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_auth_hello_wrong_version_rejected() {
        let app = test_router();
        let body = serde_json::to_string(&serde_json::json!({
            "protocol_version": "wrong-v999",
            "supported_kex": ["x25519"],
            "supported_sig": ["ed25519"],
            "client_ephemeral_pubkey": "00".repeat(32),
            "client_nonce": "00".repeat(32),
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            "client_key_id": "0000000000000000"
        }))
        .unwrap();

        let req = Request::builder()
            .uri("/v1/auth/hello")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_auth_revoked_keys_endpoint() {
        let app = test_router();
        let req = Request::builder()
            .uri("/v1/auth/revoked-keys")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handshake_then_session_token_auth() {
        use crate::auth::handshake::ServerHandshake;
        use crate::auth::types::*;

        let state = test_state();

        // Run handshake directly (tested in handshake.rs unit tests).
        let mut key_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key_bytes);
        let client_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        let client_eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let client_eph_pub = x25519_dalek::PublicKey::from(&client_eph);

        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let client_key_id = hex::encode(&client_key.verifying_key().to_bytes()[..8]);

        let client_hello = ClientHello {
            protocol_version: PROTOCOL_VERSION.to_string(),
            supported_kex: vec![KeyExchangeAlgorithm::X25519],
            supported_sig: vec![SignatureAlgorithm::Ed25519],
            client_ephemeral_pubkey: hex::encode(client_eph_pub.as_bytes()),
            client_nonce: hex::encode(nonce),
            timestamp: now,
            client_key_id: client_key_id.clone(),
        };

        let mut hs = ServerHandshake::new(state.server_signing_key.as_ref().clone());
        let server_hello = hs.process_client_hello(&client_hello).unwrap();

        // Build client auth (same transcript logic as handshake unit tests).
        use sha2::{Digest, Sha256};
        let mut transcript = Sha256::new();
        transcript.update(serde_json::to_vec(&client_hello).unwrap());
        let sh_t = serde_json::json!({
            "protocol_version": server_hello.protocol_version,
            "selected_kex": server_hello.selected_kex,
            "selected_sig": server_hello.selected_sig,
            "selected_aead": server_hello.selected_aead,
            "server_ephemeral_pubkey": server_hello.server_ephemeral_pubkey,
            "server_nonce": server_hello.server_nonce,
            "server_challenge": server_hello.server_challenge,
            "timestamp": server_hello.timestamp,
            "server_key_id": server_hello.server_key_id,
        });
        transcript.update(serde_json::to_vec(&sh_t).unwrap());
        let cpk = hex::encode(client_key.verifying_key().to_bytes());
        transcript
            .update(serde_json::to_vec(&serde_json::json!({"client_static_pubkey": cpk})).unwrap());
        use ed25519_dalek::Signer;
        let sig = client_key.sign(&transcript.finalize());
        let client_auth = ClientAuth {
            client_signature: hex::encode(sig.to_bytes()),
            client_static_pubkey: cpk,
        };

        let session = hs.process_client_auth(&client_auth, &client_hello).unwrap();
        let session_id = session.session_id.clone();
        assert_eq!(session.client_key_id, client_key_id);

        // Store session.
        state.session_store.store(session).await;

        // Verify session token works in auth middleware.
        let protected = Router::new()
            .route("/v1/wallets", get(routes::wallets::list_wallets))
            .layer(axum_mw::from_fn_with_state(state.clone(), auth_middleware))
            .with_state(state);
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("GET")
            .header("x-session-token", &session_id)
            .body(Body::empty())
            .unwrap();
        let resp = protected.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "session token auth should work"
        );
    }

    // ── Schema validation ─────────────────────────────────────────

    #[tokio::test]
    async fn test_simulate_invalid_chain() {
        let app = test_router();
        let body = serde_json::to_string(&serde_json::json!({
            "chain": "invalid-chain", "to": "0x1234", "value": "0"
        }))
        .unwrap();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sig = crate::middleware::hmac::compute_signature(
            "test-admin-key",
            timestamp,
            "POST",
            "/v1/wallets/test-id/simulate",
            body.as_bytes(),
        );
        let req = Request::builder()
            .uri("/v1/wallets/test-id/simulate")
            .method("POST")
            .header("x-api-key", "test-admin-key")
            .header("x-signature", &sig)
            .header("x-timestamp", timestamp.to_string())
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
