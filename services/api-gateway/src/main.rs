//! MPC Wallet API Gateway — Axum HTTP service with defense-in-depth auth.
//!
//! Security layers:
//! 1. CORS restriction (configurable allowed origins)
//! 2. Auth middleware (mTLS, session JWT, or Bearer JWT)
//! 3. RBAC enforcement per route handler
//! 4. Audit logging of all auth events

use mpc_wallet_api::build_router;
use mpc_wallet_api::config::AppConfig;
use mpc_wallet_api::state::AppState;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

    // Start background session pruning (every 60s).
    state.session_store.spawn_prune_task();

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
    use axum::middleware as axum_mw;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    use mpc_wallet_api::auth::handshake::ServerHandshake;
    use mpc_wallet_api::auth::types::*;
    use mpc_wallet_api::middleware::auth::auth_middleware;
    use mpc_wallet_api::routes;

    async fn test_state() -> AppState {
        let config = AppConfig::for_test();
        AppState::from_config(&config)
    }

    async fn test_router() -> Router {
        build_router(test_state().await, &[])
    }

    // ── Public endpoints ──────────────────────────────────────────

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = test_router().await;
        let req = Request::builder()
            .uri("/v1/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_chains_endpoint() {
        let app = test_router().await;
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
        let app = test_router().await;
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_error_message_is_sanitized() {
        let app = test_router().await;
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "authentication failed");
    }

    // ── Metrics requires auth ─────────────────────────────────────

    #[tokio::test]
    async fn test_metrics_requires_auth() {
        let app = test_router().await;
        let req = Request::builder()
            .uri("/v1/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Handshake endpoints ─────────────────────────────────────────

    #[tokio::test]
    async fn test_auth_hello_endpoint() {
        let app = test_router().await;
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
        let app = test_router().await;
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_revoked_keys_endpoint() {
        let app = test_router().await;
        let req = Request::builder()
            .uri("/v1/auth/revoked-keys")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handshake_then_session_token_auth() {
        let state = test_state().await;

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

        let session = hs
            .process_client_auth(&client_auth, &client_hello, 3600)
            .unwrap();
        let session_id = session.session_id.clone();
        assert_eq!(session.client_key_id, client_key_id);

        state.session_store.store(session).await;

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
}
