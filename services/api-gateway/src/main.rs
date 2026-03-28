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

/// Initialize structured logging with optional JSON format and secret redaction.
///
/// - `RUST_LOG` env controls log levels (default: `mpc_wallet_api=info,tower_http=info`)
/// - `LOG_FORMAT=json` enables JSON output (default: human-readable)
fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "mpc_wallet_api=info,tower_http=info".into());

    let use_json = std::env::var("LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if use_json {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_target(true)
                    .with_thread_ids(true)
                    .map_event_format(|_fmt| mpc_wallet_api::logging::RedactingJsonFormat),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .map_event_format(|_fmt| mpc_wallet_api::logging::RedactingTextFormat),
            )
            .init();
    }
}

#[tokio::main]
async fn main() {
    init_tracing();

    let config = AppConfig::from_env_with_vault().await;
    let mut state = AppState::from_config(&config).await;

    // Connect MPC orchestrator to NATS if NATS_URL is configured.
    if let Ok(nats_url) = std::env::var("NATS_URL") {
        let result = mpc_wallet_api::orchestrator::MpcOrchestrator::connect_with_key(
            &nats_url,
            state.server_signing_key.as_ref().clone(),
        )
        .await;
        match result {
            Ok(mut orch) => {
                // Load node verifying keys if configured (required for keygen/sign).
                if let Some(ref path) = config.node_verifying_keys_file {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        if let Ok(keys) = serde_json::from_str::<
                            Vec<mpc_wallet_core::rpc::PeerKeyEntry>,
                        >(&content)
                        {
                            tracing::info!(count = keys.len(), "loaded MPC node verifying keys");
                            orch.set_node_verifying_keys(keys);
                        }
                    }
                }
                state.orchestrator = orch;
                tracing::info!("MPC orchestrator connected to NATS — distributed mode active");
            }
            Err(e) => {
                tracing::warn!("MPC orchestrator NATS connect failed: {e} — keygen/sign will fail");
            }
        }
    } else {
        tracing::warn!("NATS_URL not set — MPC keygen/sign operations will fail");
    }

    // Start background session pruning (every 60s).
    state.session_store.spawn_prune_task();

    let app = build_router(state, &config.cors_origins);

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!(
        bind_address = %addr,
        session_backend = ?config.session_backend,
        network = %config.network,
        rate_limit_rps = config.rate_limit_rps,
        "MPC Wallet API starting"
    );

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
        AppState::from_config(&config).await
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
    async fn test_health_live_returns_ok() {
        let app = test_router().await;
        let req = Request::builder()
            .uri("/v1/health/live")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"].as_str().unwrap(), "ok");
    }

    #[tokio::test]
    async fn test_health_ready_degraded_without_nats() {
        // Default test state has no NATS orchestrator, so NATS should be disconnected.
        let app = test_router().await;
        let req = Request::builder()
            .uri("/v1/health/ready")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Without NATS, status should be 503 degraded.
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"].as_str().unwrap(), "degraded");
        assert_eq!(json["components"]["nats"].as_str().unwrap(), "disconnected");
        assert_eq!(
            json["components"]["redis"].as_str().unwrap(),
            "not_configured"
        );
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
        assert_eq!(
            json["error"]["message"].as_str().unwrap(),
            "authentication failed"
        );
        assert_eq!(json["error"]["code"].as_str().unwrap(), "AUTH_FAILED");
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
