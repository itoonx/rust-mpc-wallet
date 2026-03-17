//! MPC Wallet API Gateway — Axum HTTP service.
//!
//! Provides a REST API for MPC wallet operations: keygen, signing,
//! transaction building/broadcasting, and wallet management.

mod config;
mod middleware;
mod models;
mod routes;
mod state;

use axum::{
    middleware as axum_mw,
    routing::{get, post},
    Router,
};
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::AppConfig;
use crate::middleware::auth::auth_middleware;
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

    let app = build_router(state);

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

/// Build the Axum router with all routes.
pub fn build_router(state: AppState) -> Router {
    // Public routes (no auth required).
    let public_routes = Router::new()
        .route("/v1/health", get(routes::health::health))
        .route("/v1/metrics", get(routes::health::metrics))
        .route("/v1/chains", get(routes::chains::list_chains));

    // Protected routes (auth required).
    let protected_routes = Router::new()
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
        .layer(axum_mw::from_fn_with_state(state.clone(), auth_middleware));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
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
        let config = AppConfig {
            port: 3000,
            jwt_secret: "test-secret-for-unit-tests-only-32b".into(),
            api_keys: vec!["test-api-key".into()],
            network: "testnet".into(),
            rate_limit_rps: 100,
        };
        AppState::from_config(&config)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/v1/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_chains_endpoint() {
        let app = build_router(test_state());
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

    #[tokio::test]
    async fn test_protected_endpoint_requires_auth() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_api_key_auth() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("GET")
            .header("x-api-key", "test-api-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_invalid_api_key_rejected() {
        let app = build_router(test_state());
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
    async fn test_create_wallet_validation() {
        let app = build_router(test_state());
        // Invalid scheme
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("POST")
            .header("x-api-key", "test-api-key")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "label": "test",
                    "scheme": "invalid-scheme",
                    "threshold": 2,
                    "total_parties": 3
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_wallet_success() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/v1/wallets")
            .method("POST")
            .header("x-api-key", "test-api-key")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "label": "My Wallet",
                    "scheme": "gg20-ecdsa",
                    "threshold": 2,
                    "total_parties": 3
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["data"]["label"], "My Wallet");
        assert_eq!(json["data"]["scheme"], "gg20-ecdsa");
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/v1/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_simulate_invalid_chain() {
        let app = build_router(test_state());
        let req = Request::builder()
            .uri("/v1/wallets/test-id/simulate")
            .method("POST")
            .header("x-api-key", "test-api-key")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "chain": "invalid-chain",
                    "to": "0x1234",
                    "value": "0"
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
