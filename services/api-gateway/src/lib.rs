//! MPC Wallet API Gateway — library crate for integration testing.

pub mod auth;
pub mod config;
pub mod errors;
pub mod middleware;
pub mod models;
pub mod orchestrator;
pub mod routes;
pub mod state;
pub mod vault;
pub mod wallet_store; // Legacy demo mode — use orchestrator for production (DEC-015)

use axum::{
    http::{header, HeaderName, Method},
    middleware as axum_mw,
    routing::{get, post},
    Router,
};
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};

use crate::middleware::auth::auth_middleware;
use crate::routes::auth::AuthRouteState;
use crate::state::AppState;

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
        .route(
            "/v1/auth/refresh-session",
            post(routes::auth::refresh_session),
        )
        .route("/v1/auth/revoked-keys", get(routes::auth::revoked_keys))
        .with_state(auth_state);

    // Public routes (no auth required) — health, chains, and auth handshake.
    let public_routes = Router::new()
        .route("/v1/health", get(routes::health::health))
        .route("/v1/chains", get(routes::chains::list_chains));

    // Protected routes (auth + RBAC).
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
        // Admin operations (behind auth).
        .route("/v1/auth/revoke-key", post(routes::auth::revoke_key))
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
                HeaderName::from_static("x-session-token"),
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
