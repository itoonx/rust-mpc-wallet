//! MPC Wallet API Gateway — library crate for integration testing.

pub mod auth;
pub mod config;
pub mod errors;
pub mod logging;
pub mod middleware;
pub mod models;
pub mod orchestrator;
pub mod org;
pub mod routes;
pub mod state;
pub mod vault;
pub mod webhooks;
pub mod whitelist;

use axum::{
    http::{header, HeaderName, Method},
    middleware as axum_mw,
    routing::{get, post},
    Json, Router,
};
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};
use utoipa::OpenApi;

use crate::middleware::auth::auth_middleware;
use crate::routes::auth::AuthRouteState;
use crate::state::AppState;

/// OpenAPI specification generated from code — the source of truth.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "MPC Wallet API",
        version = "1.0.0",
        description = "Threshold MPC wallet REST API. No single party ever holds a complete private key.",
        license(name = "MIT")
    ),
    paths(
        // Health
        routes::health::health,
        routes::health::health_live,
        routes::health::health_ready,
        routes::health::metrics,
        // Auth
        routes::auth::auth_hello,
        routes::auth::auth_verify,
        routes::auth::refresh_session,
        routes::auth::revoked_keys,
        routes::auth::revoke_key,
        // Chains
        routes::chains::list_chains,
        routes::chains::derive_address,
        // Wallets
        routes::wallets::create_wallet,
        routes::wallets::list_wallets,
        routes::wallets::get_wallet,
        routes::wallets::sign_message,
        routes::wallets::refresh_wallet,
        routes::wallets::freeze_wallet,
        routes::wallets::unfreeze_wallet,
        // Transactions
        routes::transactions::create_transaction,
        routes::transactions::simulate_transaction,
    ),
    components(schemas(
        // Response types
        models::response::ApiResponse<models::response::HealthResponse>,
        models::response::HealthResponse,
        models::response::WalletResponse,
        models::response::WalletListResponse,
        models::response::WalletDetailResponse,
        models::response::AddressEntry,
        models::response::SignResponse,
        models::response::TransactionResponse,
        models::response::SimulationResponse,
        models::response::ChainInfo,
        models::response::ChainsListResponse,
        // Request types
        models::request::CreateWalletRequest,
        models::request::SignRequest,
        models::request::TransactionRequest,
        models::request::SimulateRequest,
        // Auth types
        auth::types::ClientHello,
        auth::types::ServerHello,
        auth::types::SessionEstablished,
        auth::types::ClientAuth,
        auth::types::KeyExchangeAlgorithm,
        auth::types::SignatureAlgorithm,
        auth::types::AeadAlgorithm,
        routes::auth::AuthVerifyRequest,
        routes::auth::RefreshSessionRequest,
        routes::auth::RefreshSessionResponse,
        routes::auth::RevokeKeyRequest,
        // Health types
        routes::health::LivenessResponse,
        routes::health::ReadinessResponse,
        routes::health::ComponentStatuses,
        routes::health::ComponentStatus,
        // Error types
        errors::ErrorBody,
        errors::ErrorCode,
    )),
    tags(
        (name = "Health", description = "Health checks and metrics"),
        (name = "Auth", description = "Authentication and session management"),
        (name = "Wallets", description = "MPC wallet operations"),
        (name = "Transactions", description = "Transaction building and simulation"),
        (name = "Chains", description = "Blockchain chain information"),
        (name = "Metrics", description = "Prometheus metrics export")
    ),
    security(
        ("session_token" = [])
    )
)]
pub struct ApiDoc;

/// Return the OpenAPI spec as a pretty-printed JSON string.
pub fn openapi_spec_json() -> String {
    serde_json::to_string_pretty(&ApiDoc::openapi()).expect("OpenAPI spec must serialize to JSON")
}

/// Serve the OpenAPI JSON spec.
async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
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
        .route(
            "/v1/auth/refresh-session",
            post(routes::auth::refresh_session),
        )
        .route("/v1/auth/revoked-keys", get(routes::auth::revoked_keys))
        .with_state(auth_state);

    // Public routes (no auth required) — health, chains, docs, and auth handshake.
    let public_routes = Router::new()
        .route("/v1/health", get(routes::health::health))
        .route("/v1/health/live", get(routes::health::health_live))
        .route("/v1/health/ready", get(routes::health::health_ready))
        .route("/v1/chains", get(routes::chains::list_chains))
        .route("/v1/api-docs/openapi.json", get(openapi_json));

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_spec_has_all_endpoints() {
        let spec = ApiDoc::openapi();

        // Must be valid OpenAPI 3.1
        assert!(spec.info.version == "1.0.0", "spec version should be 1.0.0");
        assert_eq!(spec.info.title, "MPC Wallet API");

        let json = serde_json::to_value(&spec).expect("serialize spec");
        let paths_obj = json["paths"].as_object().expect("paths must be an object");
        let path_keys: Vec<&str> = paths_obj.keys().map(|k| k.as_str()).collect();

        // All 20 endpoints must be present
        let expected = vec![
            "/v1/health",
            "/v1/health/live",
            "/v1/health/ready",
            "/v1/metrics",
            "/v1/auth/hello",
            "/v1/auth/verify",
            "/v1/auth/refresh-session",
            "/v1/auth/revoked-keys",
            "/v1/auth/revoke-key",
            "/v1/chains",
            "/v1/chains/{chain}/address/{id}",
            "/v1/wallets",
            "/v1/wallets/{id}",
            "/v1/wallets/{id}/sign",
            "/v1/wallets/{id}/transactions",
            "/v1/wallets/{id}/simulate",
            "/v1/wallets/{id}/refresh",
            "/v1/wallets/{id}/freeze",
            "/v1/wallets/{id}/unfreeze",
        ];

        for ep in &expected {
            assert!(
                path_keys.iter().any(|k| k == ep),
                "missing endpoint in OpenAPI spec: {ep}"
            );
        }

        assert!(
            path_keys.len() >= 19,
            "should have at least 19 unique paths (some share GET+POST), got {}",
            path_keys.len()
        );
    }

    #[test]
    fn test_openapi_spec_json_serializes() {
        let spec = ApiDoc::openapi();
        let json =
            serde_json::to_string_pretty(&spec).expect("OpenAPI spec must serialize to JSON");
        assert!(json.contains("\"openapi\""));
        assert!(json.contains("MPC Wallet API"));
        assert!(json.len() > 1000, "spec should be substantial");
    }

    /// Write the OpenAPI spec to `docs/openapi.json`.
    /// Run with: cargo test -p mpc-wallet-api export_openapi_spec -- --ignored
    #[test]
    #[ignore]
    fn export_openapi_spec() {
        let json = openapi_spec_json();

        // Validate basics before writing
        assert!(json.contains("\"openapi\""), "must contain openapi key");
        assert!(json.contains("/v1/health"), "must contain health endpoint");
        assert!(
            json.contains("/v1/wallets"),
            "must contain wallets endpoint"
        );

        // Write to docs/openapi.json (relative to workspace root)
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
        let output_path = workspace_root.join("docs").join("openapi.json");

        std::fs::write(&output_path, &json)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", output_path.display()));

        println!("OpenAPI spec exported to {}", output_path.display());
        assert!(output_path.exists());
    }
}
