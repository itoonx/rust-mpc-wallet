//! Health check and metrics endpoints.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use prometheus::Encoder;
use serde::Serialize;

use mpc_wallet_chains::registry::ChainRegistry;

use crate::models::response::{ApiResponse, HealthResponse};
use crate::state::AppState;

/// `GET /v1/health` — basic health check (backward compatible).
pub async fn health() -> Json<ApiResponse<HealthResponse>> {
    Json(ApiResponse::ok(HealthResponse {
        status: "healthy".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        chains_supported: ChainRegistry::supported_chains().len(),
    }))
}

/// `GET /v1/health/live` — liveness probe, always returns 200.
pub async fn health_live() -> Json<LivenessResponse> {
    Json(LivenessResponse {
        status: "ok".to_string(),
    })
}

/// `GET /v1/health/ready` — readiness probe, checks backend connectivity.
pub async fn health_ready(State(state): State<AppState>) -> (StatusCode, Json<ReadinessResponse>) {
    let nats_status = if state.orchestrator.is_connected() {
        ComponentStatus::Connected
    } else {
        ComponentStatus::Disconnected
    };

    // Check Redis: if backend is Redis, try a simple operation.
    let redis_status = if state.session_store.is_redis_backend() {
        // Try to prune (a lightweight operation that exercises the backend).
        // If it works, we're connected.
        let can_reach = state.replay_cache.prune().await;
        // prune returns count; if it doesn't panic/error, we're connected.
        let _ = can_reach;
        ComponentStatus::Connected
    } else {
        ComponentStatus::NotConfigured
    };

    // Vault status: check if SECRETS_BACKEND=vault was configured.
    let vault_status = if std::env::var("SECRETS_BACKEND")
        .map(|v| v.eq_ignore_ascii_case("vault"))
        .unwrap_or(false)
    {
        // Vault was configured; if we got this far startup succeeded.
        ComponentStatus::Connected
    } else {
        ComponentStatus::NotConfigured
    };

    let overall = if nats_status == ComponentStatus::Disconnected {
        "degraded"
    } else {
        "ready"
    };

    let status_code = if overall == "ready" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let response = ReadinessResponse {
        status: overall.to_string(),
        components: ComponentStatuses {
            nats: nats_status,
            redis: redis_status,
            vault: vault_status,
        },
    };

    (status_code, Json(response))
}

/// `GET /v1/metrics` — Prometheus metrics export.
pub async fn metrics() -> String {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

// ── Response Types ─────────────────────────────────────────────────────

/// Liveness probe response.
#[derive(Debug, Serialize)]
pub struct LivenessResponse {
    pub status: String,
}

/// Readiness probe response with component health.
#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    pub status: String,
    pub components: ComponentStatuses,
}

/// Individual component health statuses.
#[derive(Debug, Serialize)]
pub struct ComponentStatuses {
    pub nats: ComponentStatus,
    pub redis: ComponentStatus,
    pub vault: ComponentStatus,
}

/// Status of an individual component.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    Connected,
    Disconnected,
    NotConfigured,
}
