//! Health check and metrics endpoints.

use axum::Json;
use prometheus::Encoder;

use mpc_wallet_chains::registry::ChainRegistry;

use crate::models::response::{ApiResponse, HealthResponse};

/// `GET /v1/health` — health check.
pub async fn health() -> Json<ApiResponse<HealthResponse>> {
    Json(ApiResponse::ok(HealthResponse {
        status: "healthy".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        chains_supported: ChainRegistry::supported_chains().len(),
    }))
}

/// `GET /v1/metrics` — Prometheus metrics export.
pub async fn metrics() -> String {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
