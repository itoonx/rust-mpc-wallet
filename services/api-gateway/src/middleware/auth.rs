//! Authentication middleware: JWT Bearer tokens and API key validation.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::models::response::ApiResponse;
use crate::state::AppState;

/// Authentication middleware that checks for either:
/// - `Authorization: Bearer <jwt>` header (user-facing)
/// - `X-API-Key: <key>` header (service-to-service)
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();

    // Check X-API-Key first (simpler, service-to-service).
    if let Some(api_key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        if state.api_keys.contains(&api_key.to_string()) {
            return next.run(request).await;
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::err("invalid API key")),
        )
            .into_response();
    }

    // Check Authorization: Bearer <jwt>.
    if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            match state.jwt_validator.validate(token) {
                Ok(_ctx) => return next.run(request).await,
                Err(e) => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(ApiResponse::<()>::err(format!("JWT error: {e}"))),
                    )
                        .into_response();
                }
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(ApiResponse::<()>::err(
            "missing Authorization header or X-API-Key",
        )),
    )
        .into_response()
}
