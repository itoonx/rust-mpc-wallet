//! Standard generic error types for the API gateway.
//!
//! `ApiError` provides:
//! - Machine-readable `ErrorCode` (SCREAMING_SNAKE_CASE in JSON)
//! - Automatic HTTP status code mapping via `IntoResponse`
//! - Structured JSON error responses
//! - `From<CoreError>` for automatic conversion from core errors

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use mpc_wallet_core::error::CoreError;
use serde::Serialize;
use utoipa::ToSchema;

/// Machine-readable error code for programmatic client handling.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    // Auth
    AuthFailed,
    AuthRateLimited,

    // Permission
    PermissionDenied,
    MfaRequired,

    // Validation
    InvalidInput,
    InvalidConfig,

    // Resource
    NotFound,

    // Business logic
    PolicyDenied,
    ApprovalRequired,
    SessionError,
    KeyFrozen,

    // Crypto / Protocol
    ProtocolError,
    CryptoError,
    SerializationError,

    // Infra
    InternalError,
}

/// Structured error body in JSON responses.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

/// Structured API error response envelope.
#[derive(Debug, Serialize)]
struct ApiErrorResponse {
    success: bool,
    error: ErrorBody,
}

/// The standard API error type.
///
/// Implements `IntoResponse` so route handlers can return `Result<..., ApiError>`.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, ErrorCode::AuthFailed, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, ErrorCode::PermissionDenied, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, message)
    }

    pub fn rate_limited() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::AuthRateLimited,
            "rate limit exceeded",
        )
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::InternalError,
            message,
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ApiErrorResponse {
            success: false,
            error: ErrorBody {
                code: self.code,
                message: self.message,
            },
        };
        (self.status, Json(body)).into_response()
    }
}

impl From<CoreError> for ApiError {
    fn from(err: CoreError) -> Self {
        let message = err.to_string();
        match err {
            CoreError::Unauthorized(_) => {
                Self::new(StatusCode::FORBIDDEN, ErrorCode::PermissionDenied, message)
            }
            CoreError::InvalidInput(_) | CoreError::PasswordRequired(_) => {
                Self::bad_request(ErrorCode::InvalidInput, message)
            }
            CoreError::InvalidConfig(_) => Self::bad_request(ErrorCode::InvalidConfig, message),
            CoreError::NotFound(_) => Self::not_found(message),
            CoreError::PolicyRequired(_) => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorCode::PolicyDenied,
                message,
            ),
            CoreError::ApprovalRequired(_) => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorCode::ApprovalRequired,
                message,
            ),
            CoreError::SessionError(_) => Self::bad_request(ErrorCode::SessionError, message),
            CoreError::KeyFrozen(_) => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorCode::KeyFrozen,
                message,
            ),
            CoreError::Serialization(_) => {
                Self::bad_request(ErrorCode::SerializationError, message)
            }
            CoreError::EvmLowS(_) => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorCode::CryptoError,
                message,
            ),
            CoreError::Protocol(_) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::ProtocolError,
                message,
            ),
            CoreError::Crypto(_) | CoreError::Encryption(_) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::CryptoError,
                message,
            ),
            CoreError::Transport(_)
            | CoreError::KeyStore(_)
            | CoreError::AuditError(_)
            | CoreError::Other(_) => Self::internal(message),
        }
    }
}
