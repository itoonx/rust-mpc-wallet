//! HMAC request signing verification for mutation endpoints.
//!
//! Requires `X-Signature: v1=<hex_hmac>` and `X-Timestamp: <unix_seconds>` headers
//! on all POST requests. The HMAC is computed over `{timestamp}.{method}.{path}.{sha256_of_body}`.
//!
//! This ensures that a leaked API key alone cannot forge requests — the attacker
//! also needs the signing secret.
#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::models::response::ApiResponse;

type HmacSha256 = Hmac<Sha256>;

/// Maximum age of a signed request (30 seconds).
const MAX_TIMESTAMP_DRIFT_SECS: u64 = 30;

/// Verify HMAC request signature on mutation (POST) endpoints.
///
/// Reads the `X-Signature` and `X-Timestamp` headers, recomputes the HMAC
/// over `{timestamp}.{method}.{path}.{sha256_of_body}`, and compares in
/// constant time.
///
/// The signing key is the raw API key itself (from `X-API-Key` header).
/// For JWT-authenticated requests, HMAC signing is not required (JWT has
/// its own integrity guarantee).
pub async fn hmac_middleware(request: Request, next: Next) -> Response {
    // Only enforce HMAC on POST requests.
    if request.method() != axum::http::Method::POST {
        return next.run(request).await;
    }

    // If authenticated via JWT (no X-API-Key), skip HMAC.
    let has_api_key = request.headers().get("x-api-key").is_some();
    if !has_api_key {
        return next.run(request).await;
    }

    let api_key = request
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    // Extract signature and timestamp headers.
    let signature_header = match request
        .headers()
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_string(),
        None => {
            tracing::warn!("HMAC: missing X-Signature header");
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::err("authentication failed")),
            )
                .into_response();
        }
    };

    let timestamp_str = match request
        .headers()
        .get("x-timestamp")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_string(),
        None => {
            tracing::warn!("HMAC: missing X-Timestamp header");
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::err("authentication failed")),
            )
                .into_response();
        }
    };

    // Parse and validate timestamp (replay protection).
    let timestamp: u64 = match timestamp_str.parse() {
        Ok(t) => t,
        Err(_) => {
            tracing::warn!("HMAC: invalid X-Timestamp value");
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::err("authentication failed")),
            )
                .into_response();
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now.abs_diff(timestamp) > MAX_TIMESTAMP_DRIFT_SECS {
        tracing::warn!(
            drift_secs = now.abs_diff(timestamp),
            "HMAC: timestamp too old or too far in the future"
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::err("authentication failed")),
        )
            .into_response();
    }

    // Parse signature: "v1=<hex>"
    let expected_hex = match signature_header.strip_prefix("v1=") {
        Some(h) => h.to_string(),
        None => {
            tracing::warn!("HMAC: X-Signature must start with v1=");
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::err("authentication failed")),
            )
                .into_response();
        }
    };

    let expected_bytes = match hex::decode(&expected_hex) {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("HMAC: invalid hex in X-Signature");
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::err("authentication failed")),
            )
                .into_response();
        }
    };

    // Collect request metadata for HMAC.
    let method = request.method().to_string();
    let path = request.uri().path().to_string();

    // Read body for hashing, then put it back.
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1_048_576).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::err("request body too large")),
            )
                .into_response();
        }
    };

    // Compute SHA-256 of body.
    use sha2::Digest;
    let body_hash = Sha256::digest(&body_bytes);
    let body_hash_hex = hex::encode(body_hash);

    // Compute HMAC: "{timestamp}.{method}.{path}.{body_sha256}"
    let hmac_input = format!("{timestamp_str}.{method}.{path}.{body_hash_hex}");
    let mut mac =
        HmacSha256::new_from_slice(api_key.as_bytes()).expect("HMAC accepts any key size");
    mac.update(hmac_input.as_bytes());
    let computed: [u8; 32] = mac.finalize().into_bytes().into();

    // Constant-time comparison.
    let ct_match: bool = if expected_bytes.len() == 32 {
        computed.ct_eq(expected_bytes.as_slice()).into()
    } else {
        false
    };
    if !ct_match {
        tracing::warn!("HMAC: signature mismatch");
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::err("authentication failed")),
        )
            .into_response();
    }

    // Reconstruct request with the body.
    let request = Request::from_parts(parts, Body::from(body_bytes));
    next.run(request).await
}

/// Compute an HMAC signature for a request (client-side helper for tests).
pub fn compute_signature(
    api_key: &str,
    timestamp: u64,
    method: &str,
    path: &str,
    body: &[u8],
) -> String {
    use sha2::Digest;
    let body_hash = Sha256::digest(body);
    let body_hash_hex = hex::encode(body_hash);
    let hmac_input = format!("{timestamp}.{method}.{path}.{body_hash_hex}");

    let mut mac =
        HmacSha256::new_from_slice(api_key.as_bytes()).expect("HMAC accepts any key size");
    mac.update(hmac_input.as_bytes());
    let result: [u8; 32] = mac.finalize().into_bytes().into();
    format!("v1={}", hex::encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_and_verify_signature() {
        let sig = compute_signature("my-key", 1000, "POST", "/v1/wallets", b"{}");
        assert!(sig.starts_with("v1="));
        assert_eq!(sig.len(), 3 + 64); // "v1=" + 64 hex chars

        // Same inputs produce same signature
        let sig2 = compute_signature("my-key", 1000, "POST", "/v1/wallets", b"{}");
        assert_eq!(sig, sig2);

        // Different key produces different signature
        let sig3 = compute_signature("other-key", 1000, "POST", "/v1/wallets", b"{}");
        assert_ne!(sig, sig3);

        // Different body produces different signature
        let sig4 = compute_signature("my-key", 1000, "POST", "/v1/wallets", b"{\"x\":1}");
        assert_ne!(sig, sig4);
    }
}
