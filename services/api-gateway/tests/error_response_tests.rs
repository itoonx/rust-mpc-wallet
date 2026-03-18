//! # Standard Error Response — Integration Tests
//!
//! Verifies that all API error responses follow the structured format:
//! ```json
//! { "success": false, "error": { "code": "ERROR_CODE", "message": "..." } }
//! ```
//!
//! Tests cover:
//! - Error response structure (code + message fields present)
//! - Correct error codes for each failure scenario
//! - HTTP status code mapping
//! - Auth errors return generic messages (no info leak)
//! - CoreError → ApiError conversion produces correct codes

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use mpc_wallet_api::auth::client::HandshakeClient;
use mpc_wallet_api::auth::handshake::ServerHandshake;
use mpc_wallet_api::auth::types::*;
use mpc_wallet_api::build_router;

// ── Helpers ──────────────────────────────────────────────────────────

async fn test_app() -> (axum::Router, mpc_wallet_api::state::AppState) {
    let config = mpc_wallet_api::config::AppConfig::for_test();
    let state = mpc_wallet_api::state::AppState::from_config(&config).await;
    let router = build_router(state.clone(), &[]);
    (router, state)
}

async fn test_router() -> axum::Router {
    test_app().await.0
}

/// Perform a full handshake via server state and return session token.
async fn do_handshake(state: &mpc_wallet_api::state::AppState) -> String {
    let client_key = gen_ed25519_key();
    let client = HandshakeClient::new(client_key, None);
    let bundle = client.build_client_hello();

    let mut server_hs = ServerHandshake::new_arc(state.server_signing_key.clone());
    let server_hello = server_hs
        .process_client_hello(&bundle.client_hello)
        .unwrap();

    let (client_auth, _derived) = client
        .process_server_hello(
            &bundle.client_hello,
            &server_hello,
            bundle.ephemeral_secret,
            &bundle.client_nonce,
        )
        .unwrap();

    let session = server_hs
        .process_client_auth(&client_auth, &bundle.client_hello, 3600)
        .unwrap();

    let session_id = session.session_id.clone();
    state.session_store.store(session).await;
    session_id
}

fn json_post(uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn get_with_session(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .method("GET")
        .header("x-session-token", token)
        .body(Body::empty())
        .unwrap()
}

fn post_with_session(uri: &str, token: &str, body: String) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .method("POST")
        .header("x-session-token", token)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Assert the error response has the standard structure.
fn assert_error_structure(json: &Value, expected_code: &str) {
    assert_eq!(
        json["success"].as_bool(),
        Some(false),
        "success must be false"
    );
    assert!(
        json["error"].is_object(),
        "error must be an object, got: {}",
        json["error"]
    );
    assert_eq!(
        json["error"]["code"].as_str(),
        Some(expected_code),
        "expected error code {expected_code}, got: {}",
        json["error"]["code"]
    );
    assert!(
        json["error"]["message"].as_str().is_some(),
        "error.message must be a string"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 1. Error Response Structure
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_error_response_has_code_and_message() {
    let app = test_router().await;

    // Unauthenticated request → should get structured error
    let req = Request::builder()
        .uri("/v1/wallets")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let json = body_json(resp).await;
    assert_error_structure(&json, "AUTH_FAILED");
    assert_eq!(
        json["error"]["message"].as_str().unwrap(),
        "authentication failed"
    );
}

#[tokio::test]
async fn test_error_response_has_no_data_field() {
    let app = test_router().await;

    let req = Request::builder()
        .uri("/v1/wallets")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let json = body_json(resp).await;

    // Error responses should NOT have a data field
    assert!(json.get("data").is_none() || json["data"].is_null());
}

// ═══════════════════════════════════════════════════════════════════════
// 2. AUTH_FAILED — 401
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_auth_failed_no_token() {
    let app = test_router().await;
    let req = Request::builder()
        .uri("/v1/wallets")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json = body_json(resp).await;
    assert_error_structure(&json, "AUTH_FAILED");
}

#[tokio::test]
async fn test_auth_failed_invalid_session_token() {
    let app = test_router().await;
    let req = get_with_session("/v1/wallets", "invalid-token-here");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json = body_json(resp).await;
    assert_error_structure(&json, "AUTH_FAILED");
}

#[tokio::test]
async fn test_auth_failed_empty_session_token() {
    let app = test_router().await;
    let req = get_with_session("/v1/wallets", "");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json = body_json(resp).await;
    assert_error_structure(&json, "AUTH_FAILED");
}

#[tokio::test]
async fn test_auth_error_message_is_generic() {
    let app = test_router().await;

    // Different auth failure causes should all return same generic message
    let scenarios = vec![
        ("no-token", ""),
        ("bad-token", "definitely-not-valid"),
        ("expired-token", "expired.jwt.token"),
    ];

    for (label, token) in scenarios {
        let req = if token.is_empty() {
            Request::builder()
                .uri("/v1/wallets")
                .method("GET")
                .body(Body::empty())
                .unwrap()
        } else {
            get_with_session("/v1/wallets", token)
        };

        let resp = app.clone().oneshot(req).await.unwrap();
        let json = body_json(resp).await;
        assert_eq!(
            json["error"]["message"].as_str().unwrap(),
            "authentication failed",
            "auth error for '{label}' must be generic — no info leak"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 3. AUTH_RATE_LIMITED — 429
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_rate_limit_returns_correct_error_code() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let client = HandshakeClient::new(client_key, None);

    // Exhaust rate limit (10 req/sec per key_id)
    for _ in 0..15 {
        let bundle = client.build_client_hello();
        let body = serde_json::to_string(&bundle.client_hello).unwrap();
        let req = json_post("/v1/auth/hello", body);
        let resp = app.clone().oneshot(req).await.unwrap();

        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            let json = body_json(resp).await;
            assert_error_structure(&json, "AUTH_RATE_LIMITED");
            assert_eq!(
                json["error"]["message"].as_str().unwrap(),
                "rate limit exceeded"
            );
            return;
        }
    }
    // Rate limit should have triggered within 15 requests
    panic!("rate limit was not triggered after 15 requests");
}

// ═══════════════════════════════════════════════════════════════════════
// 4. PERMISSION_DENIED / MFA_REQUIRED — 403
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_permission_denied_for_create_wallet() {
    let (app, state) = test_app().await;
    let token = do_handshake(&state).await;

    // Viewer role trying to create wallet (requires admin+MFA) → 403
    let body = serde_json::json!({
        "label": "test",
        "scheme": "gg20-ecdsa",
        "threshold": 2,
        "total_parties": 3
    });
    let req = post_with_session("/v1/wallets", &token, serde_json::to_string(&body).unwrap());
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let json = body_json(resp).await;
    assert!(
        json["error"]["code"].as_str().unwrap() == "MFA_REQUIRED"
            || json["error"]["code"].as_str().unwrap() == "PERMISSION_DENIED",
        "expected PERMISSION_DENIED or MFA_REQUIRED, got: {}",
        json["error"]["code"]
    );
}

#[tokio::test]
async fn test_permission_denied_for_revoke_key() {
    let (app, state) = test_app().await;
    let token = do_handshake(&state).await;

    // Viewer role trying to revoke key (requires admin) → 403
    let body = serde_json::json!({ "key_id": "some-key" });
    let req = post_with_session(
        "/v1/auth/revoke-key",
        &token,
        serde_json::to_string(&body).unwrap(),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let json = body_json(resp).await;
    assert_error_structure(&json, "PERMISSION_DENIED");
}

// ═══════════════════════════════════════════════════════════════════════
// 5. INVALID_INPUT — 400
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_invalid_input_bad_chain_name() {
    let (app, state) = test_app().await;
    let token = do_handshake(&state).await;

    let body = serde_json::json!({
        "chain": "not-a-real-chain",
        "to": "0x1234",
        "value": "1000"
    });
    let req = post_with_session(
        "/v1/wallets/test-id/simulate",
        &token,
        serde_json::to_string(&body).unwrap(),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    assert_error_structure(&json, "INVALID_INPUT");
}

#[tokio::test]
async fn test_sign_requires_initiator_role() {
    let (app, state) = test_app().await;
    let token = do_handshake(&state).await;

    // Viewer role trying to sign → 403 before hex validation
    let body = serde_json::json!({ "message": "deadbeef" });
    let req = post_with_session(
        "/v1/wallets/test-id/sign",
        &token,
        serde_json::to_string(&body).unwrap(),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let json = body_json(resp).await;
    assert_error_structure(&json, "PERMISSION_DENIED");
}

#[tokio::test]
async fn test_invalid_input_bad_hex_data_in_simulate() {
    let (app, state) = test_app().await;
    let token = do_handshake(&state).await;

    let body = serde_json::json!({
        "chain": "ethereum",
        "to": "0x1234567890123456789012345678901234567890",
        "value": "1000",
        "data": "0xZZZZZZ"
    });
    let req = post_with_session(
        "/v1/wallets/test-id/simulate",
        &token,
        serde_json::to_string(&body).unwrap(),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    assert_error_structure(&json, "INVALID_INPUT");
}

#[tokio::test]
async fn test_transaction_requires_initiator_role() {
    let (app, state) = test_app().await;
    let token = do_handshake(&state).await;

    // Viewer role trying to create transaction → 403
    let body = serde_json::json!({
        "chain": "ethereum",
        "to": "0x1234567890123456789012345678901234567890",
        "value": "1000"
    });
    let req = post_with_session(
        "/v1/wallets/test-id/transactions",
        &token,
        serde_json::to_string(&body).unwrap(),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let json = body_json(resp).await;
    assert_error_structure(&json, "PERMISSION_DENIED");
}

// ═══════════════════════════════════════════════════════════════════════
// 6. NOT_FOUND — 404
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_not_found_wallet() {
    let (app, state) = test_app().await;
    let token = do_handshake(&state).await;

    let req = get_with_session("/v1/wallets/nonexistent-wallet-id", &token);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let json = body_json(resp).await;
    assert_error_structure(&json, "NOT_FOUND");
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not found"));
}

// ═══════════════════════════════════════════════════════════════════════
// 7. Handshake errors return AUTH_FAILED
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_handshake_wrong_version_returns_auth_failed() {
    let app = test_router().await;

    let body = serde_json::json!({
        "protocol_version": "wrong-version",
        "supported_kex": ["x25519"],
        "supported_sig": ["ed25519"],
        "client_ephemeral_pubkey": "ab".repeat(32),
        "client_nonce": "cd".repeat(32),
        "timestamp": unix_now(),
        "client_key_id": "0000000000000000"
    });
    let req = json_post("/v1/auth/hello", serde_json::to_string(&body).unwrap());
    let resp = app.oneshot(req).await.unwrap();

    let json = body_json(resp).await;
    assert_error_structure(&json, "AUTH_FAILED");
    assert_eq!(
        json["error"]["message"].as_str().unwrap(),
        "authentication failed",
        "handshake error must not leak specific reason"
    );
}

#[tokio::test]
async fn test_verify_invalid_challenge_returns_auth_failed() {
    let app = test_router().await;

    let body = serde_json::json!({
        "server_challenge": "nonexistent-challenge",
        "client_signature": "ab".repeat(64),
        "client_static_pubkey": "cd".repeat(32)
    });
    let req = json_post("/v1/auth/verify", serde_json::to_string(&body).unwrap());
    let resp = app.oneshot(req).await.unwrap();

    let json = body_json(resp).await;
    assert_error_structure(&json, "AUTH_FAILED");
}

// ═══════════════════════════════════════════════════════════════════════
// 8. Success responses still work (no regression)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_success_response_format_unchanged() {
    let app = test_router().await;

    // Health endpoint — public, always succeeds
    let req = Request::builder()
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["success"].as_bool(), Some(true));
    assert!(json["data"].is_object());
    assert!(json.get("error").is_none() || json["error"].is_null());

    // Chains endpoint — public
    let req = Request::builder()
        .uri("/v1/chains")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["success"].as_bool(), Some(true));
    assert!(json["data"]["chains"].is_array());
}

#[tokio::test]
async fn test_handshake_success_returns_no_error() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let client = HandshakeClient::new(client_key, None);
    let bundle = client.build_client_hello();

    let body = serde_json::to_string(&bundle.client_hello).unwrap();
    let req = json_post("/v1/auth/hello", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["success"].as_bool(), Some(true));
    assert!(json["data"]["server_challenge"].is_string());
    assert!(json.get("error").is_none() || json["error"].is_null());
}

// ═══════════════════════════════════════════════════════════════════════
// 9. CoreError → ApiError conversion (via chain registry)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_invalid_chain_for_address_derivation() {
    let (app, state) = test_app().await;
    let token = do_handshake(&state).await;

    let req = Request::builder()
        .uri("/v1/chains/not-a-chain/address/test-wallet")
        .method("GET")
        .header("x-session-token", &token)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    assert_error_structure(&json, "INVALID_INPUT");
}
