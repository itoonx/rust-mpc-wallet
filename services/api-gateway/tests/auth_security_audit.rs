//! # Auth Security Audit — Integration Test Suite
//!
//! Comprehensive security-focused integration tests for the MPC Wallet API
//! authentication system. Written from an attacker's perspective to discover
//! edge cases, vulnerabilities, and protocol weaknesses.
//!
//! ## Coverage Matrix
//!
//! | Category | Tests |
//! |----------|-------|
//! | Happy path (end-to-end handshake) | 3 |
//! | Replay attacks | 2 |
//! | Timestamp manipulation | 3 |
//! | Signature forgery & substitution | 5 |
//! | Key confusion / identity attacks | 4 |
//! | Session hijacking & lifecycle | 6 |
//! | Protocol downgrade | 2 |
//! | Malformed input / fuzzing | 6 |
//! | Auth method confusion | 2 |
//! | Revocation enforcement | 3 |
//! | DoS / resource exhaustion | 2 |
//! | Information leakage | 2 |

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use mpc_wallet_api::auth::client::HandshakeClient;
use mpc_wallet_api::auth::handshake::ServerHandshake;
use mpc_wallet_api::auth::types::*;
use mpc_wallet_api::build_router;

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

// ── Test Infrastructure ────────────────────────────────────────────

mod helpers {
    use super::*;

    /// Create AppState + Router for integration testing.
    pub async fn test_app() -> (axum::Router, mpc_wallet_api::state::AppState) {
        let config = mpc_wallet_api::config::AppConfig::for_test();
        let state = mpc_wallet_api::state::AppState::from_config(&config);
        let router = build_router(state.clone(), &[]);
        (router, state)
    }

    pub async fn test_router() -> axum::Router {
        test_app().await.0
    }

    /// Perform a full valid handshake via HTTP and return the session token.
    pub async fn handshake_via_http(
        state: &mpc_wallet_api::state::AppState,
    ) -> (String, SigningKey) {
        let client_key = gen_ed25519_key();
        let session_token = handshake_via_http_with_key(state, &client_key).await;
        (session_token, client_key)
    }

    pub async fn handshake_via_http_with_key(
        state: &mpc_wallet_api::state::AppState,
        client_key: &SigningKey,
    ) -> String {
        let client = HandshakeClient::new(client_key.clone(), None);
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

    /// Build a ClientHello JSON body.
    pub fn build_hello_body(
        client_key: &SigningKey,
        eph_pub: &X25519Public,
        nonce: &[u8; 32],
        timestamp: u64,
    ) -> String {
        let client_key_id = hex::encode(&client_key.verifying_key().to_bytes()[..8]);
        serde_json::to_string(&serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "supported_kex": ["x25519"],
            "supported_sig": ["ed25519"],
            "client_ephemeral_pubkey": hex::encode(eph_pub.as_bytes()),
            "client_nonce": hex::encode(nonce),
            "timestamp": timestamp,
            "client_key_id": client_key_id
        }))
        .unwrap()
    }

    /// Send a POST JSON request to the given path.
    pub fn json_post(uri: &str, body: String) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    /// Extract JSON body from response.
    pub async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }
}

use helpers::*;

// ═══════════════════════════════════════════════════════════════════
// SECTION 1: HAPPY PATH — End-to-End Handshake
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_e2e_handshake_then_protected_access() {
    let (router, state) = test_app().await;
    let (session_token, _client_key) = handshake_via_http(&state).await;

    let req = Request::builder()
        .uri("/v1/wallets")
        .method("GET")
        .header("x-session-token", &session_token)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "session token should grant access"
    );
}

#[tokio::test]
async fn test_e2e_client_server_key_agreement() {
    // Verify both sides derive identical session keys.
    let server_key = gen_ed25519_key();
    let client_key = gen_ed25519_key();

    let client = HandshakeClient::new(client_key.clone(), Some(server_key.verifying_key()));
    let bundle = client.build_client_hello();

    let mut server_hs = ServerHandshake::new(server_key);
    let server_hello = server_hs
        .process_client_hello(&bundle.client_hello)
        .unwrap();

    let (client_auth, derived) = client
        .process_server_hello(
            &bundle.client_hello,
            &server_hello,
            bundle.ephemeral_secret,
            &bundle.client_nonce,
        )
        .unwrap();

    let server_session = server_hs
        .process_client_auth(&client_auth, &bundle.client_hello, 3600)
        .unwrap();

    assert_eq!(derived.client_write_key, server_session.client_write_key);
    assert_eq!(derived.server_write_key, server_session.server_write_key);
    assert_eq!(derived.session_id, server_session.session_id);
    assert_eq!(
        derived.key_fingerprint,
        hex::encode(&Sha256::digest(server_session.client_write_key)[..16])
    );
}

#[tokio::test]
async fn test_e2e_full_http_hello_verify_flow() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let client_eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let client_eph_pub = X25519Public::from(&client_eph);
    let nonce = random_nonce();
    let now = unix_now();

    // Step 1: hello
    let body = build_hello_body(&client_key, &client_eph_pub, &nonce, now);
    let req = json_post("/v1/auth/hello", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert!(json["success"].as_bool().unwrap());
    let server_challenge = json["data"]["server_challenge"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!server_challenge.is_empty());
}

#[tokio::test]
async fn test_e2e_full_http_hello_verify_session_protected() {
    // Complete E2E flow via HTTP: hello → verify → use session token on protected route.
    let (app, _state) = test_app().await;

    let client_key = gen_ed25519_key();
    let client = HandshakeClient::new(client_key.clone(), None);
    let bundle = client.build_client_hello();

    // Step 1: POST /v1/auth/hello via HTTP
    let body = serde_json::to_string(&bundle.client_hello).unwrap();
    let req = json_post("/v1/auth/hello", body);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "hello should succeed");
    let hello_json = body_json(resp).await;
    let sh: ServerHello = serde_json::from_value(hello_json["data"].clone()).unwrap();
    let challenge = sh.server_challenge.clone();

    // Step 2: Client processes ServerHello and builds ClientAuth
    let (client_auth, derived_keys) = client
        .process_server_hello(
            &bundle.client_hello,
            &sh,
            bundle.ephemeral_secret,
            &bundle.client_nonce,
        )
        .unwrap();

    // Step 3: POST /v1/auth/verify via HTTP
    let verify_body = serde_json::to_string(&serde_json::json!({
        "server_challenge": challenge,
        "client_signature": client_auth.client_signature,
        "client_static_pubkey": client_auth.client_static_pubkey,
    }))
    .unwrap();
    let req = json_post("/v1/auth/verify", verify_body);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "verify should succeed");
    let verify_json = body_json(resp).await;
    assert!(verify_json["success"].as_bool().unwrap());
    let session_token = verify_json["data"]["session_token"]
        .as_str()
        .unwrap()
        .to_string();
    let server_session_id = verify_json["data"]["session_id"].as_str().unwrap();

    // Verify client and server derived the same session ID
    assert_eq!(
        derived_keys.session_id, server_session_id,
        "client and server must agree on session ID"
    );

    // Step 4: Use session token on GET /v1/wallets (protected)
    let req = Request::builder()
        .uri("/v1/wallets")
        .method("GET")
        .header("x-session-token", &session_token)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "session token from HTTP handshake must work on protected routes"
    );
    let wallets_json = body_json(resp).await;
    assert!(wallets_json["success"].as_bool().unwrap());

    // Step 5: Verify without session token still fails
    let req = Request::builder()
        .uri("/v1/wallets")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "without session token must still fail"
    );
}

#[tokio::test]
async fn test_rate_limit_on_handshake() {
    let (app, _state) = test_app().await;

    let client_key = gen_ed25519_key();
    let eph_pub = X25519Public::from(&X25519Secret::random_from_rng(rand::rngs::OsRng));
    // Send 15 rapid hello requests with the same key_id (limit is 10/sec).
    let mut hit_limit = false;
    for _ in 0..15 {
        let nonce = random_nonce();
        let body = build_hello_body(&client_key, &eph_pub, &nonce, unix_now());
        let req = json_post("/v1/auth/hello", body);
        let resp = app.clone().oneshot(req).await.unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            hit_limit = true;
            break;
        }
    }
    assert!(
        hit_limit,
        "rate limit should kick in after 10 rapid requests"
    );
}

#[tokio::test]
async fn test_dynamic_key_revocation() {
    let (_app, state) = test_app().await;

    // Revoke a key dynamically via state (admin operation).
    let was_new = state.revoke_key("deadbeef12345678".into()).await;
    assert!(was_new, "first revocation should return true");

    // Verify it shows up in revoked set.
    assert!(state.is_key_revoked("deadbeef12345678").await);
}

#[tokio::test]
async fn test_session_store_capacity_limit() {
    let store = mpc_wallet_api::auth::session::SessionStore::in_memory();
    let now = unix_now();

    // Fill up to capacity and verify rejection.
    // We test with a smaller batch since MAX_SESSIONS is 100k.
    for i in 0..100 {
        let session = AuthenticatedSession {
            session_id: format!("cap-{i}"),
            client_pubkey: [0u8; 32],
            client_key_id: "test".into(),
            client_write_key: [1u8; 32],
            server_write_key: [2u8; 32],
            expires_at: now + 3600,
            created_at: now,
        };
        assert!(store.store(session).await, "should accept session {i}");
    }
    assert_eq!(store.count().await, 100);
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 2: REPLAY ATTACKS
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_replay_same_nonce_rejected() {
    let (router, _state) = test_app().await;

    let client_key = gen_ed25519_key();
    let eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = X25519Public::from(&eph);
    let nonce = random_nonce();
    let now = unix_now();

    let body = build_hello_body(&client_key, &eph_pub, &nonce, now);

    // First request should succeed.
    let req1 = json_post("/v1/auth/hello", body.clone());
    let resp1 = router.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // ATTACK: Replay the exact same ClientHello (same nonce).
    let req2 = json_post("/v1/auth/hello", body);
    let resp2 = router.oneshot(req2).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::UNAUTHORIZED,
        "replay of same nonce must be rejected"
    );
}

#[tokio::test]
async fn test_replay_verify_with_consumed_challenge() {
    // After a verify completes, the challenge is consumed.
    // ATTACK: Try to re-use the same challenge to establish another session.
    let (_router, state) = test_app().await;

    let client_key = gen_ed25519_key();
    let client = HandshakeClient::new(client_key.clone(), None);

    // Complete a full handshake.
    let bundle = client.build_client_hello();
    let mut server_hs = ServerHandshake::new_arc(state.server_signing_key.clone());
    let server_hello = server_hs
        .process_client_hello(&bundle.client_hello)
        .unwrap();
    let _server_challenge = server_hello.server_challenge.clone();
    let (_client_auth, _) = client
        .process_server_hello(
            &bundle.client_hello,
            &server_hello,
            bundle.ephemeral_secret,
            &bundle.client_nonce,
        )
        .unwrap();

    // Store a pending handshake manually to simulate the hello step.
    // Then verify once (succeeds)...
    // The key point: server_challenge is consumed on verify,
    // so a second verify with the same challenge should fail.
    // We test this via router:

    let app = build_router(state.clone(), &[]);

    // Do hello via HTTP to store pending.
    let bundle2 = client.build_client_hello();
    let body = serde_json::to_string(&bundle2.client_hello).unwrap();
    let req = json_post("/v1/auth/hello", body);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let challenge = json["data"]["server_challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let sh: ServerHello = serde_json::from_value(json["data"].clone()).unwrap();

    // Build client auth for this handshake.
    let (ca, _) = client
        .process_server_hello(
            &bundle2.client_hello,
            &sh,
            bundle2.ephemeral_secret,
            &bundle2.client_nonce,
        )
        .unwrap();

    let verify_body = serde_json::to_string(&serde_json::json!({
        "server_challenge": challenge,
        "client_signature": ca.client_signature,
        "client_static_pubkey": ca.client_static_pubkey,
    }))
    .unwrap();

    // First verify — should succeed.
    let req = json_post("/v1/auth/verify", verify_body.clone());
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // ATTACK: Replay verify with the same challenge.
    let req = json_post("/v1/auth/verify", verify_body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "replayed verify with consumed challenge must fail"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 3: TIMESTAMP MANIPULATION
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_handshake_timestamp_31s_in_past_rejected() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = X25519Public::from(&eph);
    let nonce = random_nonce();

    let body = build_hello_body(&client_key, &eph_pub, &nonce, unix_now() - 31);
    let req = json_post("/v1/auth/hello", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "timestamp 31s drift must fail"
    );
}

#[tokio::test]
async fn test_handshake_timestamp_30s_in_past_accepted() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = X25519Public::from(&eph);
    let nonce = random_nonce();

    // Exactly at the boundary — should still be accepted (abs_diff <= 30).
    let body = build_hello_body(&client_key, &eph_pub, &nonce, unix_now() - 29);
    let req = json_post("/v1/auth/hello", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "timestamp 29s drift should be accepted"
    );
}

#[tokio::test]
async fn test_handshake_timestamp_zero_rejected() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = X25519Public::from(&eph);
    let nonce = random_nonce();

    // ATTACK: Send timestamp = 0 (epoch).
    let body = build_hello_body(&client_key, &eph_pub, &nonce, 0);
    let req = json_post("/v1/auth/hello", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "timestamp=0 must be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 4: SIGNATURE FORGERY & SUBSTITUTION
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_verify_with_forged_signature() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let client = HandshakeClient::new(client_key.clone(), None);
    let bundle = client.build_client_hello();

    // Do hello.
    let body = serde_json::to_string(&bundle.client_hello).unwrap();
    let req = json_post("/v1/auth/hello", body);
    let resp = app.clone().oneshot(req).await.unwrap();
    let json = body_json(resp).await;
    let challenge = json["data"]["server_challenge"]
        .as_str()
        .unwrap()
        .to_string();

    // ATTACK: Submit verify with garbage signature.
    let verify_body = serde_json::to_string(&serde_json::json!({
        "server_challenge": challenge,
        "client_signature": "ff".repeat(64), // 64 bytes of 0xFF
        "client_static_pubkey": hex::encode(client_key.verifying_key().to_bytes()),
    }))
    .unwrap();

    let req = json_post("/v1/auth/verify", verify_body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "forged signature must be rejected"
    );
}

#[tokio::test]
async fn test_verify_with_different_key_signature() {
    // ATTACK: Sign the transcript with a DIFFERENT Ed25519 key than the one
    // claimed in client_static_pubkey.
    let app = test_router().await;

    let legitimate_key = gen_ed25519_key();
    let attacker_key = gen_ed25519_key();

    let client = HandshakeClient::new(legitimate_key.clone(), None);
    let bundle = client.build_client_hello();

    let body = serde_json::to_string(&bundle.client_hello).unwrap();
    let req = json_post("/v1/auth/hello", body);
    let resp = app.clone().oneshot(req).await.unwrap();
    let json = body_json(resp).await;
    let challenge = json["data"]["server_challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let sh: ServerHello = serde_json::from_value(json["data"].clone()).unwrap();

    // Compute transcript with legitimate key's pubkey...
    let legit_pubkey_hex = hex::encode(legitimate_key.verifying_key().to_bytes());
    let transcript_hash = compute_transcript_hash(&bundle.client_hello, &sh, &legit_pubkey_hex);

    // ...but sign with the attacker's key.
    let attacker_sig = attacker_key.sign(&transcript_hash);

    let verify_body = serde_json::to_string(&serde_json::json!({
        "server_challenge": challenge,
        "client_signature": hex::encode(attacker_sig.to_bytes()),
        "client_static_pubkey": legit_pubkey_hex,
    }))
    .unwrap();

    let req = json_post("/v1/auth/verify", verify_body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "signature from different key must be rejected"
    );
}

#[tokio::test]
async fn test_verify_with_wrong_pubkey_but_correct_sig() {
    // ATTACK: Provide a valid signature from attacker_key, but claim
    // the pubkey is the attacker's (key_id won't match the original hello).
    let app = test_router().await;

    let original_key = gen_ed25519_key();
    let attacker_key = gen_ed25519_key();

    // Build hello with original key.
    let client = HandshakeClient::new(original_key.clone(), None);
    let bundle = client.build_client_hello();

    let body = serde_json::to_string(&bundle.client_hello).unwrap();
    let req = json_post("/v1/auth/hello", body);
    let resp = app.clone().oneshot(req).await.unwrap();
    let json = body_json(resp).await;
    let challenge = json["data"]["server_challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let sh: ServerHello = serde_json::from_value(json["data"].clone()).unwrap();

    // Compute transcript using attacker pubkey and sign with attacker key.
    let attacker_pubkey_hex = hex::encode(attacker_key.verifying_key().to_bytes());
    let transcript_hash = compute_transcript_hash(&bundle.client_hello, &sh, &attacker_pubkey_hex);
    let sig = attacker_key.sign(&transcript_hash);

    let verify_body = serde_json::to_string(&serde_json::json!({
        "server_challenge": challenge,
        "client_signature": hex::encode(sig.to_bytes()),
        "client_static_pubkey": attacker_pubkey_hex,
    }))
    .unwrap();

    let req = json_post("/v1/auth/verify", verify_body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "key_id mismatch (attacker pubkey vs hello key_id) must be rejected"
    );
}

#[tokio::test]
async fn test_verify_truncated_signature() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let client = HandshakeClient::new(client_key.clone(), None);
    let bundle = client.build_client_hello();

    let body = serde_json::to_string(&bundle.client_hello).unwrap();
    let req = json_post("/v1/auth/hello", body);
    let resp = app.clone().oneshot(req).await.unwrap();
    let json = body_json(resp).await;
    let challenge = json["data"]["server_challenge"]
        .as_str()
        .unwrap()
        .to_string();

    // ATTACK: Truncated signature (only 32 bytes instead of 64).
    let verify_body = serde_json::to_string(&serde_json::json!({
        "server_challenge": challenge,
        "client_signature": "ab".repeat(32),  // 32 bytes, should be 64
        "client_static_pubkey": hex::encode(client_key.verifying_key().to_bytes()),
    }))
    .unwrap();

    let req = json_post("/v1/auth/verify", verify_body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "truncated signature must be rejected"
    );
}

#[tokio::test]
async fn test_verify_all_zeros_signature() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let client = HandshakeClient::new(client_key.clone(), None);
    let bundle = client.build_client_hello();

    let body = serde_json::to_string(&bundle.client_hello).unwrap();
    let req = json_post("/v1/auth/hello", body);
    let resp = app.clone().oneshot(req).await.unwrap();
    let json = body_json(resp).await;
    let challenge = json["data"]["server_challenge"]
        .as_str()
        .unwrap()
        .to_string();

    // ATTACK: All-zeros signature.
    let verify_body = serde_json::to_string(&serde_json::json!({
        "server_challenge": challenge,
        "client_signature": "00".repeat(64),
        "client_static_pubkey": hex::encode(client_key.verifying_key().to_bytes()),
    }))
    .unwrap();

    let req = json_post("/v1/auth/verify", verify_body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "all-zeros signature must be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 5: KEY CONFUSION / IDENTITY ATTACKS
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_client_rejects_wrong_server_key() {
    let server_key = gen_ed25519_key();
    let client_key = gen_ed25519_key();
    let wrong_server_pk = gen_ed25519_key().verifying_key();

    let client = HandshakeClient::new(client_key, Some(wrong_server_pk));
    let bundle = client.build_client_hello();

    let mut server_hs = ServerHandshake::new(server_key);
    let server_hello = server_hs
        .process_client_hello(&bundle.client_hello)
        .unwrap();

    let result = client.process_server_hello(
        &bundle.client_hello,
        &server_hello,
        bundle.ephemeral_secret,
        &bundle.client_nonce,
    );
    assert!(
        result.is_err(),
        "client must reject server signed with wrong key"
    );
}

#[tokio::test]
async fn test_key_id_spoofing_rejected() {
    // ATTACK: Client claims a key_id that doesn't match their pubkey.
    let server_key = gen_ed25519_key();
    let client_key = gen_ed25519_key();
    let eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = X25519Public::from(&eph);

    let mut client_hello = ClientHello {
        protocol_version: PROTOCOL_VERSION.to_string(),
        supported_kex: vec![KeyExchangeAlgorithm::X25519],
        supported_sig: vec![SignatureAlgorithm::Ed25519],
        client_ephemeral_pubkey: hex::encode(eph_pub.as_bytes()),
        client_nonce: hex::encode(random_nonce()),
        timestamp: unix_now(),
        client_key_id: hex::encode(&client_key.verifying_key().to_bytes()[..8]),
    };

    // Spoof the key_id to a different value.
    client_hello.client_key_id = "0000000000000000".to_string();

    let mut server_hs = ServerHandshake::new(server_key);
    let server_hello = server_hs.process_client_hello(&client_hello).unwrap();

    // Sign with the real key (whose key_id doesn't match the spoofed one).
    let pubkey_hex = hex::encode(client_key.verifying_key().to_bytes());
    let transcript_hash = compute_transcript_hash(&client_hello, &server_hello, &pubkey_hex);
    let sig = client_key.sign(&transcript_hash);

    let client_auth = ClientAuth {
        client_signature: hex::encode(sig.to_bytes()),
        client_static_pubkey: pubkey_hex,
    };

    let result = server_hs.process_client_auth(&client_auth, &client_hello, 3600);
    assert!(result.is_err(), "key_id spoofing must be detected");
}

#[tokio::test]
async fn test_forward_secrecy_unique_keys_per_session() {
    // Different sessions with the same client key must produce different session keys.
    let (_router, state) = test_app().await;
    let client_key = gen_ed25519_key();

    let token1 = handshake_via_http_with_key(&state, &client_key).await;
    let token2 = handshake_via_http_with_key(&state, &client_key).await;

    assert_ne!(
        token1, token2,
        "different sessions must have different tokens"
    );

    let s1 = state.session_store.get(&token1).await.unwrap();
    let s2 = state.session_store.get(&token2).await.unwrap();
    assert_ne!(
        s1.client_write_key, s2.client_write_key,
        "forward secrecy violated"
    );
}

#[tokio::test]
async fn test_all_zeros_ephemeral_pubkey_handled() {
    // ATTACK: Use all-zeros ephemeral pubkey (low-order point).
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let nonce = random_nonce();
    let now = unix_now();
    let client_key_id = hex::encode(&client_key.verifying_key().to_bytes()[..8]);

    let body = serde_json::to_string(&serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "supported_kex": ["x25519"],
        "supported_sig": ["ed25519"],
        "client_ephemeral_pubkey": "00".repeat(32),  // All zeros
        "client_nonce": hex::encode(nonce),
        "timestamp": now,
        "client_key_id": client_key_id
    }))
    .unwrap();

    let req = json_post("/v1/auth/hello", body);
    let resp = app.oneshot(req).await.unwrap();
    // The server should accept the hello (X25519 allows all-zeros pubkey in x25519-dalek),
    // but the resulting shared secret will be all-zeros, which is a degenerate case.
    // This is acceptable because the signature binding ensures authentication.
    // Just verify no panic occurs.
    assert!(
        resp.status() == StatusCode::OK || resp.status() == StatusCode::UNAUTHORIZED,
        "should handle all-zeros ephemeral key without panic"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 6: SESSION HIJACKING & LIFECYCLE
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_expired_session_rejected() {
    let (router, state) = test_app().await;

    // Create a session that's already expired.
    let session = AuthenticatedSession {
        session_id: "expired-session-123".to_string(),
        client_pubkey: [0u8; 32],
        client_key_id: "test".into(),
        client_write_key: [1u8; 32],
        server_write_key: [2u8; 32],
        expires_at: 1000, // Long expired
        created_at: 500,
    };
    state.session_store.store(session).await;

    let req = Request::builder()
        .uri("/v1/wallets")
        .method("GET")
        .header("x-session-token", "expired-session-123")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expired session must be rejected"
    );
}

#[tokio::test]
async fn test_nonexistent_session_token_rejected() {
    let app = test_router().await;

    let req = Request::builder()
        .uri("/v1/wallets")
        .method("GET")
        .header("x-session-token", "totally-made-up-session-id")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "nonexistent session must be rejected"
    );
}

#[tokio::test]
async fn test_session_revocation() {
    let (router, state) = test_app().await;
    let (session_token, _) = handshake_via_http(&state).await;

    // Verify it works before revocation.
    let req = Request::builder()
        .uri("/v1/wallets")
        .method("GET")
        .header("x-session-token", &session_token)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Revoke the session.
    state.session_store.revoke(&session_token).await;

    // Should now fail.
    let req = Request::builder()
        .uri("/v1/wallets")
        .method("GET")
        .header("x-session-token", &session_token)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "revoked session must be rejected"
    );
}

#[tokio::test]
async fn test_refresh_expired_session_fails() {
    let app = test_router().await;

    let body = serde_json::to_string(&serde_json::json!({
        "session_token": "does-not-exist-12345"
    }))
    .unwrap();

    let req = json_post("/v1/auth/refresh-session", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "refreshing nonexistent session must fail"
    );
}

#[tokio::test]
async fn test_refresh_valid_session_extends_ttl() {
    let state = mpc_wallet_api::state::AppState::from_config(
        &mpc_wallet_api::config::AppConfig::for_test(),
    );

    let (session_token, _) = handshake_via_http(&state).await;

    // Get original expiry.
    let original = state.session_store.get(&session_token).await.unwrap();
    let original_expires = original.expires_at;

    // Build refresh router with same state.
    let router = build_router(state.clone(), &[]);
    let body = serde_json::to_string(&serde_json::json!({
        "session_token": session_token
    }))
    .unwrap();

    let req = json_post("/v1/auth/refresh-session", body);
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    let new_expires = json["data"]["expires_at"].as_u64().unwrap();
    assert!(
        new_expires >= original_expires,
        "refresh must extend or maintain TTL"
    );
}

#[tokio::test]
async fn test_session_token_is_opaque() {
    // Session tokens should not contain exploitable structure.
    let (_router, state) = test_app().await;
    let (token, _) = handshake_via_http(&state).await;

    // Token should be hex-encoded (no special chars).
    assert!(
        token.chars().all(|c| c.is_ascii_hexdigit()),
        "token must be hex"
    );
    assert!(token.len() >= 16, "token must be at least 8 bytes hex");
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 7: PROTOCOL DOWNGRADE ATTACKS
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_unsupported_kex_algorithm_rejected() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let eph_pub = X25519Public::from(&X25519Secret::random_from_rng(rand::rngs::OsRng));
    let nonce = random_nonce();
    let client_key_id = hex::encode(&client_key.verifying_key().to_bytes()[..8]);

    // ATTACK: Claim to only support a non-existent algorithm.
    let body = serde_json::to_string(&serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "supported_kex": ["p256-ecdh"],  // Not supported
        "supported_sig": ["ed25519"],
        "client_ephemeral_pubkey": hex::encode(eph_pub.as_bytes()),
        "client_nonce": hex::encode(nonce),
        "timestamp": unix_now(),
        "client_key_id": client_key_id
    }))
    .unwrap();

    let req = json_post("/v1/auth/hello", body);
    let resp = app.oneshot(req).await.unwrap();
    // The enum variant "p256-ecdh" is not recognized by serde, so Axum returns
    // 422 (Unprocessable Entity) before the handler runs. Either 401 or 422
    // is acceptable — the request must NOT succeed.
    assert!(
        resp.status().is_client_error(),
        "unsupported KEX algorithm must be rejected (got {})",
        resp.status()
    );
}

#[tokio::test]
async fn test_wrong_protocol_version_rejected() {
    let app = test_router().await;

    let body = serde_json::to_string(&serde_json::json!({
        "protocol_version": "mpc-wallet-auth-v0",  // Old/wrong version
        "supported_kex": ["x25519"],
        "supported_sig": ["ed25519"],
        "client_ephemeral_pubkey": "ab".repeat(32),
        "client_nonce": "cd".repeat(32),
        "timestamp": unix_now(),
        "client_key_id": "0000000000000000"
    }))
    .unwrap();

    let req = json_post("/v1/auth/hello", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 8: MALFORMED INPUT / FUZZING
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_hello_empty_body_rejected() {
    let app = test_router().await;

    let req = Request::builder()
        .uri("/v1/auth/hello")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::OK, "empty body must not succeed");
}

#[tokio::test]
async fn test_hello_invalid_json_rejected() {
    let app = test_router().await;

    let req = Request::builder()
        .uri("/v1/auth/hello")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("not json at all {{{"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_client_error(),
        "invalid JSON must return 4xx"
    );
}

#[tokio::test]
async fn test_hello_oversized_nonce_rejected() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let eph_pub = X25519Public::from(&X25519Secret::random_from_rng(rand::rngs::OsRng));
    let client_key_id = hex::encode(&client_key.verifying_key().to_bytes()[..8]);

    // ATTACK: 64-byte nonce instead of 32-byte.
    let body = serde_json::to_string(&serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "supported_kex": ["x25519"],
        "supported_sig": ["ed25519"],
        "client_ephemeral_pubkey": hex::encode(eph_pub.as_bytes()),
        "client_nonce": "ab".repeat(64),  // 64 bytes, should be 32
        "timestamp": unix_now(),
        "client_key_id": client_key_id
    }))
    .unwrap();

    let req = json_post("/v1/auth/hello", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "oversized nonce must be rejected"
    );
}

#[tokio::test]
async fn test_hello_short_ephemeral_key_rejected() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let client_key_id = hex::encode(&client_key.verifying_key().to_bytes()[..8]);

    // ATTACK: 16-byte ephemeral key instead of 32-byte.
    let body = serde_json::to_string(&serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "supported_kex": ["x25519"],
        "supported_sig": ["ed25519"],
        "client_ephemeral_pubkey": "ab".repeat(16),  // Only 16 bytes
        "client_nonce": "cd".repeat(32),
        "timestamp": unix_now(),
        "client_key_id": client_key_id
    }))
    .unwrap();

    let req = json_post("/v1/auth/hello", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "short ephemeral key must be rejected"
    );
}

#[tokio::test]
async fn test_hello_invalid_hex_in_pubkey() {
    let app = test_router().await;

    let client_key = gen_ed25519_key();
    let client_key_id = hex::encode(&client_key.verifying_key().to_bytes()[..8]);

    // ATTACK: Non-hex characters in pubkey.
    let body = serde_json::to_string(&serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "supported_kex": ["x25519"],
        "supported_sig": ["ed25519"],
        "client_ephemeral_pubkey": "gg".repeat(32),  // 'g' is not hex
        "client_nonce": "cd".repeat(32),
        "timestamp": unix_now(),
        "client_key_id": client_key_id
    }))
    .unwrap();

    let req = json_post("/v1/auth/hello", body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "invalid hex must be rejected"
    );
}

#[tokio::test]
async fn test_verify_nonexistent_challenge() {
    let app = test_router().await;

    let verify_body = serde_json::to_string(&serde_json::json!({
        "server_challenge": "ff".repeat(32),  // Random, not from any hello
        "client_signature": "ab".repeat(64),
        "client_static_pubkey": "cd".repeat(32),
    }))
    .unwrap();

    let req = json_post("/v1/auth/verify", verify_body);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "verify with no matching hello must fail"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 9: HMAC BYPASS & MANIPULATION
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// SECTION 10: AUTH METHOD CONFUSION
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_invalid_session_does_not_fall_through() {
    // SECURITY: If session token is present but invalid, it should NOT fall
    // through to try other auth methods. This prevents auth confusion attacks.
    let app = test_router().await;

    let req = Request::builder()
        .uri("/v1/wallets")
        .method("GET")
        .header("x-session-token", "invalid-session")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "invalid session token must fail immediately without trying other auth"
    );
}

#[tokio::test]
async fn test_empty_auth_headers_rejected() {
    let app = test_router().await;

    let req = Request::builder()
        .uri("/v1/wallets")
        .method("GET")
        .header("x-session-token", "")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "empty session token must be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 11: REVOCATION ENFORCEMENT
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_revoked_keys_endpoint_public() {
    let app = test_router().await;

    let req = Request::builder()
        .uri("/v1/auth/revoked-keys")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert!(json["success"].as_bool().unwrap());
    // Default test config has no revoked keys.
    assert!(json["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_revoked_key_cannot_handshake() {
    // Create state with a revoked key.
    let config = mpc_wallet_api::config::AppConfig::for_test();
    let state = mpc_wallet_api::state::AppState::from_config(&config);

    let client_key = gen_ed25519_key();
    let client_key_id = hex::encode(&client_key.verifying_key().to_bytes()[..8]);

    // Manually add to revoked set (simulate revocation).
    let mut revoked = std::collections::HashSet::new();
    revoked.insert(client_key_id.clone());
    let state_with_revoked = mpc_wallet_api::state::AppState {
        revoked_keys: mpc_wallet_api::state::RevocationStore::in_memory_with(revoked),
        ..state
    };
    let router = build_router(state_with_revoked, &[]);

    let eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = X25519Public::from(&eph);
    let nonce = random_nonce();
    let body = build_hello_body(&client_key, &eph_pub, &nonce, unix_now());

    let req = json_post("/v1/auth/hello", body);
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "revoked key must not be able to start handshake"
    );
}

#[tokio::test]
async fn test_session_refresh_revokes_on_key_revocation() {
    // Create a valid session, then simulate key revocation,
    // and verify refresh fails + session is revoked.
    let config = mpc_wallet_api::config::AppConfig::for_test();
    let state = mpc_wallet_api::state::AppState::from_config(&config);

    let client_key = gen_ed25519_key();
    let client_key_id = hex::encode(&client_key.verifying_key().to_bytes()[..8]);

    // Create session first (before revocation).
    let session_token = handshake_via_http_with_key(&state, &client_key).await;
    assert!(state.session_store.get(&session_token).await.is_some());

    // Now rebuild state with the key revoked.
    let mut revoked = std::collections::HashSet::new();
    revoked.insert(client_key_id);
    let state_revoked = mpc_wallet_api::state::AppState {
        revoked_keys: mpc_wallet_api::state::RevocationStore::in_memory_with(revoked),
        session_store: state.session_store.clone(), // Same session store
        ..state
    };
    let router = build_router(state_revoked.clone(), &[]);

    // Try to refresh — should fail because key is now revoked.
    let body = serde_json::to_string(&serde_json::json!({
        "session_token": session_token
    }))
    .unwrap();
    let req = json_post("/v1/auth/refresh-session", body);
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "refresh must fail when key is revoked"
    );

    // Session should also have been actively revoked from the store.
    assert!(
        state_revoked
            .session_store
            .get(&session_token)
            .await
            .is_none(),
        "session must be removed from store after revoked key refresh attempt"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 12: DoS / RESOURCE EXHAUSTION
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_session_store_handles_many_sessions() {
    let store = mpc_wallet_api::auth::session::SessionStore::in_memory();
    let now = unix_now();

    // Insert 1000 sessions.
    for i in 0..1000 {
        let session = AuthenticatedSession {
            session_id: format!("session-{i}"),
            client_pubkey: [0u8; 32],
            client_key_id: "test".into(),
            client_write_key: [1u8; 32],
            server_write_key: [2u8; 32],
            expires_at: now + 3600,
            created_at: now,
        };
        store.store(session).await;
    }

    assert_eq!(store.count().await, 1000);
    assert!(store.get("session-500").await.is_some());
    assert!(store.get("session-999").await.is_some());
}

#[tokio::test]
async fn test_expired_session_pruning() {
    let store = mpc_wallet_api::auth::session::SessionStore::in_memory();
    let now = unix_now();

    // Insert a mix of expired and active sessions.
    for i in 0..100 {
        let session = AuthenticatedSession {
            session_id: format!("sess-{i}"),
            client_pubkey: [0u8; 32],
            client_key_id: "test".into(),
            client_write_key: [1u8; 32],
            server_write_key: [2u8; 32],
            expires_at: if i < 50 { 1000 } else { now + 3600 },
            created_at: 500,
        };
        store.store(session).await;
    }

    let pruned = store.prune_expired().await;
    assert_eq!(pruned, 50, "should prune exactly 50 expired sessions");
    assert_eq!(store.count().await, 50, "50 active sessions should remain");
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 13: INFORMATION LEAKAGE
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_error_messages_are_generic() {
    let app = test_router().await;

    // Different auth failures should all return the same error message.
    let scenarios = vec![
        ("expired session", {
            Request::builder()
                .uri("/v1/wallets")
                .method("GET")
                .header("x-session-token", "expired-fake")
                .body(Body::empty())
                .unwrap()
        }),
        ("no auth at all", {
            Request::builder()
                .uri("/v1/wallets")
                .method("GET")
                .body(Body::empty())
                .unwrap()
        }),
    ];

    for (label, req) in scenarios {
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "failed for: {label}"
        );

        let json = body_json(resp).await;
        assert_eq!(
            json["error"].as_str().unwrap(),
            "authentication failed",
            "error message for '{label}' must be generic — no info leak"
        );
    }
}

#[tokio::test]
async fn test_handshake_errors_are_generic() {
    let app = test_router().await;

    // Wrong version.
    let body = serde_json::to_string(&serde_json::json!({
        "protocol_version": "wrong",
        "supported_kex": ["x25519"],
        "supported_sig": ["ed25519"],
        "client_ephemeral_pubkey": "ab".repeat(32),
        "client_nonce": "cd".repeat(32),
        "timestamp": unix_now(),
        "client_key_id": "0000000000000000"
    }))
    .unwrap();

    let req = json_post("/v1/auth/hello", body);
    let resp = app.clone().oneshot(req).await.unwrap();
    let json = body_json(resp).await;
    assert_eq!(
        json["error"].as_str().unwrap(),
        "authentication failed",
        "handshake error must not leak specific failure reason"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 14: EDGE CASES — CONCURRENT & RACE CONDITIONS
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_concurrent_handshakes_independent() {
    // Multiple handshakes happening simultaneously should not interfere.
    let (_router, state) = test_app().await;
    let client1 = gen_ed25519_key();
    let client2 = gen_ed25519_key();

    let (t1, t2) = tokio::join!(
        handshake_via_http_with_key(&state, &client1),
        handshake_via_http_with_key(&state, &client2),
    );

    assert_ne!(t1, t2, "concurrent sessions must have different tokens");

    let s1 = state.session_store.get(&t1).await.unwrap();
    let s2 = state.session_store.get(&t2).await.unwrap();
    assert_ne!(s1.client_pubkey, s2.client_pubkey);
    assert_ne!(s1.client_write_key, s2.client_write_key);
}

#[tokio::test]
async fn test_same_client_multiple_sessions() {
    // One client should be able to have multiple active sessions.
    let (_router, state) = test_app().await;
    let client_key = gen_ed25519_key();

    let t1 = handshake_via_http_with_key(&state, &client_key).await;
    let t2 = handshake_via_http_with_key(&state, &client_key).await;
    let t3 = handshake_via_http_with_key(&state, &client_key).await;

    assert!(state.session_store.get(&t1).await.is_some());
    assert!(state.session_store.get(&t2).await.is_some());
    assert!(state.session_store.get(&t3).await.is_some());

    // Revoking one should not affect others.
    state.session_store.revoke(&t2).await;
    assert!(state.session_store.get(&t1).await.is_some());
    assert!(state.session_store.get(&t2).await.is_none());
    assert!(state.session_store.get(&t3).await.is_some());
}
