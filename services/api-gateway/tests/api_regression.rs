//! API Regression Tests — Real HTTP via reqwest
//!
//! These tests hit a **running** gateway over real HTTP (not in-process Router).
//! They catch integration issues that in-process tests miss: middleware ordering,
//! header parsing, session serialization, CORS, etc.
//!
//! Requires: `./scripts/local-infra.sh up` (Vault + Redis + NATS + Gateway)
//! Run:      `cargo test -p mpc-wallet-api --test api_regression -- --ignored --test-threads=1`

use ed25519_dalek::SigningKey;
use mpc_wallet_api::auth::client::HandshakeClient;
use mpc_wallet_api::auth::types::*;
use reqwest::Client;
use serde_json::Value;

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

fn gateway_url() -> String {
    std::env::var("GATEWAY_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".into())
}

fn http_client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

async fn get(url: &str) -> (u16, Value) {
    let resp = http_client().get(url).send().await.expect("GET failed");
    let status = resp.status().as_u16();
    let json = resp.json().await.unwrap_or(Value::Null);
    (status, json)
}

async fn get_with_session(url: &str, token: &str) -> (u16, Value) {
    let resp = http_client()
        .get(url)
        .header("x-session-token", token)
        .send()
        .await
        .expect("GET with session failed");
    let status = resp.status().as_u16();
    let json = resp.json().await.unwrap_or(Value::Null);
    (status, json)
}

async fn post_json(url: &str, body: &Value) -> (u16, Value) {
    let resp = http_client()
        .post(url)
        .json(body)
        .send()
        .await
        .expect("POST failed");
    let status = resp.status().as_u16();
    let json = resp.json().await.unwrap_or(Value::Null);
    (status, json)
}

/// Perform full 3-message handshake via real HTTP.
/// Returns (session_token, session_id).
async fn full_handshake(gw: &str) -> (String, String) {
    let client_key = gen_ed25519_key();
    let client = HandshakeClient::new(client_key, None);
    let bundle = client.build_client_hello();

    // Step 1: POST /v1/auth/hello
    let hello_body = serde_json::to_value(&bundle.client_hello).unwrap();
    let (status, hello_resp) = post_json(&format!("{gw}/v1/auth/hello"), &hello_body).await;
    assert_eq!(status, 200, "auth/hello failed: {hello_resp}");

    let server_hello: ServerHello =
        serde_json::from_value(hello_resp["data"].clone()).expect("parse ServerHello");

    // Step 2: Client processes ServerHello → build ClientAuth
    let (client_auth, _derived) = client
        .process_server_hello(
            &bundle.client_hello,
            &server_hello,
            bundle.ephemeral_secret,
            &bundle.client_nonce,
        )
        .expect("process_server_hello failed");

    // Step 3: POST /v1/auth/verify
    let verify_body = serde_json::json!({
        "server_challenge": server_hello.server_challenge,
        "client_signature": client_auth.client_signature,
        "client_static_pubkey": client_auth.client_static_pubkey,
    });
    let (status, verify_resp) = post_json(&format!("{gw}/v1/auth/verify"), &verify_body).await;
    assert_eq!(status, 200, "auth/verify failed: {verify_resp}");

    let session_token = verify_resp["data"]["session_token"]
        .as_str()
        .expect("no session_token")
        .to_string();
    let session_id = verify_resp["data"]["session_id"]
        .as_str()
        .expect("no session_id")
        .to_string();

    (session_token, session_id)
}

// ═══════════════════════════════════════════════════════════════════════
// 1. Health Endpoints
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_health_endpoint() {
    let gw = gateway_url();
    let (status, json) = get(&format!("{gw}/v1/health")).await;

    assert_eq!(status, 200);
    assert_eq!(json["success"].as_bool(), Some(true));
    assert_eq!(json["data"]["status"].as_str(), Some("healthy"));
    assert!(json["data"]["chains_supported"].as_u64().unwrap_or(0) >= 50);
}

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_health_live() {
    let gw = gateway_url();
    let (status, json) = get(&format!("{gw}/v1/health/live")).await;

    assert_eq!(status, 200);
    // /health/live returns flat JSON (no data wrapper): {"status":"ok"}
    assert_eq!(json["status"].as_str(), Some("ok"));
}

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_health_ready() {
    let gw = gateway_url();
    let (status, json) = get(&format!("{gw}/v1/health/ready")).await;

    assert_eq!(status, 200);
    // /health/ready returns flat JSON (no data wrapper): {"status":"ready","components":{...}}
    let comp = &json["components"];
    // At minimum, NATS should be connected since local-infra starts it
    assert!(
        comp["nats"].as_str().is_some(),
        "readiness should report NATS status"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 2. Chains Endpoint
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_chains_returns_50() {
    let gw = gateway_url();
    let (status, json) = get(&format!("{gw}/v1/chains")).await;

    assert_eq!(status, 200);
    assert_eq!(json["data"]["total"].as_u64(), Some(50));
    let chains = json["data"]["chains"].as_array().unwrap();
    let names: Vec<&str> = chains.iter().filter_map(|c| c["name"].as_str()).collect();
    assert!(names.contains(&"ethereum"), "missing ethereum");
    assert!(names.contains(&"bitcoin-mainnet"), "missing bitcoin");
    assert!(names.contains(&"solana"), "missing solana");
    assert!(names.contains(&"sui"), "missing sui");
}

// ═══════════════════════════════════════════════════════════════════════
// 3. Auth Handshake — Full Flow via Real HTTP
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_full_handshake_and_session_access() {
    let gw = gateway_url();
    let (session_token, session_id) = full_handshake(&gw).await;

    assert!(!session_token.is_empty(), "session_token must not be empty");
    assert!(!session_id.is_empty(), "session_id must not be empty");

    // Use session to access protected endpoint
    let (status, json) = get_with_session(&format!("{gw}/v1/wallets"), &session_token).await;
    assert_eq!(
        status, 200,
        "session token should grant access to /v1/wallets"
    );
    assert_eq!(json["success"].as_bool(), Some(true));
}

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_session_refresh() {
    let gw = gateway_url();
    let (session_token, _) = full_handshake(&gw).await;

    // Refresh session
    let refresh_body = serde_json::json!({ "session_token": session_token });
    let (status, json) = post_json(&format!("{gw}/v1/auth/refresh-session"), &refresh_body).await;
    assert_eq!(status, 200, "refresh should succeed: {json}");

    let new_token = json["data"]["session_token"]
        .as_str()
        .expect("refresh must return new session_token");
    assert!(!new_token.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════
// 4. Protected Endpoints Without Auth → 401
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_wallets_without_auth_returns_401() {
    let gw = gateway_url();
    let (status, json) = get(&format!("{gw}/v1/wallets")).await;

    assert_eq!(status, 401);
    assert_eq!(json["success"].as_bool(), Some(false));
    assert_eq!(json["error"]["code"].as_str(), Some("AUTH_FAILED"));
}

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_create_wallet_without_auth_returns_401() {
    let gw = gateway_url();
    let body = serde_json::json!({
        "chain": "ethereum",
        "threshold": 2,
        "parties": 3
    });
    let (status, json) = post_json(&format!("{gw}/v1/wallets"), &body).await;

    assert_eq!(status, 401);
    assert_eq!(json["error"]["code"].as_str(), Some("AUTH_FAILED"));
}

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_revoke_key_without_auth_returns_401() {
    let gw = gateway_url();
    let body = serde_json::json!({ "key_id": "deadbeef" });
    let (status, json) = post_json(&format!("{gw}/v1/auth/revoke-key"), &body).await;

    assert_eq!(status, 401);
    assert_eq!(json["error"]["code"].as_str(), Some("AUTH_FAILED"));
}

// ═══════════════════════════════════════════════════════════════════════
// 5. Invalid Auth Headers → 401
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_invalid_session_token_returns_401() {
    let gw = gateway_url();
    let (status, json) = get_with_session(&format!("{gw}/v1/wallets"), "garbage-token").await;

    assert_eq!(status, 401);
    assert_eq!(json["error"]["code"].as_str(), Some("AUTH_FAILED"));
}

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_invalid_bearer_token_returns_401() {
    let gw = gateway_url();
    let resp = http_client()
        .get(format!("{gw}/v1/wallets"))
        .header("Authorization", "Bearer invalid-jwt-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

// ═══════════════════════════════════════════════════════════════════════
// 6. Error Response Format Consistency
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_error_response_format() {
    let gw = gateway_url();

    // 401 error format
    let (_, json_401) = get(&format!("{gw}/v1/wallets")).await;
    assert_eq!(json_401["success"].as_bool(), Some(false));
    assert!(
        json_401["error"]["code"].is_string(),
        "error must have code"
    );
    assert!(
        json_401["error"]["message"].is_string(),
        "error must have message"
    );
    assert!(json_401["data"].is_null(), "error must not have data");

    // 404 error format (nonexistent wallet)
    let (session_token, _) = full_handshake(&gw).await;
    let (status_404, json_404) =
        get_with_session(&format!("{gw}/v1/wallets/nonexistent-id"), &session_token).await;
    assert_eq!(status_404, 404);
    assert_eq!(json_404["success"].as_bool(), Some(false));
    assert!(
        json_404["error"]["code"].is_string(),
        "404 error must have code"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 7. Rate Limiting
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_rate_limit_on_auth_hello() {
    let gw = gateway_url();

    // Use the same client_key_id to trigger rate limiting (10 req/sec)
    let client_key = gen_ed25519_key();
    let mut got_429 = false;

    for _ in 0..20 {
        let client = HandshakeClient::new(client_key.clone(), None);
        let bundle = client.build_client_hello();
        let body = serde_json::to_value(&bundle.client_hello).unwrap();
        let (status, _) = post_json(&format!("{gw}/v1/auth/hello"), &body).await;

        if status == 429 {
            got_429 = true;
            break;
        }
    }

    assert!(
        got_429,
        "should get 429 after rapid-fire handshake attempts"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 8. Revoked Keys Endpoint (Public)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_revoked_keys_endpoint() {
    let gw = gateway_url();
    let (status, json) = get(&format!("{gw}/v1/auth/revoked-keys")).await;

    assert_eq!(status, 200);
    assert_eq!(json["success"].as_bool(), Some(true));
    // data is a flat array of revoked keys (possibly empty)
    assert!(
        json["data"].is_array(),
        "data should be an array of revoked keys"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 9. Wallet Create + Sign Flow (RBAC + MPC)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_create_wallet_requires_admin_mfa() {
    let gw = gateway_url();
    let (session_token, _) = full_handshake(&gw).await;

    // Default session has Viewer role (no Admin + MFA) → should be denied
    let body = serde_json::json!({
        "label": "test-wallet",
        "scheme": "gg20-ecdsa",
        "threshold": 2,
        "total_parties": 3
    });
    let resp = http_client()
        .post(format!("{gw}/v1/wallets"))
        .header("x-session-token", &session_token)
        .json(&body)
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    let json: Value = resp.json().await.unwrap();

    // Should be 403 (insufficient permissions) since default session is Viewer
    assert_eq!(status, 403, "Viewer role should not create wallets: {json}");
    assert_eq!(json["success"].as_bool(), Some(false));
}

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_sign_nonexistent_wallet_returns_404() {
    let gw = gateway_url();
    let (session_token, _) = full_handshake(&gw).await;

    let body = serde_json::json!({
        "message": "deadbeef"
    });
    let resp = http_client()
        .post(format!("{gw}/v1/wallets/nonexistent-wallet-id/sign"))
        .header("x-session-token", &session_token)
        .json(&body)
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    let json: Value = resp.json().await.unwrap();

    // Viewer role can't sign (needs Initiator/Admin) → 403
    // OR if RBAC passes somehow → 404 wallet not found
    assert!(
        status == 403 || status == 404,
        "sign on nonexistent wallet should be 403 or 404, got {status}: {json}"
    );
    assert_eq!(json["success"].as_bool(), Some(false));
}

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_sign_invalid_hex_message_returns_400() {
    let gw = gateway_url();
    let (session_token, _) = full_handshake(&gw).await;

    let body = serde_json::json!({
        "message": "not-valid-hex-zzz"
    });
    let resp = http_client()
        .post(format!("{gw}/v1/wallets/some-wallet/sign"))
        .header("x-session-token", &session_token)
        .json(&body)
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    let json: Value = resp.json().await.unwrap();

    // Could be 403 (RBAC) or 400 (invalid hex) depending on middleware order
    assert!(
        status == 400 || status == 403,
        "invalid hex should be 400 or 403, got {status}: {json}"
    );
    assert_eq!(json["success"].as_bool(), Some(false));
}

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_simulate_transaction_requires_auth() {
    let gw = gateway_url();
    let body = serde_json::json!({
        "chain": "ethereum",
        "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
        "value": "1000000000000000000"
    });
    let (status, json) = post_json(&format!("{gw}/v1/wallets/any-wallet/simulate"), &body).await;

    assert_eq!(status, 401, "simulate without auth should be 401: {json}");
}

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_freeze_wallet_requires_admin_mfa() {
    let gw = gateway_url();
    let (session_token, _) = full_handshake(&gw).await;

    let resp = http_client()
        .post(format!("{gw}/v1/wallets/any-wallet/freeze"))
        .header("x-session-token", &session_token)
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    // Viewer can't freeze → 403
    assert_eq!(status, 403, "freeze without Admin+MFA should be 403");
}

// ═══════════════════════════════════════════════════════════════════════
// 10. Happy-Path Helpers (Admin key from local-infra)
// ═══════════════════════════════════════════════════════════════════════

/// Load admin signing key from the seed file generated by local-infra.sh.
/// Returns None if the file doesn't exist (infra not started with admin key).
fn load_admin_key() -> Option<SigningKey> {
    // Try KEY_DIR env, then workspace-relative path, then absolute fallback
    let key_dir = std::env::var("KEY_DIR").ok().or_else(|| {
        // Find workspace root by looking for Cargo.lock
        let mut dir = std::env::current_dir().ok()?;
        loop {
            if dir.join("Cargo.lock").exists() {
                return Some(dir.join("infra/local/.keys").to_string_lossy().into_owned());
            }
            if !dir.pop() {
                return None;
            }
        }
    })?;
    let seed_path = format!("{key_dir}/test_admin_seed.hex");
    let seed_hex = std::fs::read_to_string(&seed_path).ok()?.trim().to_string();
    let seed_bytes = hex::decode(&seed_hex).ok()?;
    let seed: [u8; 32] = seed_bytes.try_into().ok()?;
    Some(SigningKey::from_bytes(&seed))
}

/// Perform full handshake with a specific signing key.
/// Returns (session_token, session_id).
async fn full_handshake_with_key(gw: &str, key: SigningKey) -> (String, String) {
    let client = HandshakeClient::new(key, None);
    let bundle = client.build_client_hello();

    let hello_body = serde_json::to_value(&bundle.client_hello).unwrap();
    let (status, hello_resp) = post_json(&format!("{gw}/v1/auth/hello"), &hello_body).await;
    assert_eq!(status, 200, "auth/hello failed: {hello_resp}");

    let server_hello: ServerHello =
        serde_json::from_value(hello_resp["data"].clone()).expect("parse ServerHello");

    let (client_auth, _derived) = client
        .process_server_hello(
            &bundle.client_hello,
            &server_hello,
            bundle.ephemeral_secret,
            &bundle.client_nonce,
        )
        .expect("process_server_hello failed");

    let verify_body = serde_json::json!({
        "server_challenge": server_hello.server_challenge,
        "client_signature": client_auth.client_signature,
        "client_static_pubkey": client_auth.client_static_pubkey,
    });
    let (status, verify_resp) = post_json(&format!("{gw}/v1/auth/verify"), &verify_body).await;
    assert_eq!(status, 200, "auth/verify failed: {verify_resp}");

    let session_token = verify_resp["data"]["session_token"]
        .as_str()
        .expect("no session_token")
        .to_string();
    let session_id = verify_resp["data"]["session_id"]
        .as_str()
        .expect("no session_id")
        .to_string();

    (session_token, session_id)
}

fn post_json_with_session_sync() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .unwrap()
}

// ═══════════════════════════════════════════════════════════════════════
// 11. Happy-Path: Keygen + Sign (Real MPC via NATS)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_keygen_and_sign_happy_path() {
    let gw = gateway_url();
    let admin_key =
        load_admin_key().expect("Admin key not found — run ./scripts/local-infra.sh up first");

    // 1. Handshake with admin key → Admin + MFA session
    let (session_token, _) = full_handshake_with_key(&gw, admin_key).await;

    // 2. Create wallet (distributed keygen via 3 MPC nodes)
    //    Use FROST Ed25519 — GG20 ECDSA MtA requires real Paillier keys which
    //    simulated keygen doesn't produce (Πenc ZK proof fails on sign).
    let create_body = serde_json::json!({
        "label": "regression-test-wallet",
        "scheme": "frost-ed25519",
        "threshold": 2,
        "total_parties": 3
    });
    let long_client = post_json_with_session_sync();
    let resp = long_client
        .post(format!("{gw}/v1/wallets"))
        .header("x-session-token", &session_token)
        .json(&create_body)
        .send()
        .await
        .expect("create wallet request failed");

    let status = resp.status().as_u16();
    let json: Value = resp.json().await.unwrap();
    assert_eq!(status, 201, "create wallet should return 201: {json}");
    assert_eq!(json["success"].as_bool(), Some(true));

    let wallet_id = json["data"]["id"]
        .as_str()
        .expect("wallet response must have id");
    let scheme = json["data"]["scheme"]
        .as_str()
        .expect("wallet response must have scheme");
    assert_eq!(scheme, "frost-ed25519");
    assert!(!wallet_id.is_empty(), "wallet_id must not be empty");

    // 3. Sign a message (distributed sign via MPC nodes)
    let message_hex = "deadbeefcafebabe";
    let sign_body = serde_json::json!({
        "message": message_hex
    });
    let resp = long_client
        .post(format!("{gw}/v1/wallets/{wallet_id}/sign"))
        .header("x-session-token", &session_token)
        .json(&sign_body)
        .send()
        .await
        .expect("sign request failed");

    let status = resp.status().as_u16();
    let json: Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "sign should return 200: {json}");
    assert_eq!(json["success"].as_bool(), Some(true));

    let sig = &json["data"]["signature"];
    let sig_scheme = json["data"]["scheme"].as_str().unwrap_or("");
    assert_eq!(
        sig_scheme, "frost-ed25519",
        "scheme mismatch in sign response"
    );

    // FROST Ed25519 returns {"signature": "<hex>"} — 64-byte Ed25519 signature
    assert!(
        sig["signature"].is_string(),
        "EdDSA signature must have 'signature' field"
    );
    let sig_hex = sig["signature"].as_str().unwrap();
    assert_eq!(
        sig_hex.len(),
        128,
        "Ed25519 signature should be 64 bytes (128 hex chars)"
    );
}

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_admin_can_list_created_wallet() {
    let gw = gateway_url();
    let admin_key = load_admin_key().expect("Admin key not found");

    let (session_token, _) = full_handshake_with_key(&gw, admin_key).await;

    // List wallets — should include any wallets created by previous tests
    let (status, json) = get_with_session(&format!("{gw}/v1/wallets"), &session_token).await;
    assert_eq!(status, 200, "admin should list wallets: {json}");
    assert_eq!(json["success"].as_bool(), Some(true));
    assert!(
        json["data"]["wallets"].is_array(),
        "wallets should be an array"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 12. Full Endpoint Coverage (Sprint 28 — fill remaining gaps)
// ═══════════════════════════════════════════════════════════════════════

/// GET /v1/metrics — Prometheus metrics endpoint returns text format.
#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_metrics_returns_prometheus_format() {
    let gw = gateway_url();
    let (session_token, _) = full_handshake(&gw).await;

    let resp = http_client()
        .get(format!("{gw}/v1/metrics"))
        .header("x-session-token", &session_token)
        .send()
        .await
        .expect("GET /v1/metrics failed");

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(status, 200, "metrics should return 200: {body}");
    assert!(
        body.contains("mpc_api_requests_total")
            || body.contains("# HELP")
            || body.contains("# TYPE"),
        "metrics body should contain Prometheus text format: {body}"
    );
}

/// GET /v1/wallets/{id} — wallet detail by ID (404 for nonexistent).
#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_get_wallet_by_id_nonexistent_returns_404() {
    let gw = gateway_url();
    let admin_key = load_admin_key().expect("Admin key not found");
    let (session_token, _) = full_handshake_with_key(&gw, admin_key).await;

    let (status, json) = get_with_session(
        &format!("{gw}/v1/wallets/nonexistent-wallet-id"),
        &session_token,
    )
    .await;
    assert_eq!(status, 404, "nonexistent wallet should return 404: {json}");
    assert_eq!(json["success"].as_bool(), Some(false));
}

/// POST /v1/wallets/{id}/unfreeze — requires Admin+MFA (viewer gets 403).
#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_unfreeze_wallet_requires_admin_mfa() {
    let gw = gateway_url();
    let (session_token, _) = full_handshake(&gw).await;

    let resp = http_client()
        .post(format!("{gw}/v1/wallets/any-wallet/unfreeze"))
        .header("x-session-token", &session_token)
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    // Viewer can't unfreeze → 403
    assert_eq!(status, 403, "unfreeze without Admin+MFA should be 403");
}

/// GET /v1/chains/{chain}/address/{id} — requires auth (401 without).
#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_derive_address_requires_auth() {
    let gw = gateway_url();

    let (status, json) = get(&format!("{gw}/v1/chains/ethereum/address/any-wallet")).await;
    assert_eq!(
        status, 401,
        "derive address without auth should be 401: {json}"
    );
}

/// POST /v1/wallets/{id}/transactions — requires auth (401 without).
#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_create_transaction_requires_auth() {
    let gw = gateway_url();
    let body = serde_json::json!({
        "chain": "ethereum",
        "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
        "value": "1000000000000000000"
    });

    let (status, json) =
        post_json(&format!("{gw}/v1/wallets/any-wallet/transactions"), &body).await;
    assert_eq!(
        status, 401,
        "create transaction without auth should be 401: {json}"
    );
}

/// POST /v1/wallets/{id}/refresh — not yet implemented (viewer → 403).
#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_refresh_wallet_requires_admin() {
    let gw = gateway_url();
    let (session_token, _) = full_handshake(&gw).await;

    let resp = http_client()
        .post(format!("{gw}/v1/wallets/any-wallet/refresh"))
        .header("x-session-token", &session_token)
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    // Viewer can't refresh → 403 (RBAC rejects before reaching 501)
    assert_eq!(status, 403, "refresh without Admin+MFA should be 403");
}
