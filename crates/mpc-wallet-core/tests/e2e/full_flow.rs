//! E2E tests: Auth + Redis + Vault integration.
//!
//! Requires: `./scripts/local-infra.sh up` (Vault + Redis + NATS + Gateway)
//! Run: `cargo test --test e2e_tests -- --ignored`

const DEFAULT_GATEWAY_URL: &str = "http://127.0.0.1:3000";
const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1:6379";

fn gateway_url() -> String {
    std::env::var("GATEWAY_URL").unwrap_or_else(|_| DEFAULT_GATEWAY_URL.into())
}

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| DEFAULT_REDIS_URL.into())
}

/// Helper: GET request, return (status, json)
async fn get(url: &str) -> (u16, serde_json::Value) {
    let resp = reqwest::get(url).await.expect("HTTP request failed");
    let status = resp.status().as_u16();
    let json = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ═══════════════════════════════════════════════════════════════════════
// Gateway health (proves Vault secrets were loaded + Redis connected)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_gateway_health_with_vault_and_redis() {
    let gw = gateway_url();
    let (status, json) = get(&format!("{gw}/v1/health")).await;

    assert_eq!(status, 200, "gateway must be healthy");
    assert_eq!(json["data"]["status"].as_str(), Some("healthy"));
    assert!(
        json["data"]["chains_supported"].as_u64().unwrap_or(0) >= 50,
        "should support 50+ chains"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Auth: unauthenticated → structured error
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_unauthenticated_returns_structured_error() {
    let gw = gateway_url();
    let (status, json) = get(&format!("{gw}/v1/wallets")).await;

    assert_eq!(status, 401);
    assert_eq!(json["success"].as_bool(), Some(false));
    assert_eq!(json["error"]["code"].as_str(), Some("AUTH_FAILED"));
    assert_eq!(
        json["error"]["message"].as_str(),
        Some("authentication failed")
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Chains endpoint (public, no auth)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires running gateway: ./scripts/local-infra.sh up"]
async fn test_chains_endpoint_returns_all_chains() {
    let gw = gateway_url();
    let (status, json) = get(&format!("{gw}/v1/chains")).await;

    assert_eq!(status, 200);
    assert_eq!(json["success"].as_bool(), Some(true));

    let total = json["data"]["total"].as_u64().unwrap_or(0);
    assert_eq!(total, 50, "should return 50 chains");

    let chains = json["data"]["chains"].as_array().unwrap();
    let names: Vec<&str> = chains.iter().filter_map(|c| c["name"].as_str()).collect();
    assert!(names.contains(&"ethereum"));
    assert!(names.contains(&"bitcoin-mainnet"));
    assert!(names.contains(&"solana"));
    assert!(names.contains(&"sui"));
}

// ═══════════════════════════════════════════════════════════════════════
// Redis: verify Redis is being used (connect directly)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires Redis: ./scripts/local-infra.sh up"]
async fn test_redis_is_reachable() {
    let url = redis_url();
    let client = redis::Client::open(url.as_str()).expect("Redis client creation failed");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection failed");

    let pong: String = redis::cmd("PING")
        .query_async(&mut conn)
        .await
        .expect("Redis PING failed");
    assert_eq!(pong, "PONG");
}
