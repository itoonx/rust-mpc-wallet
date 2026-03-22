# API Regression Test Guide

19 tests that hit the **real running gateway** over HTTP (not in-process Router).
Catches integration issues that unit tests miss: middleware ordering, header parsing,
session serialization, CORS, error response format, rate limiting, RBAC enforcement.

## Prerequisites

| Tool | Why |
|------|-----|
| Docker | Vault + Redis + NATS containers |
| cargo | Build gateway + MPC nodes + keygen tool |
| curl + jq | Smoke tests in `local-infra.sh` |

No `openssl` needed — Ed25519 key generation uses Rust (`ed25519-dalek`) cross-platform.

## Quick Start (3 commands)

```bash
# 1. Start everything (Vault + Redis + NATS + 3 MPC nodes + Gateway)
./scripts/local-infra.sh up

# 2. Run 19 regression tests
GATEWAY_URL="http://127.0.0.1:3000" \
  cargo test -p mpc-wallet-api --test api_regression -- --ignored --test-threads=1

# 3. Tear down
./scripts/local-infra.sh down
```

## Verbose / Debug Mode

```bash
# Full debug with backtrace + per-test output
GATEWAY_URL="http://127.0.0.1:3000" \
RUST_BACKTRACE=1 \
  cargo test -p mpc-wallet-api --test api_regression -- --ignored --test-threads=1 --nocapture
```

### Run a Single Test (debug)

```bash
GATEWAY_URL="http://127.0.0.1:3000" \
  cargo test -p mpc-wallet-api --test api_regression test_full_handshake_and_session_access \
  -- --ignored --nocapture
```

### Manual Endpoint Probing (curl)

```bash
# Health
curl -sv http://127.0.0.1:3000/v1/health | jq .
curl -sv http://127.0.0.1:3000/v1/health/live | jq .
curl -sv http://127.0.0.1:3000/v1/health/ready | jq .

# Chains (50 supported)
curl -s http://127.0.0.1:3000/v1/chains | jq '.data.total'

# Auth error (should return 401 + structured JSON)
curl -s http://127.0.0.1:3000/v1/wallets | jq .

# Revoked keys (public endpoint)
curl -s http://127.0.0.1:3000/v1/auth/revoked-keys | jq .
```

## Step-by-Step: What `local-infra.sh up` Does

```
1. check_prereqs     — verify docker, curl, jq, cargo are installed
2. generate_keys     — `cargo run --example gen_gateway_keys` (Ed25519 keypair)
3. start_containers  — docker compose up (Vault, Redis, NATS)
4. provision_vault   — write secrets, create AppRole, get credentials
5. build_binaries    — cargo build --release (gateway + mpc-node)
6. start_nodes       — 3 MPC nodes (each with own key store + NATS)
7. start_gateway     — API gateway (Vault secrets + Redis sessions + NATS orchestrator)
8. smoke_test        — curl health + chains + auth error format
```

## Test Coverage Map

| # | Test Name | What It Verifies | Expected |
|---|-----------|------------------|----------|
| 1 | `test_health_endpoint` | `/v1/health` returns healthy + chain count | 200, `chains_supported >= 50` |
| 2 | `test_health_live` | `/v1/health/live` liveness probe | 200, `{"status":"ok"}` |
| 3 | `test_health_ready` | `/v1/health/ready` readiness + components | 200, NATS status present |
| 4 | `test_chains_returns_50` | `/v1/chains` returns all 50 chains | 200, includes ETH/BTC/SOL/SUI |
| 5 | `test_full_handshake_and_session_access` | Full Ed25519 handshake flow | hello(200) -> verify(200) -> session access(200) |
| 6 | `test_session_refresh` | Session refresh returns new token | 200, new `session_token` |
| 7 | `test_wallets_without_auth_returns_401` | GET /wallets without auth | 401, `AUTH_FAILED` |
| 8 | `test_create_wallet_without_auth_returns_401` | POST /wallets without auth | 401, `AUTH_FAILED` |
| 9 | `test_revoke_key_without_auth_returns_401` | POST /auth/revoke-key without auth | 401, `AUTH_FAILED` |
| 10 | `test_invalid_session_token_returns_401` | Garbage session token | 401, `AUTH_FAILED` |
| 11 | `test_invalid_bearer_token_returns_401` | Invalid Bearer JWT | 401 |
| 12 | `test_error_response_format` | 401 + 404 error JSON structure | `{success:false, error:{code,message}}` |
| 13 | `test_rate_limit_on_auth_hello` | Rate limiter triggers on rapid requests | 429 within 20 attempts |
| 14 | `test_revoked_keys_endpoint` | Public revoked-keys endpoint | 200, data is array |
| 15 | `test_create_wallet_requires_admin_mfa` | Viewer role can't create wallets | 403 |
| 16 | `test_sign_nonexistent_wallet_returns_404` | Sign on missing wallet (RBAC first) | 403 or 404 |
| 17 | `test_sign_invalid_hex_message_returns_400` | Invalid hex message | 400 or 403 |
| 18 | `test_simulate_transaction_requires_auth` | Simulate without auth | 401 |
| 19 | `test_freeze_wallet_requires_admin_mfa` | Viewer can't freeze | 403 |

## Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│  cargo test (reqwest HTTP client)                   │
│  19 regression tests                                │
└───────────────────┬─────────────────────────────────┘
                    │ HTTP :3000
┌───────────────────▼─────────────────────────────────┐
│  API Gateway (mpc-wallet-api)                       │
│  - Auth middleware (mTLS / Session JWT / Bearer JWT) │
│  - Rate limiter (token-bucket)                      │
│  - RBAC (Viewer/Initiator/Admin)                    │
│  - MpcOrchestrator (NATS pub/sub)                   │
└──┬─────────────┬─────────────┬──────────────────────┘
   │ NATS :4222  │ Redis :6379 │ Vault :8200
┌──▼──┐ ┌──▼──┐ ┌──▼──┐  ┌──▼──┐    ┌──▼──┐
│Node1│ │Node2│ │Node3│  │Redis│    │Vault│
│ MPC │ │ MPC │ │ MPC │  │sess │    │ KV  │
└─────┘ └─────┘ └─────┘  └─────┘    └─────┘
```

## Troubleshooting

### Port Conflict (e.g., Redis 6379 already in use)

```bash
# Find what's using the port
lsof -i :6379

# Stop the conflicting container
docker stop <container_name>

# Then retry
./scripts/local-infra.sh up
```

### Gateway Won't Start

```bash
# Check logs
./scripts/local-infra.sh logs

# Check all service health
./scripts/local-infra.sh status

# Rebuild gateway only
./scripts/local-infra.sh restart-gw
```

### Test Fails Locally But Passed Before

```bash
# Run single failing test with full debug
GATEWAY_URL="http://127.0.0.1:3000" \
RUST_BACKTRACE=full \
  cargo test -p mpc-wallet-api --test api_regression <test_name> \
  -- --ignored --nocapture

# Compare actual response vs expected
curl -sv http://127.0.0.1:3000/v1/<endpoint> 2>&1 | jq .
```

### Custom Gateway Port

```bash
# Edit infra/local/.env
GATEWAY_PORT=3001

# Or pass at runtime
GATEWAY_URL="http://127.0.0.1:3001" cargo test ...
```

## Key Design Decisions

- Tests are `#[ignore]` so `cargo test --workspace` skips them (no infra needed for CI unit tests)
- `--test-threads=1` is **required** because tests share gateway state (rate limiter, session store)
- `full_handshake()` helper performs real Ed25519 key exchange (X25519 ECDH + transcript hashing)
- Tests verify both happy path AND error paths (401/403/404/429)
- Response format assertions ensure API contract stability across releases

## File Locations

```
services/api-gateway/tests/api_regression.rs  — 19 test functions
scripts/local-infra.sh                        — infrastructure orchestrator
infra/local/.env                              — port config, backend settings
infra/local/docker-compose.yml                — Vault + Redis + NATS containers
crates/mpc-wallet-core/examples/gen_gateway_keys.rs — cross-platform Ed25519 keygen
```
