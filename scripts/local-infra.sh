#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# MPC Wallet — Local Infrastructure (1-shot)
#
# Spins up Vault + Redis + NATS + Gateway on localhost for testing.
# All config lives in infra/local/.env — no hardcoded values here.
#
# Usage:
#   ./scripts/local-infra.sh              # start everything
#   ./scripts/local-infra.sh down         # tear down (containers + gateway)
#   ./scripts/local-infra.sh status       # check service health
#   ./scripts/local-infra.sh logs         # tail all service logs
#   ./scripts/local-infra.sh restart-gw   # rebuild & restart gateway only
#
# First run:
#   cp infra/local/.env.example infra/local/.env   # then edit if needed
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# ── Paths ─────────────────────────────────────────────────────────────

ENV_FILE="infra/local/.env"
ENV_EXAMPLE="infra/local/.env.example"
COMPOSE_FILE="infra/local/docker-compose.yml"
COMPOSE_PROJECT="mpc-local"
PID_FILE="/tmp/mpc-wallet-gateway.pid"

# ── Colors ────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1" >&2; exit 1; }
step() { echo -e "\n${CYAN}--- $1 ---${NC}"; }

# ── Load .env ─────────────────────────────────────────────────────────

load_env() {
  if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
      warn ".env not found — copying from .env.example"
      cp "$ENV_EXAMPLE" "$ENV_FILE"
    else
      err "No .env or .env.example found at infra/local/"
    fi
  fi

  # Export all non-comment, non-empty lines
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
}

load_env

# ── Derived values (from .env) ────────────────────────────────────────

VAULT_ADDR="http://127.0.0.1:${VAULT_PORT:-8200}"
REDIS_URL="redis://127.0.0.1:${REDIS_PORT:-6379}"
NATS_URL="nats://127.0.0.1:${NATS_CLIENT_PORT:-4222}"
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT:-3000}"

# Docker compose command
DC="docker compose -p $COMPOSE_PROJECT -f $COMPOSE_FILE --env-file $ENV_FILE"

# ── Helpers ───────────────────────────────────────────────────────────

check_prereqs() {
  local missing=()
  command -v docker  >/dev/null 2>&1 || missing+=("docker")
  command -v curl    >/dev/null 2>&1 || missing+=("curl")
  command -v jq      >/dev/null 2>&1 || missing+=("jq (brew install jq)")
  command -v openssl >/dev/null 2>&1 || missing+=("openssl")
  command -v cargo   >/dev/null 2>&1 || missing+=("cargo (rustup)")

  if [ ${#missing[@]} -gt 0 ]; then
    err "Missing: ${missing[*]}"
  fi

  docker info >/dev/null 2>&1 || err "Docker daemon not running"
}

# Wait for a service health check URL to respond
wait_healthy() {
  local name="$1" url="$2" max="${3:-30}"
  for i in $(seq 1 "$max"); do
    if curl -sf "$url" >/dev/null 2>&1; then
      log "$name is healthy"
      return 0
    fi
    [ "$i" -eq "$max" ] && err "$name failed health check after ${max}s ($url)"
    sleep 1
  done
}

# Stop the gateway process if running
stop_gateway() {
  if [ -f "$PID_FILE" ]; then
    local pid
    pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      log "Gateway stopped (PID: $pid)"
    fi
    rm -f "$PID_FILE"
  fi
  # Belt and suspenders
  pkill -f "target/.*/mpc-wallet-api" 2>/dev/null || true
}

# Vault API helper
vault_api() {
  local method="$1" path="$2"; shift 2
  curl -sf -X "$method" "${VAULT_ADDR}/v1/${path}" \
    -H "X-Vault-Token: ${VAULT_DEV_TOKEN:-dev-root-token}" \
    -H "Content-Type: application/json" \
    "$@"
}

# ── Subcommands ───────────────────────────────────────────────────────

cmd_down() {
  step "Tearing down"
  stop_gateway
  stop_nodes
  $DC down -v 2>/dev/null || true
  rm -f "$PID_FILE"
  log "All containers, nodes, and volumes removed."
}

cmd_status() {
  step "Service status"
  $DC ps 2>/dev/null || warn "Compose services not running"
  echo ""

  local vault_ok redis_ok nats_ok gw_ok
  vault_ok=$(curl -sf "${VAULT_ADDR}/v1/sys/health" 2>/dev/null | jq -r '"initialized=\(.initialized) sealed=\(.sealed)"' 2>/dev/null || echo "not running")
  redis_ok=$(docker exec "${COMPOSE_PROJECT}-redis-1" redis-cli ping 2>/dev/null || echo "not running")
  nats_ok=$(curl -sf "http://127.0.0.1:${NATS_MONITOR_PORT:-8222}/healthz" 2>/dev/null && echo "ok" || echo "not running")
  gw_ok=$(curl -sf "${GATEWAY_URL}/v1/health" 2>/dev/null | jq -r '.data.status' 2>/dev/null || echo "not running")

  echo "  Vault:   $vault_ok"
  echo "  Redis:   $redis_ok"
  echo "  NATS:    $nats_ok"
  echo "  Gateway: $gw_ok"

  # Node status
  for i in 1 2 3; do
    if [ -f "$NODE_PID_DIR/node-${i}.pid" ]; then
      local npid; npid=$(cat "$NODE_PID_DIR/node-${i}.pid")
      if kill -0 "$npid" 2>/dev/null; then
        echo "  Node $i:  running (PID: $npid)"
      else
        echo "  Node $i:  stopped"
      fi
    else
      echo "  Node $i:  not started"
    fi
  done

  if [ -f "$PID_FILE" ]; then
    local pid; pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
      echo "  Gateway PID: $pid"
    fi
  fi
}

cmd_logs() {
  $DC logs -f "$@"
}

cmd_restart_gw() {
  step "Rebuilding gateway + nodes"
  stop_gateway
  stop_nodes
  build_binaries
  start_nodes
  start_gateway
  smoke_test
}

# ── Core functions ────────────────────────────────────────────────────

start_containers() {
  step "Starting containers (Vault + Redis + NATS)"
  $DC up -d

  wait_healthy "Vault" "${VAULT_ADDR}/v1/sys/health" 30

  # Redis has no HTTP endpoint — use redis-cli ping via docker exec
  for i in $(seq 1 30); do
    if docker exec "${COMPOSE_PROJECT}-redis-1" redis-cli ping 2>/dev/null | grep -q PONG; then
      log "Redis is healthy"
      break
    fi
    [ "$i" -eq 30 ] && err "Redis failed health check after 30s"
    sleep 1
  done

  wait_healthy "NATS" "http://127.0.0.1:${NATS_MONITOR_PORT:-8222}/healthz" 15
}

provision_vault() {
  step "Provisioning Vault"

  local mount="${VAULT_MOUNT:-secret}"
  local path="${VAULT_SECRETS_PATH:-mpc-wallet/gateway}"
  local role="${VAULT_APPROLE_NAME:-mpc-gateway}"
  local policy="${VAULT_POLICY_NAME:-mpc-gateway}"

  # Generate random secrets
  local jwt_secret server_signing_key session_encryption_key
  jwt_secret=$(openssl rand -hex 32)
  server_signing_key=$(openssl rand -hex 32)
  session_encryption_key=$(openssl rand -hex 32)

  # Write secrets
  vault_api POST "${mount}/data/${path}" \
    -d "$(jq -n \
      --arg jwt "$jwt_secret" \
      --arg ssk "$server_signing_key" \
      --arg sek "$session_encryption_key" \
      --arg redis "redis://127.0.0.1:${REDIS_PORT:-6379}" \
      '{data: {jwt_secret: $jwt, server_signing_key: $ssk, session_encryption_key: $sek, redis_url: $redis}}'
    )" > /dev/null

  # Verify
  local count
  count=$(vault_api GET "${mount}/data/${path}" | jq -r '.data.data | keys | length')
  log "Secrets written to ${mount}/${path} ($count keys)"

  # Enable AppRole (idempotent)
  vault_api POST "sys/auth/approle" -d '{"type":"approle"}' 2>/dev/null || true

  # Policy
  vault_api PUT "sys/policies/acl/${policy}" \
    -d "$(jq -n --arg p "path \"${mount}/data/${path}\" { capabilities = [\"read\"] }" '{policy: $p}')" > /dev/null

  # Role
  vault_api POST "auth/approle/role/${role}" \
    -d '{"token_policies":["'"${policy}"'"],"token_ttl":"1h","token_max_ttl":"4h"}' > /dev/null

  # Get credentials
  APPROLE_ROLE_ID=$(vault_api GET "auth/approle/role/${role}/role-id" | jq -r '.data.role_id')
  APPROLE_SECRET_ID=$(vault_api POST "auth/approle/role/${role}/secret-id" | jq -r '.data.secret_id')

  log "AppRole ready (role_id=${APPROLE_ROLE_ID:0:8}...)"
}

build_binaries() {
  step "Building Gateway + MPC Node (${CARGO_PROFILE:-release})"

  local profile="${CARGO_PROFILE:-release}"
  if [ "$profile" = "debug" ]; then
    cargo build -p mpc-wallet-api -p mpc-wallet-node 2>&1 | tail -3
  else
    cargo build --release -p mpc-wallet-api -p mpc-wallet-node 2>&1 | tail -3
  fi
  log "Build complete"
}

NODE_PID_DIR="/tmp/mpc-wallet-nodes"

stop_nodes() {
  if [ -d "$NODE_PID_DIR" ]; then
    for f in "$NODE_PID_DIR"/*.pid; do
      [ -f "$f" ] || continue
      local pid
      pid=$(cat "$f")
      kill "$pid" 2>/dev/null || true
    done
    rm -rf "$NODE_PID_DIR"
  fi
  pkill -f "target/.*/mpc-node" 2>/dev/null || true
}

start_nodes() {
  step "Starting 3 MPC nodes"
  stop_nodes
  mkdir -p "$NODE_PID_DIR"

  local profile="${CARGO_PROFILE:-release}"
  local binary="./target/${profile}/mpc-node"
  [ -f "$binary" ] || err "Binary not found: $binary"

  for i in 1 2 3; do
    local key_dir="/tmp/mpc-node-${i}-keys"
    mkdir -p "$key_dir"

    # Generate deterministic signing key per node (for dev — production uses Vault)
    local signing_key
    signing_key=$(printf "%02x" "$i" | head -c2)
    signing_key=$(printf "${signing_key}%.0s" {1..32})

    PARTY_ID="$i" \
    NATS_URL="nats://127.0.0.1:${NATS_CLIENT_PORT:-4222}" \
    KEY_STORE_DIR="$key_dir" \
    KEY_STORE_PASSWORD="dev-password-local-test" \
    NODE_SIGNING_KEY="$signing_key" \
    RUST_LOG="mpc_wallet_node=info" \
      "$binary" &

    local pid=$!
    echo "$pid" > "$NODE_PID_DIR/node-${i}.pid"
    log "MPC Node $i started (PID: $pid, key_dir: $key_dir)"
  done

  # Give nodes time to connect to NATS
  sleep 2
  log "All 3 MPC nodes started"
}

start_gateway() {
  step "Starting API gateway"
  stop_gateway

  local profile="${CARGO_PROFILE:-release}"
  local binary="./target/${profile}/mpc-wallet-api"
  [ -f "$binary" ] || err "Binary not found: $binary (run build first)"

  SECRETS_BACKEND=vault \
  VAULT_ADDR="$VAULT_ADDR" \
  VAULT_ROLE_ID="$APPROLE_ROLE_ID" \
  VAULT_SECRET_ID="$APPROLE_SECRET_ID" \
  VAULT_MOUNT="${VAULT_MOUNT:-secret}" \
  VAULT_SECRETS_PATH="${VAULT_SECRETS_PATH:-mpc-wallet/gateway}" \
  NETWORK="${NETWORK:-testnet}" \
  SESSION_BACKEND="${SESSION_BACKEND:-redis}" \
  SESSION_TTL="${SESSION_TTL:-3600}" \
  REDIS_URL="redis://127.0.0.1:${REDIS_PORT:-6379}" \
  NATS_URL="nats://127.0.0.1:${NATS_CLIENT_PORT:-4222}" \
  PORT="${GATEWAY_PORT:-3000}" \
  RATE_LIMIT_RPS="${RATE_LIMIT_RPS:-100}" \
  RUST_LOG="${RUST_LOG:-mpc_wallet_api=info}" \
    "$binary" &

  local pid=$!
  echo "$pid" > "$PID_FILE"
  log "Gateway starting (PID: $pid)"

  wait_healthy "Gateway" "${GATEWAY_URL}/v1/health" 15
}

smoke_test() {
  step "Smoke test"

  echo ""
  echo "  Health:"
  curl -sf "${GATEWAY_URL}/v1/health" | jq -c '{ status: .data.status, chains: .data.chains_supported }'

  echo "  Chains:"
  curl -sf "${GATEWAY_URL}/v1/chains" | jq -c '{ total: .data.total }'

  echo "  Auth error format:"
  curl -s "${GATEWAY_URL}/v1/wallets" | jq -c '.error'

  echo ""
}

print_summary() {
  local pid
  pid=$(cat "$PID_FILE" 2>/dev/null || echo "?")

  step "Local infrastructure ready"
  echo ""
  printf "  %-10s %s\n" "Vault"    "${VAULT_ADDR}  (UI: ${VAULT_ADDR}/ui, token: ${VAULT_DEV_TOKEN:-dev-root-token})"
  printf "  %-10s %s\n" "Redis"    "redis://127.0.0.1:${REDIS_PORT:-6379}"
  printf "  %-10s %s\n" "NATS"     "${NATS_URL}  (monitor: http://127.0.0.1:${NATS_MONITOR_PORT:-8222})"
  printf "  %-10s %s\n" "Node 1"   "PID: $(cat $NODE_PID_DIR/node-1.pid 2>/dev/null || echo '?')  (party_id=1, coordinator)"
  printf "  %-10s %s\n" "Node 2"   "PID: $(cat $NODE_PID_DIR/node-2.pid 2>/dev/null || echo '?')  (party_id=2)"
  printf "  %-10s %s\n" "Node 3"   "PID: $(cat $NODE_PID_DIR/node-3.pid 2>/dev/null || echo '?')  (party_id=3)"
  printf "  %-10s %s\n" "Gateway"  "${GATEWAY_URL}  (PID: ${pid}, orchestrator mode)"
  echo ""
  echo "  Vault secrets: ${VAULT_MOUNT:-secret}/${VAULT_SECRETS_PATH:-mpc-wallet/gateway}"
  echo ""
  echo "  Commands:"
  echo "    ./scripts/local-infra.sh status       # health check"
  echo "    ./scripts/local-infra.sh logs          # tail all logs"
  echo "    ./scripts/local-infra.sh restart-gw    # rebuild gateway"
  echo "    ./scripts/local-infra.sh down          # tear down everything"
  echo ""
  echo "  Quick test:"
  echo "    curl -s ${GATEWAY_URL}/v1/health | jq ."
  echo "    curl -s ${GATEWAY_URL}/v1/chains | jq .data.total"
  echo ""
}

# ── Main ──────────────────────────────────────────────────────────────

cmd_up() {
  step "Checking prerequisites"
  check_prereqs
  log "OK"

  # Clean up any stale containers from previous runs
  $DC down -v 2>/dev/null || true
  stop_gateway

  start_containers
  provision_vault
  build_binaries
  start_nodes
  start_gateway
  smoke_test
  print_summary
}

# ── Dispatch ──────────────────────────────────────────────────────────

cmd_test() {
  step "Running E2E test suite"

  # Ensure infra is up
  cmd_up

  step "Running E2E tests (--ignored)"
  NATS_URL="$NATS_URL" \
  REDIS_URL="$REDIS_URL" \
  GATEWAY_URL="$GATEWAY_URL" \
    cargo test --workspace -- --ignored --test-threads=1 2>&1

  local exit_code=$?

  step "E2E tests complete (exit: $exit_code)"
  if [ $exit_code -eq 0 ]; then
    log "All E2E tests passed"
  else
    warn "Some E2E tests failed — check output above"
  fi
  return $exit_code
}

# ── Dispatch ──────────────────────────────────────────────────────────

case "${1:-up}" in
  up)           cmd_up ;;
  down|stop)    cmd_down ;;
  status)       cmd_status ;;
  logs)         shift; cmd_logs "$@" ;;
  restart-gw)   cmd_restart_gw ;;
  test)         cmd_test ;;
  *)
    echo "Usage: $0 [up|down|status|logs|restart-gw|test]"
    echo ""
    echo "  up           Start Vault + Redis + NATS + Gateway (default)"
    echo "  down         Tear down all containers and gateway"
    echo "  status       Check health of all services"
    echo "  logs         Tail container logs (pass service name to filter)"
    echo "  restart-gw   Rebuild and restart gateway only"
    echo "  test         Start infra + run E2E tests (--ignored)"
    exit 1
    ;;
esac
