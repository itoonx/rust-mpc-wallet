<div align="center">

```
          ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗███████╗██╗  ██╗
          ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██╔════╝╚██╗██╔╝
          ██║   ██║███████║██║   ██║██║     ██║   █████╗   ╚███╔╝
          ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██╔══╝   ██╔██╗
           ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ███████╗██╔╝ ██╗
            ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝
                   Your keys. Distributed. Unstoppable.
```

**Threshold MPC Wallet SDK** — No single party ever holds a complete private key.

EVM (26) | Bitcoin | Polkadot | Solana | Sui | Aptos | TON | TRON | Cosmos | Starknet | 50 chains

[![CI](https://github.com/itoonx/vaultex-mpc-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/itoonx/vaultex-mpc-rust/actions/workflows/ci.yml)

[English](README.md) | [中文](README.zh-CN.md)

</div>

---

## What is Vaultex?

Vaultex is a **Rust workspace** for building enterprise-grade **threshold multi-party computation (MPC) wallets**. The full private key is **never assembled** in memory — not during key generation, not during signing, not ever.

```
                    ┌─────────┐
                    │  Party 1 │ ← holds share s₁
                    └────┬────┘
                         │
   ┌─────────┐      ┌───┴───┐      ┌─────────┐
   │  Party 2 │──────│  NATS  │──────│  Party 3 │
   │  share s₂│      │  mTLS  │      │  share s₃│
   └─────────┘      └───┬───┘      └─────────┘
                         │
                    ┌────┴────┐
                    │ Signature│ ← valid ECDSA/Schnorr/EdDSA
                    │  (r, s)  │   full key x never computed
                    └─────────┘
```

**Why Vaultex?**

- **Zero single point of failure** — gateway holds 0 shares, each node holds exactly 1. Compromise any single server = attacker gets nothing usable
- **Multi-chain** — 50 blockchains across 8 ecosystems: EVM, Bitcoin, Substrate, Move, Cosmos, UTXO, TON/TRON, Starknet
- **Enterprise controls** — RBAC, ABAC, MFA, policy engine, approval workflows, audit trail
- **Proactive security** — key refresh rotates shares without changing addresses
- **Production-ready infra** — HashiCorp Vault secrets, Redis sessions, NATS transport, Docker + K8s deployment

---

## Documentation

| Document | Description |
|----------|-------------|
| **[CLI Guide](docs/CLI_GUIDE.md)** | Full command reference with examples and sample output |
| **[Architecture](docs/ARCHITECTURE.md)** | System design, trait boundaries, module map |
| **[Security](docs/SECURITY.md)** | Threat model, resolved findings, disclosure policy |
| **[Contributing](docs/CONTRIBUTING.md)** | Guide for humans and LLMs/AI agents |
| **[Changelog](CHANGELOG.md)** | Version history and release notes |
| **[Chain Roadmap](docs/CHAIN_ROADMAP.md)** | 54-chain expansion plan: EVM L2s, Move, Substrate, TON, Cosmos |
| **[Standards & References](docs/STANDARDS.md)** | All cryptographic standards, RFCs, EIPs, BIPs implemented |
| **[API Reference](docs/API_REFERENCE.md)** | REST API endpoints, auth methods |
| **[Auth Spec](specs/AUTH_SPEC.md)** | Key-exchange handshake protocol (28 sections) |
| **[Security Audit](docs/SECURITY_AUDIT_AUTH.md)** | Auth security audit (57 tests, all findings resolved) |
| **[Security Findings](docs/SECURITY_FINDINGS.md)** | Full audit trail (0 CRITICAL/HIGH open) |

---

## Quickstart

```bash
git clone https://github.com/itoonx/vaultex-mpc-rust.git
cd vaultex-mpc-rust

# Run unit + integration tests (no infra needed)
cargo test --workspace              # 507 tests, ~4 seconds

# Start full production stack locally (Vault + Redis + NATS + 3 MPC nodes + gateway)
./scripts/local-infra.sh up         # 1-shot: builds, provisions, starts everything

# Run E2E tests against live infra
./scripts/local-infra.sh test       # distributed keygen + sign via NATS

# Interactive CLI demo (single-process, no infra needed)
./scripts/demo.sh
```

---

## Features

| Category | Highlights |
|----------|-----------|
| **MPC Protocols** | GG20 ECDSA, FROST Ed25519, FROST Schnorr, Sr25519, STARK, BLS12-381 |
| **Key Lifecycle** | Keygen, refresh, reshare (change threshold/add parties), freeze |
| **50 Chains** | EVM L1/L2s, Bitcoin, Solana, Sui, Aptos, Movement, TON, TRON, LTC, DOGE, ZEC, XMR |
| **RPC Registry** | Multi-provider (Dwellir, Alchemy, Infura, Blockstream, Mempool), failover, health tracking |
| **Broadcast** | `eth_sendRawTransaction`, REST `/tx`, `sendTransaction`, `sui_executeTransactionBlock` |
| **Transport** | NATS mTLS + per-session ECDH + SignedEnvelope replay protection |
| **Enterprise** | RBAC, ABAC, MFA, policy engine, approval workflows, audit ledger |
| **Simulation** | Pre-sign risk scoring for all chains |
| **Operations** | Multi-cloud constraints, RPC failover, chaos framework, DR |
| **MPC Nodes** | Distributed architecture — each node holds 1 share, gateway orchestrates |

---

## Authentication & API Gateway

Three auth methods — each serves a different purpose at a different layer:

```
mTLS          =  Machine → Machine   ("I am a trusted service")
Session JWT   =  App → Server        ("I completed the key-exchange handshake")
Bearer JWT    =  Human → System      ("I am a user verified by the IdP")
```

```
Service (mTLS)              SDK Client (Session JWT)         User (Bearer JWT)
┌──────────┐               ┌──────────┐                    ┌──────────┐
│ TLS cert │               │ Ed25519 + │                    │ Auth0 /  │
│ issued   │               │ X25519   │                    │ Okta     │
│ by CA    │               │ handshake │                    │ issues   │
└────┬─────┘               └────┬─────┘                    └────┬─────┘
     │                          │                               │
     │  X-Client-Cert-CN       │  X-Session-Token: <jwt>      │  Authorization: Bearer <jwt>
     ▼                          ▼                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         API Gateway                                   │
│  Priority: mTLS (0) → Session JWT (1) → Bearer JWT (2) → 401         │
│                                                                       │
│  If header is PRESENT but invalid → fail immediately (no fall-through)│
└──────────────────────────────────────┬───────────────────────────────┘
                                       │
                                       ▼
                              ┌─────────────────┐
                              │   MPC Nodes      │
                              │   (verify        │
                              │   SignAuthorization│
                              │   before signing) │
                              └─────────────────┘
```

All three can be used simultaneously in the same deployment — for example, mTLS between internal services, Session JWT for SDK clients, and Bearer JWT for the admin web UI.

### Three Auth Methods (priority order)

#### 1. Session JWT (`X-Session-Token`) — App talks to Server

**Who uses it:** SDK clients, native apps, mobile apps, desktop wallets.
**Purpose:** Application-level identity — "this client completed the key-exchange handshake and this request is genuinely from them."

**How it works:**

```
Step 1: Key Exchange (once per session)
  Client                              Server
  ──────                              ──────
  Generate ephemeral X25519 key  ───► Validate, generate server ephemeral key
  Ed25519 key ID                      Sign transcript with Ed25519
                                 ◄─── ServerHello (challenge + signature)
  Sign transcript with Ed25519   ───► Verify client signature
  ClientAuth                          Derive shared key via ECDH + HKDF
                                 ◄─── SessionEstablished (session_id)
  Both sides now have:
    client_write_key (32 bytes) ← for signing JWTs
    server_write_key (32 bytes) ← for future encrypted responses

Step 2: Per-Request JWT (every API call)
  Client builds JWT:
    { "sid": "session_id",
      "ip": "203.0.113.42",       ← request context for audit
      "fp": "device_fingerprint",
      "ua": "SDK/1.0",
      "rid": "req_unique_id",
      "iat": 1710768000,
      "exp": 1710768120 }         ← short-lived (2 min)
  Signs with HS256(client_write_key)
  Sends: X-Session-Token: eyJhbG...

  Server:
    1. Decode JWT → extract session_id (no signature check yet)
    2. Look up session → retrieve stored client_write_key
    3. Verify HS256 signature with that key
       → Wrong key? 401. Tampered payload? 401. Expired? 401.
    4. Extract request context for audit trail
```

```bash
# Handshake
POST /v1/auth/hello   # → ServerHello
POST /v1/auth/verify  # → { session_id, session_token }

# Authenticated request
curl -H "X-Session-Token: eyJhbGciOiJIUzI1NiJ9.eyJzaWQiOi..." \
     https://api.example.com/v1/wallets
```

**Security:** forward secrecy (ephemeral keys), mutual auth (both sides sign), replay protection (short-lived JWT + nonce), request context binding (IP/device in signed claims).

---

#### 2. mTLS (Mutual TLS) — Machine talks to Machine

**Who uses it:** Backend services, microservices, MPC nodes.
**Purpose:** Infrastructure-level identity — "this machine is a service we trust." No secrets in code or headers — identity comes from TLS certificates issued by your organization's CA. Kubernetes/Istio manage certs automatically.

**How it works:**

```
Service A                   TLS Terminator (nginx/envoy)        Gateway
┌──────────┐  presents     ┌──────────────────────────┐       ┌─────────┐
│ client   │──────────────│ 1. Verify cert against CA │──────│ Extract │
│ cert +   │  TLS handshk │ 2. Extract CN + fingerprint│      │ identity│
│ key      │              │ 3. Set X-Client-Cert-* hdrs│      │ Map role│
└──────────┘              └──────────────────────────┘       └─────────┘
```

**No shared secrets, no tokens in headers.** The TLS terminator handles certificate verification and passes identity to the gateway via headers:

- `X-Client-Cert-Verified: SUCCESS` — cert was verified against the CA
- `X-Client-Cert-CN: trading-service.internal` — Common Name
- `X-Client-Cert-Fingerprint: sha256:abcdef...` — certificate fingerprint

The gateway maps CN → service identity + RBAC role via `MTLS_SERVICES_FILE`:

```json
[
  {
    "cn": "trading-service.internal",
    "fingerprint": "sha256:abcdef1234567890",
    "role": "initiator",
    "label": "Trading Service"
  },
  {
    "cn": "monitoring.internal",
    "role": "viewer",
    "label": "Monitoring Dashboard"
  }
]
```

**Security:** No secrets to rotate (just certs). Identity at transport level. Certificate pinning via fingerprint. Standard infrastructure (Kubernetes, Istio, Consul all support mTLS).

---

#### 3. Bearer JWT (`Authorization: Bearer`) — Human talks to System

**Who uses it:** End users via web apps, admin dashboards.
**Purpose:** User-level identity — "this person is who they claim to be and has these permissions." JWTs are issued by an Identity Provider (Auth0, Okta, Firebase) — the gateway doesn't manage passwords.

**How it works:**

```
Identity Provider (Auth0, Okta, etc.)
  ↓ issues JWT with claims:
  { "sub": "user_123", "roles": ["initiator"], "iss": "mpc-wallet",
    "aud": "mpc-wallet-api", "exp": 1710771600,
    "dept": "trading", "risk_tier": "standard", "mfa_verified": true }
  ↓
Client sends: Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
  ↓
Server validates:
  1. Signature (RS256/ES256/HS256) against configured secret/key
  2. Issuer (iss) matches JWT_ISSUER config
  3. Audience (aud) matches JWT_AUDIENCE config
  4. Not expired (exp > now)
  5. Extract roles → map to RBAC permissions
  6. Extract ABAC attributes (dept, risk_tier, mfa_verified)
```

```bash
curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOi..." \
     https://api.example.com/v1/wallets
```

**No HMAC signing needed** — the JWT itself has integrity guarantees from its signature.

---

#### Real-World Deployment Example

A typical enterprise deployment uses all three methods simultaneously:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Production Environment                        │
│                                                                  │
│  ┌──────────────┐  mTLS    ┌──────────┐  mTLS   ┌────────────┐ │
│  │ Trading      │─────────│          │────────│ MPC Node 1  │ │
│  │ Service      │  cert    │   API    │  cert   │ (party 1)  │ │
│  └──────────────┘         │ Gateway  │        ├────────────┤ │
│                            │          │        │ MPC Node 2  │ │
│  ┌──────────────┐ Session │          │        │ (party 2)  │ │
│  │ Mobile App   │──JWT───│          │        ├────────────┤ │
│  │ (Vaultex SDK)│ (HS256) │          │        │ MPC Node 3  │ │
│  └──────────────┘         │          │        │ (party 3)  │ │
│                            │          │        └────────────┘ │
│  ┌──────────────┐ Bearer  │          │                        │
│  │ Admin Web UI │──JWT───│          │                        │
│  │ (Auth0 SSO)  │ (RS256) │          │                        │
│  └──────────────┘         └──────────┘                        │
│                                                                  │
│  Each layer has its own purpose:                                 │
│  • mTLS: "Is this a trusted service?"                           │
│  • Session JWT: "Did this client pass the handshake?"           │
│  • Bearer JWT: "Which user is this and what can they do?"       │
└─────────────────────────────────────────────────────────────────┘
```

#### Which method should I use?

| Scenario | Recommended Method | Why |
|----------|--------------------|-----|
| Backend microservice | **mTLS** | Best practice: no shared secrets, transport-level identity, cert rotation |
| Kubernetes / service mesh | **mTLS** | Native support in Istio, Linkerd, Consul Connect |
| SDK / native app | **Session JWT** | Forward secrecy, mutual auth, per-request context binding |
| Mobile app | **Session JWT** | Device fingerprint in JWT claims for audit trail |
| Web app with IdP | **Bearer JWT** | Users authenticate via Auth0/Okta, no key management needed |
| Admin dashboard | **Bearer JWT + MFA** | User identity + MFA step-up for sensitive operations |

### Security Features

| Feature | Implementation |
|---------|---------------|
| **Forward secrecy** | Per-session ephemeral X25519 keys |
| **Mutual authentication** | Ed25519 transcript signatures (both sides) |
| **Rate limiting** | 10 req/sec per client_key_id on handshake |
| **Session store** | 100k cap + background prune (60s) |
| **Key zeroization** | `Zeroize + ZeroizeOnDrop` on all session keys |
| **Dynamic revocation** | `POST /v1/auth/revoke-key` (admin, no restart) |
| **Sign authorization** | MPC nodes independently verify gateway proof before signing |
| **Audit trail** | Encrypted request context (ChaCha20-Poly1305) + millisecond timeline |
| **Mainnet safety** | `SERVER_SIGNING_KEY` + `CLIENT_KEYS_FILE` required on mainnet |
| **Secrets management** | KMS/HSM recommended — `KmsSigner` + `KeyEncryptionProvider` traits ready |

> **Production:** Never store secrets (`JWT_SECRET`, `SERVER_SIGNING_KEY`, `SESSION_ENCRYPTION_KEY`) as plaintext env vars or config files. Use AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, or Kubernetes External Secrets. For highest security, use KMS/HSM so signing keys never leave the hardware boundary — see [`docs/API_REFERENCE.md#secrets-management`](docs/API_REFERENCE.md#secrets-management).

> Full API reference: [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) | Protocol spec: [`specs/AUTH_SPEC.md`](specs/AUTH_SPEC.md)

### Error Responses

All API errors return structured JSON with a machine-readable `code` for programmatic handling:

```json
{
  "success": false,
  "error": {
    "code": "NOT_FOUND",
    "message": "wallet 550e8400 not found"
  }
}
```

| Code | HTTP | When |
|------|------|------|
| `AUTH_FAILED` | 401 | Invalid/expired token, revoked key |
| `AUTH_RATE_LIMITED` | 429 | Rate limit exceeded |
| `PERMISSION_DENIED` | 403 | Insufficient RBAC role |
| `MFA_REQUIRED` | 403 | Admin+MFA operation without MFA |
| `INVALID_INPUT` | 400 | Bad request params (hex, format) |
| `NOT_FOUND` | 404 | Wallet/resource not found |
| `KEY_FROZEN` | 422 | Wallet frozen, signing blocked |
| `POLICY_DENIED` | 422 | Policy check failed |
| `INTERNAL_ERROR` | 500 | Server error |

> Full error code reference: [`docs/API_REFERENCE.md#error-codes`](docs/API_REFERENCE.md#error-codes)

### MPC Node Architecture (Production — DEC-015)

In production, the gateway holds **zero key shares**. Each MPC node is a standalone process that holds exactly 1 share, stored in an encrypted file store (AES-256-GCM + Argon2id). All coordination happens via NATS.

```
┌────────────────────────────────────────────────────────────────────────┐
│                         Production Deployment                          │
│                                                                        │
│   ┌─────────────┐        ┌──────────┐        ┌──────────┐            │
│   │  Clients     │ ──────│   API     │ ──────│  Vault    │            │
│   │ (SDK/Web/App)│  HTTPS │ Gateway  │ Vault  │ (Secrets) │            │
│   └─────────────┘        │ (0 shares│        └──────────┘            │
│                           │  RBAC +  │                                 │
│                           │  Policy) │        ┌──────────┐            │
│                           └────┬─────┘ ──────│  Redis    │            │
│                                │       Redis  │ (Sessions)│            │
│                     NATS Control Channels      └──────────┘            │
│                    ┌───────────┼───────────┐                           │
│                    │           │           │                            │
│              ┌─────▼────┐ ┌───▼─────┐ ┌───▼─────┐                    │
│              │  MPC      │ │  MPC    │ │  MPC    │                    │
│              │  Node 1   │ │  Node 2 │ │  Node 3 │                    │
│              │           │ │         │ │         │                    │
│              │ share s₁  │ │ share s₂│ │ share s₃│  ← encrypted     │
│              │ KeyStore  │ │ KeyStore│ │ KeyStore│    on disk        │
│              │ (AES-GCM) │ │ (AES)  │ │ (AES)  │                    │
│              └─────┬─────┘ └───┬─────┘ └───┬─────┘                    │
│                    │           │           │                            │
│                    └───────────┼───────────┘                           │
│                     NATS Protocol Channels                             │
│                      (SignedEnvelope + seq_no)                         │
└────────────────────────────────────────────────────────────────────────┘
```

**Security guarantees:**
- No single process can reconstruct the private key
- Attacker must compromise ≥ threshold nodes simultaneously
- Gateway compromise = 0 shares leaked (only metadata)
- Each node verifies `SignAuthorization` before signing (DEC-012)

**NATS channels:**

| Channel | Purpose |
|---------|---------|
| `mpc.control.keygen.{group_id}` | Gateway → nodes: initiate keygen ceremony |
| `mpc.control.sign.{group_id}` | Gateway → nodes: sign request + SignAuthorization proof |
| `mpc.control.freeze.{group_id}` | Gateway → nodes: freeze/unfreeze key group |
| `mpc.{session_id}.party.{party_id}` | Node ↔ node: MPC protocol messages (SignedEnvelope) |

**Sign flow (DEC-012):**

```
1. Client → Gateway:  POST /v1/wallets/:id/sign { message: "0xdead..." }
2. Gateway:           Auth (mTLS/JWT) → RBAC check → Policy check → Approvals
3. Gateway:           Create SignAuthorization (Ed25519 signed proof)
4. Gateway → NATS:    Publish SignRequest + SignAuthorization to signer nodes
5. Each Node:         Verify SignAuthorization → Load share from KeyStore
6. Nodes ↔ Nodes:     MPC sign protocol via NATS (SignedEnvelope + seq_no)
7. Coordinator:       Assemble final signature → Reply to gateway
8. Gateway → Client:  Return { signature: { r, s, recovery_id } }
```

### Secrets Management (HashiCorp Vault)

Production secrets are loaded from **HashiCorp Vault** at gateway startup. No plaintext secrets in environment variables or config files.

```bash
# Production: secrets from Vault (recommended)
export SECRETS_BACKEND=vault
export VAULT_ADDR=https://vault.internal:8200
export VAULT_ROLE_ID=<approle-role-id>
export VAULT_SECRET_ID=<approle-secret-id>

# Development: plaintext env vars (NEVER in production)
export JWT_SECRET=$(openssl rand -hex 32)
```

Vault stores: `jwt_secret`, `server_signing_key`, `session_encryption_key`, `redis_url`

Supports: Vault Token auth (dev/CI) and AppRole auth (production).

> Full Vault configuration: [`docs/API_REFERENCE.md#secrets-management`](docs/API_REFERENCE.md#secrets-management)

### Infrastructure & Deployment

**Local development (1 command):**
```bash
./scripts/local-infra.sh up    # Vault + Redis + NATS + 3 MPC nodes + gateway
./scripts/local-infra.sh test  # Run E2E tests
./scripts/local-infra.sh down  # Tear down everything
```

**Docker (production):**
```bash
docker compose -f infra/docker/docker-compose.yml up -d
# Starts: NATS + 3 MPC nodes (separate containers) + gateway
# Each node has its own persistent volume for encrypted key shares
```

**Kubernetes:**
- StatefulSet for MPC nodes (stable DNS: `mpc-node-0.mpc-node.svc`)
- Deployment for gateway
- NATS cluster via Helm chart
- Secrets via External Secrets Operator → Vault
- See `infra/k8s/` for manifests

### Testing

| Layer | Tests | What it proves |
|-------|-------|---------------|
| **Unit** (507) | `cargo test --workspace` | Protocol correctness, chain providers, auth, policy |
| **Signature Verification** (14) | All 50 chains | MPC signature verifies cryptographically per chain |
| **E2E — Gateway** (7) | Vault secrets, Redis sessions, auth, chain endpoints | Infrastructure integration |
| **E2E — Distributed** (2) | 3 nodes keygen + 2 nodes sign via NATS | **True MPC: each node holds 1 share, gateway holds 0** |
| **E2E — NATS** (6) | Transport connectivity, message round-trip, protocol | NATS SignedEnvelope + session isolation |
| **Benchmarks** (~35) | `cargo bench --workspace` | Performance baselines for all operations |

```bash
cargo test --workspace                           # 507 unit tests (~4s)
cargo test --test signature_verification         # 14 sig verification tests
./scripts/local-infra.sh test                    # E2E with live infra
cargo bench --workspace                          # Performance benchmarks
```

---

## Supported Blockchains (50)

### EVM Chains (26)

| Chain | Chain ID | Type | Dwellir | Alchemy | Infura |
|-------|----------|------|:-------:|:-------:|:------:|
| Ethereum | `1` | L1 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Polygon | `137` | L1 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| BSC | `56` | L1 | :white_check_mark: | | |
| Arbitrum | `42161` | L2 (Optimistic) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Optimism | `10` | L2 (OP Stack) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Base | `8453` | L2 (OP Stack) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Avalanche | `43114` | L1 (C-Chain) | :white_check_mark: | | :white_check_mark: |
| Linea | `59144` | L2 (zkEVM) | :white_check_mark: | | :white_check_mark: |
| zkSync Era | `324` | L2 (ZK Rollup) | :white_check_mark: | | |
| Scroll | `534352` | L2 (zkEVM) | :white_check_mark: | | |
| Mantle | `5000` | L2 (Modular) | :white_check_mark: | | |
| Blast | `81457` | L2 (Yield) | :white_check_mark: | | |
| Zora | `7777777` | L2 (OP Stack) | :white_check_mark: | | |
| Fantom | `250` | L1 (DAG) | :white_check_mark: | | |
| Gnosis | `100` | L1 (xDai) | :white_check_mark: | | |
| Cronos | `25` | L1 | :white_check_mark: | | |
| Celo | `42220` | L1 (Mobile) | :white_check_mark: | | |
| Moonbeam | `1284` | Parachain (EVM) | :white_check_mark: | | |
| Ronin | `2020` | L1 (Gaming) | :white_check_mark: | | |
| opBNB | `204` | L2 (BNB) | :white_check_mark: | | |
| Immutable | `13371` | L2 (zkEVM) | :white_check_mark: | | |
| Manta Pacific | `169` | L2 (Privacy) | :white_check_mark: | | |
| Hyperliquid | `999` | L1 (Perps DEX) | :white_check_mark: | | |
| Berachain | `80094` | L1 (PoL) | :white_check_mark: | | |
| MegaETH | `6342` | L2 (Real-time) | :white_check_mark: | | |
| Monad | `143` | L1 (Parallel EVM) | :white_check_mark: | | |

> All EVM chains use **GG20 ECDSA (secp256k1)** signing protocol and **EIP-1559** transaction format.

### UTXO Chains (5)

| Chain | Address Format | Signing | Dwellir | Blockstream | Mempool |
|-------|---------------|---------|:-------:|:-----------:|:-------:|
| Bitcoin (Mainnet) | Taproot P2TR (`bc1p...`) | FROST Schnorr (BIP-340) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Bitcoin (Testnet) | Taproot P2TR (`tb1p...`) | FROST Schnorr (BIP-340) | | :white_check_mark: | :white_check_mark: |
| Litecoin | P2PKH (`L...`) / bech32 (`ltc1...`) | GG20 ECDSA | :white_check_mark: | | |
| Dogecoin | P2PKH (`D...`) | GG20 ECDSA | :white_check_mark: | | |
| Zcash | Transparent (`t1...`) | GG20 ECDSA | :white_check_mark: | | |

### Move Chains (2)

| Chain | Address Format | Signing | Dwellir |
|-------|---------------|---------|:-------:|
| Aptos | `0x` + 64 hex (SHA3-256) | FROST Ed25519 | :white_check_mark: |
| Movement | `0x` + 64 hex (SHA3-256) | FROST Ed25519 | :white_check_mark: |

### Substrate / Polkadot (6)

| Chain | Address (SS58) | Signing | Dwellir |
|-------|---------------|---------|:-------:|
| Polkadot | SS58 prefix 0 | FROST Ed25519 | :white_check_mark: |
| Kusama | SS58 prefix 2 | FROST Ed25519 | :white_check_mark: |
| Astar | SS58 prefix 5 | FROST Ed25519 | :white_check_mark: |
| Acala | SS58 prefix 10 | FROST Ed25519 | :white_check_mark: |
| Phala | SS58 prefix 30 | FROST Ed25519 | :white_check_mark: |
| Interlay | SS58 prefix 2032 | FROST Ed25519 | :white_check_mark: |

> Supports both FROST Ed25519 and **Sr25519 threshold MPC** (Schnorrkel on Ristretto255).

### Cosmos / IBC (5)

| Chain | Address (bech32) | Signing | Dwellir |
|-------|-----------------|---------|:-------:|
| Cosmos Hub | `cosmos1...` | GG20 ECDSA (secp256k1) | :white_check_mark: |
| Osmosis | `osmo1...` | GG20 ECDSA (secp256k1) | :white_check_mark: |
| Celestia | `celestia1...` | GG20 ECDSA / Ed25519 | :white_check_mark: |
| Injective | `inj1...` | GG20 ECDSA (secp256k1) | :white_check_mark: |
| Sei | `sei1...` | GG20 ECDSA (secp256k1) | :white_check_mark: |

### Alt L1s (2)

| Chain | Address Format | Signing | Dwellir |
|-------|---------------|---------|:-------:|
| TON | `0:` + 64 hex (SHA-256) | FROST Ed25519 | :white_check_mark: |
| TRON | Base58Check (`T...`, 0x41 prefix) | GG20 ECDSA (secp256k1) | :white_check_mark: |

### Specialized (1)

| Chain | Address Format | Signing | Dwellir |
|-------|---------------|---------|:-------:|
| Starknet | `0x` + 64 hex (251-bit field) | STARK Threshold MPC | :white_check_mark: |

> STARK curve threshold MPC signing now available via `StarkProtocol`.

### Other Chains (3)

| Chain | Address Format | Signing | Dwellir |
|-------|---------------|---------|:-------:|
| Solana | Base58 (Ed25519) | FROST Ed25519 | :white_check_mark: |
| Sui | `0x` + 64 hex (Blake2b-256) | FROST Ed25519 | :white_check_mark: |
| Monero | Base58 (spend + view key) | FROST Ed25519 | :white_check_mark: |

> RPC Registry supports **failover** (auto-switch on unhealthy), **health tracking** per endpoint, **per-chain config** (timeout, retries), and **custom providers**.

---

## MPC Signing Protocols (6)

| Protocol | Curve | Chains | Crate |
|----------|-------|--------|-------|
| **GG20 ECDSA** | secp256k1 | EVM (26), TRON, Cosmos (5), UTXO (3) | `k256` |
| **FROST Schnorr** | secp256k1 | Bitcoin (Taproot P2TR) | `frost-secp256k1-tr` |
| **FROST Ed25519** | Ed25519 | Solana, Sui, Aptos, Movement, TON, Monero | `frost-ed25519` |
| **Sr25519 Threshold** | Ristretto255 | Polkadot, Kusama, Astar, Acala, Phala, Interlay | `schnorrkel` |
| **STARK Threshold** | Stark curve | Starknet | custom |
| **BLS12-381 Threshold** | BLS12-381 | Filecoin, Ethereum validators | `blst` |

> All protocols support threshold key generation and distributed signing — the full private key is **never** assembled.

---

## Performance

| Category | Operation | Latency | Config |
|----------|-----------|---------|--------|
| **Protocol** | GG20 Keygen | **44 µs** | 2-of-3, local transport |
| | GG20 Sign | **188 µs** | 2 signers |
| | FROST Ed25519 Keygen | **~50 µs** | 2-of-3 |
| **Auth** | Ed25519 Sign | **~9 µs** | handshake transcript |
| | X25519 ECDH | **< 1 µs** | key exchange |
| | SignAuthorization create+verify | **~20 µs** | Ed25519 sign + verify |
| **Chain** | EVM Address Derivation | **~4 µs** | Keccak256 + checksum |
| | Solana Address (Base58) | **~2 µs** | Ed25519 pubkey |
| **Crypto** | ChaCha20-Poly1305 1KB | **~4 µs** | per-message encryption |
| | AES-256-GCM 1KB | **~5 µs** | key store encryption |
| | Argon2id Derive | **72 ms** | 64MiB memory-hard (intentional) |

```bash
cargo bench -p mpc-wallet-core --bench mpc_benchmarks   # Protocol + auth + crypto
cargo bench -p mpc-wallet-chains --bench chain_benchmarks # Chain operations
```

---

## Project Structure

```
crates/
  mpc-wallet-core/     ← MPC protocols, transport, key store, policy, identity, RPC messages
  mpc-wallet-chains/   ← Chain providers: 50 chains across 8 ecosystems
  mpc-wallet-cli/      ← CLI binary (keygen, sign, simulate, audit-verify)
services/
  api-gateway/         ← REST API server, auth, MpcOrchestrator (ZERO shares)
  mpc-node/            ← Standalone MPC node (1 party, 1 share, NATS + EncryptedFileStore)
infra/
  docker/              ← Dockerfile (multi-target: gateway + node), docker-compose.yml
  local/               ← Local dev .env + docker-compose (Vault + Redis + NATS)
  k8s/                 ← Kubernetes manifests (StatefulSet, Ingress, Secrets)
  terraform/           ← Multi-cloud provisioning (AWS, GCP, Azure)
scripts/
  local-infra.sh       ← 1-shot: Vault + Redis + NATS + 3 nodes + gateway
  demo.sh              ← Interactive CLI demo (single-process, no infra)
specs/                 ← AUTH_SPEC.md, SIGN_AUTHORIZATION_SPEC.md
retro/                 ← Decision records (DEC-001..015), lessons, security audits
docs/                  ← Architecture, API reference, CLI guide, deployment
```

---

## Metrics

```
  Chains:    50          Tests:     507 + 15 E2E
  Protocols: 6           CI:        fmt + clippy + test + audit + E2E
  Sprints:   15          Findings:  0 CRITICAL | 0 HIGH open
  Decisions: 15          Benchmarks: ~35
```

---

## License

MIT

---

<p align="center">
  <sub>
    Built with <a href="https://claude.com/claude-code">Claude Code</a> by a team of AI agents.
    <br/>
    No keys were harmed in the making of this SDK.
  </sub>
</p>
