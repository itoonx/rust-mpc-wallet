# MPC Wallet — Rust Architecture Specification

> Enterprise-grade threshold MPC wallet. Zero-cost abstractions. Fearless concurrency. No GC pauses.

---

## Cargo Workspace Structure

```
Cargo.toml (workspace)
├── mpc-wallet-core      ← crypto engine: TSS + EdDSA + no_std capable
├── mpc-wallet-chains    ← chain adapters: 50 chains (EVM, BTC, SOL, DOT, etc.)
└── mpc-wallet-cli       ← CLI binary: keygen / sign / bench
```

---

## Architecture Layers

### 01 — Client Layer (`mpc-client`)

| Component | Description |
|-----------|-------------|
| **Rust SDK** | `MPCClient` struct — async/await: `create_wallet()`, `sign_tx()`, `reshare()` |
| **Signer Trait** | `trait Signer: Send + Sync` — `LocalSigner`, `AwsKmsSigner`, pluggable |
| **Authorizer** | Multi-sig approval layer — Ed25519 / P256, optional zero-trust |
| **gRPC Gateway** | tonic server — expose wallet ops to non-Rust services |

### 02 — Transport Layer (`mpc-transport`)

| Component | Description | Crates |
|-----------|-------------|--------|
| **NATS** | Tokio-native NATS client, zero-copy publish, JetStream durable, TLS rustls | `async-nats`, `rustls` |
| **ECDH P2P Encryption** | Per-session X25519 key exchange, ChaCha20-Poly1305 payload, double layer on TLS | `x25519-dalek`, `chacha20poly1305` |
| **Message Codec** | MessagePack serialization, 5-10x faster than JSON, zero-copy deserialize | `rmp-serde`, `bytes` |
| **Service Discovery** | Consul HTTP client or mDNS for local cluster, health check loop | `reqwest` |

### 03 — MPC Node Cluster (`mpc-node`)

```
⬡ Node 0 (tokio::task)          ⬡ Node 1 (tokio::task)          ⬡ Node 2 (tokio::task)
├── KeyShare (Arc<RwLock>)       ├── KeyShare (Arc<RwLock>)       ├── KeyShare (Arc<RwLock>)
├── TSS round handler            ├── TSS round handler            ├── TSS round handler
├── RocksDB encrypted store      ├── RocksDB encrypted store      ├── RocksDB encrypted store
└── Auto backup (age crypt)      └── Auto backup (age crypt)      └── Auto backup (age crypt)
```

> **Threshold:** `t ≥ ⌊n/2⌋ + 1` · default 2-of-3 · full private key never reconstructed · `tokio::select!` concurrent rounds

### 04 — Crypto Core (`mpc-core`, no_std capable)

| Component | Description | Crates |
|-----------|-------------|--------|
| **ECDSA TSS** | GG20/CGGMP21 on secp256k1 — Keygen, Sign, Reshare | `k256`, `sha2` |
| **EdDSA / FROST** | FROST Ed25519 + Schnorr for Solana, Aptos, TON, Bitcoin Taproot | `frost-ed25519`, `ed25519-dalek` |
| **Sr25519** | Threshold Schnorrkel on Ristretto255 for Substrate/Polkadot | `schnorrkel` |
| **BLS12-381** | Threshold BLS — linearly homomorphic, for Filecoin/validators | `blst` |
| **STARK** | Threshold signing on Stark curve for StarkNet | custom |
| **HD Key Derivation** | BIP32-compatible child key derivation, shared `chain_code` | `tiny-hderive`, `hmac` |
| **Key Resharing** | Change node set / threshold without changing public key / address, proactive refresh | built-in |

### 05 — Chain Adapters (`chains/*`)

**Supported Ecosystems:**

| Chip | Signing |
|------|---------|
| **Ξ EVM** (26 chains) | ECDSA |
| **₿ Bitcoin** | ECDSA + Schnorr |
| **◎ Solana** | EdDSA |
| **⚛ Cosmos** (5 chains) | ECDSA |
| **🔺 Aptos/Sui** | EdDSA |
| **💎 TON** | EdDSA |
| **◉ Polkadot** (6 chains) | Sr25519 / Ed25519 |
| **▲ Starknet** | STARK |
| **＋ pluggable** | trait |

**Chain Provider Trait:**

```rust
trait ChainProvider: Send + Sync {
    fn chain(&self) -> Chain;
    fn derive_address(&self, pub_key: &GroupPublicKey) -> Result<String>;
    async fn build_transaction(&self, params: TransactionParams) -> Result<UnsignedTransaction>;
    fn finalize_transaction(&self, raw: &UnsignedTransaction, sig: &MpcSignature) -> Result<SignedTransaction>;
    async fn broadcast(&self, tx: &SignedTransaction, rpc_url: &str) -> Result<String>;
    async fn simulate_transaction(&self, params: &TransactionParams) -> Result<SimulationResult>;
}
```

### 06 — Storage Layer (`mpc-storage`)

| Component | Description | Crates |
|-----------|-------------|--------|
| **RocksDB** | Column families, AES-256 encryption at rest | `rocksdb` |
| **Key Zeroize** | Wipe secrets from memory immediately after use, Rust Drop trait integration | `zeroize`, `secrecy` |
| **Encrypted Backup** | age encryption, tokio::time interval, backup to local / S3 / GCS | `age`, `object_store` |

---

## Rust Performance Advantages

| Advantage | Description |
|-----------|-------------|
| **Zero-cost Abstraction** | `trait ChainProvider` compiles to static dispatch, no vtable overhead, monomorphization |
| **Fearless Concurrency** | `Arc<RwLock<KeyShare>>`, `tokio::select!` parallel TSS rounds, no data race by design |
| **No GC Pauses** | Signing latency deterministic, no stop-the-world GC, critical for real-time threshold |
| **MessagePack** | `rmp-serde` instead of JSON, 5-10x faster serialization, zero-copy Bytes for NATS payload |
| **Memory Safety** | `zeroize` secrets, `secrecy::Secret<T>`, borrow checker prevents use-after-free, no undefined behavior |
| **WASM Ready** | `mpc-core` separable as `no_std`, compile to WASM for browser wallet in the future |

---

## Security Model (STRIDE)

### Assets to Protect

- Key shares (per-node) — never reconstruct
- Signing authorization (policy + approvals)
- Transaction integrity (no tampering / no downgrade)
- Audit evidence (immutable, verifiable chain)
- Node identities + mTLS keys
- Allowlist / limits / policy versions

### Trust Boundaries

1. **Client ↔ API Gateway** — OIDC, mTLS optional
2. **Control Plane ↔ Data Plane** — NATS mTLS + signed envelopes
3. **MPC Nodes ↔ Storage** — envelope encryption, KMS-wrapped KEK
4. **Broadcast ↔ Chain RPC** — rate limit, provider failover
5. **Audit Ledger** — append-only + hash chain + signatures

### STRIDE Threat Matrix

| Threat | Mitigation |
|--------|------------|
| **S**poofing — fake node / fake approver | mTLS + node identity (Ed25519), OIDC + phishing-resistant MFA, cert pinning |
| **T**ampering — modify tx / policy / messages | tx_fingerprint immutability, signed envelopes, policy bundle signed releases, hash-chained audit ledger |
| **R**epudiation — "I didn't approve" | approver signature over approval payload, immutable ledger, evidence pack export |
| **I**nformation disclosure — leak keyshares | transcript hash-only, envelope encryption at rest, strict logs scrub, memory zeroize |
| **D**enial of service — flood rounds/bus | rate limit, JetStream backpressure, per-session seq_no + TTL, circuit breakers, quorum continue policy |
| **E**levation of privilege — bypass policy | "no policy, no sign" gating, SoD (maker/checker/approver), admin actions require higher quorum |

### Break-glass / Freeze

- **Freeze wallet:** deny new sessions, abort pending
- **Break-glass:** extra approvals + step-up MFA + extra evidence
- **Incident mode:** stricter policy, longer holds, manual broadcast

### Key Risks (Top 10)

1. Approval bypass / policy bug
2. Tx tampering between build → sign
3. Replay on message bus
4. Nonce misuse / bias
5. Node co-location blast radius
6. Secrets in logs / core dumps
7. KMS/IAM compromise
8. RPC manipulation / MEV attacks (EVM)
9. Insider abuse (SoD failure)
10. Audit evidence gaps

### Mitigations (Must Implement)

- Policy-as-code + signed releases
- tx_fingerprint canonical hash locked pre-sign
- seq_no monotonic + expiring envelopes
- nonce hardening (commit + deterministic fallback)
- 3-of-5 across multi-cloud + on-prem
- zeroize + secrecy + crash/ptrace hardening
- envelope encryption (DEK + KMS-wrapped KEK)
- tx simulation + contract method allowlists
- maker/checker/approver enforced
- append-only ledger + evidence pack

### Security Testing Plan

- **Unit:** state machine, policy edges, replay reject
- **Integration:** full sign flow with mocked nodes
- **Chaos:** kill node mid-round, partition NATS
- **Red-team:** approval spoof, tx tampering attempt
- **Secrets:** log scanning + core dump prevention
- **Supply chain:** crate audit + SBOM

---

## Repo Layout (Enterprise v2)

```
/
├── Cargo.toml (workspace)
├── README.md
├── docs/
│   ├── SPECS.md (this file)
│   ├── THREAT_MODEL.md
│   └── RUNBOOKS.md
├── infra/
│   ├── k8s/ (helm/kustomize)
│   └── terraform/ (multi-cloud + on-prem stubs)
├── crates/
│   ├── mpc-core/ (crypto engine: ECDSA TSS + FROST + Sr25519 + BLS + STARK)
│   ├── mpc-transport/ (NATS, mTLS, envelopes, replay protect)
│   ├── mpc-storage/ (envelope encryption, zeroize, backups)
│   └── chains/ (evm, bitcoin, solana, cosmos, substrate, aptos, ton, tron, starknet, monero, utxo)
├── services/
│   ├── api-gateway/ (Axum: auth + routing + rate limit)
│   ├── policy-engine/ (policy eval + signed releases)
│   ├── approval-orchestrator/ (SoD workflow + quorum)
│   ├── tx-builder/ (canonical tx build + fingerprint)
│   ├── tx-simulator/ (EVM simulate, BTC/SOL validators)
│   ├── session-manager/ (state machine, retries, idempotency)
│   ├── broadcaster/ (broadcast + confirm + provider failover)
│   └── audit-ledger/ (append-only hash chain + evidence pack)
└── bins/
    ├── mpc-node/ (daemon, per-cloud deployment)
    └── mpc-cli/ (keygen/sign/reshare/bench/admin helpers)
```

---

## CI Pipeline (Required)

- `cargo fmt` + `cargo clippy` (deny warnings)
- Unit tests + integration tests
- `cargo audit` + supply-chain checks
- SBOM generation (CycloneDX)
- Secret scanning (no keys in repo)
- Container build + signature (cosign)
- Deploy to staging + smoke tests

## Security Gates

- Policy bundle signed releases enforced
- No policy → no sign (compile-time + runtime guard)
- Replay protection tests must pass
- Evidence pack export required for production
- Log scrub + PII/secret redaction tests

## Observability Standard

- `tracing` + OpenTelemetry traces
- Prometheus metrics: p95 sign latency, quorum risk
- Structured JSON logs with correlation id
- Alerts: node quorum, replay attempts, policy denies spike

---

## Delivery Plan (Epics)

### Epic A — Identity & Access
- A1: OIDC auth middleware (JWKS cache)
- A2: RBAC permissions + endpoint guards
- A3: ABAC attributes (dept/cost center/risk tier)
- A4: Admin actions: step-up MFA requirement (policy)

### Epic B — Policy Engine
- B1: Policy schema + versioning
- B2: Signed policy releases (SECURITY quorum)
- B3: Evaluator: allowlist/limits/risk
- B4: Templates: Exchange/Treasury/Custodian

### Epic C — Approvals & SoD
- C1: Approval payload signing (approver signature)
- C2: Quorum enforcement + hold periods
- C3: Maker/Checker/Approver separation validation
- C4: Break-glass approvals (extra evidence)

### Epic D — Session Manager
- D1: State machine + persistence
- D2: Idempotent execute + request locking
- D3: Retry budgets + quorum degrade logic
- D4: Anti-tamper: tx_fingerprint lock pre-sign

### Epic E — Transport Hardening
- E1: mTLS + cert rotation plan
- E2: Signed envelopes (Ed25519 node identity)
- E3: Replay protection (seq_no, TTL)
- E4: JetStream subjects + ACL

### Epic F — Audit Ledger
- F1: Append-only ledger + hash chain + service signature
- F2: Evidence pack exporter (policy+approvals+hashes+tx)
- F3: Tamper verification CLI (audit-verify)
- F4: WORM storage integration (S3 object lock or immudb)

### Epic G — Tx Simulation
- G1: EVM simulate + ABI decode + proxy detect
- G2: BTC PSBT validation + fee sanity
- G3: SOL program allowlist + writable checks
- G4: Risk score + policy hooks

### Epic H — Key Lifecycle
- H1: Proactive refresh schedule + ceremony records
- H2: Reshare add/remove nodes (strict approvals)
- H3: Freeze/unfreeze wallet + abort sessions
- H4: Disaster recovery playbook + drills

### Epic I — Multi-cloud Ops
- I1: Enforce node distribution constraints (no 3-in-1 cloud quorum)
- I2: Health/heartbeat + quorum risk alerts
- I3: Provider failover for RPC broadcasting
- I4: Chaos tests: node kill, partition, replay

---

## MVP Exit Criteria

- 3-of-5 signing across multi-cloud + on-prem
- Policy enforced pre-sign + approvals quorum enforced
- Signed envelopes + replay protection passing tests
- Append-only audit ledger + evidence pack export
- Freeze + break-glass runbooks tested
