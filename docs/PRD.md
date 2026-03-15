# MPC Wallet SDK — Product Requirements Document

**Version:** 0.1.0-draft  
**Date:** 2026-03-15  
**Author:** R7 PM Agent  
**Status:** Active — Sprint 1

---

## Vision

The MPC Wallet SDK is a production-grade, open-source Rust library that enables institutions,
exchanges, and infrastructure teams to operate threshold multi-party computation wallets across
Ethereum/EVM, Bitcoin, Solana, and Sui — without any single party ever holding or reconstructing
the full private key. The SDK ships as a composable Cargo workspace: a `no_std`-capable crypto
core, pluggable transport and storage backends, per-chain transaction adapters, and a growing set
of enterprise services (policy engine, approval orchestrator, session manager, audit ledger) that
together satisfy SOC 2, ISO 27001, and financial-grade custody requirements.

---

## Goals

1. **Correct threshold cryptography.** Replace all simulation/stub implementations with real,
   auditable MPC protocols (GG20/CGGMP21 for ECDSA; FROST for EdDSA/Schnorr) that provably
   never reconstruct the full private key on any single node.

2. **All supported chains produce valid, broadcastable transactions.** Every chain adapter
   (EVM, Bitcoin, Solana, Sui) must serialize transactions in the exact on-chain wire format and
   produce signatures that verify against on-chain validators — no JSON stubs in production paths.

3. **Enterprise security posture by default.** Signed message envelopes + replay protection,
   zeroized secrets in memory, encrypted at-rest key storage, append-only audit ledger, and a
   "no policy → no sign" gating rule are all non-optional.

4. **Clean, semver-stable public API.** All four core traits (`MpcProtocol`, `Transport`,
   `KeyStore`, `ChainProvider`) are frozen at v0.1.0; breaking changes require a major version
   bump. The SDK is `cargo add`-friendly with feature flags gating heavy optional dependencies.

5. **Operationally self-contained.** SDK consumers can run a fully functional 2-of-3 MPC cluster
   with the local transport and encrypted file store — no external services required for
   development. Production deployments add NATS transport and RocksDB storage via feature flags.

---

## Non-Goals (v1.0)

- **No hardware wallet / HSM integration** — planned for v2.0 (PKCS#11 / AWS CloudHSM).
- **No WASM browser wallet** — `mpc-wallet-core` is structured for future `no_std` + WASM
  support, but browser delivery is not a v1.0 deliverable.
- **No Cosmos / IBC chains** — architecture supports adding them; not in scope.
- **No TON or Aptos** — EdDSA framework is in place; chain adapters are not.
- **No built-in key recovery / social recovery** — disaster recovery is documented as a runbook,
  not an automated protocol.
- **No multi-asset gas abstraction** — each chain pays gas in its native token.
- **No governance / DAO signing flows** — policy engine covers enterprise custody, not DAO voting.

---

## User Personas

### Persona 1 — Crypto Infrastructure Engineer (SDK Consumer)
*Works at an exchange or custodian. Integrates the SDK into their Rust backend.*

**Needs:**
- Clear Rust docs on every public type and trait.
- Feature-flagged dependencies so they don't pull in unused chain crates.
- A working 2-of-3 example they can run locally in under 5 minutes.
- Semver guarantees so upgrades don't break their build without warning.

**Pain points today:**
- GG20 is a simulation that reconstructs the secret — this is a non-starter for production.
- Solana and Sui transaction builders produce JSON, not wire-format bytes.

### Persona 2 — MPC Node Operator
*Runs one or more MPC nodes on behalf of the organization or their customers.*

**Needs:**
- NATS transport with TLS and per-session ECDH encryption so inter-node messages cannot be
  intercepted or replayed.
- Encrypted RocksDB key store so key shares survive node restarts.
- Proactive key refresh to rotate shares without changing the on-chain address.
- Health/heartbeat endpoints to integrate with their monitoring stack.

**Pain points today:**
- NATS transport is a stub (`todo!()`).
- No proactive key refresh implementation.

### Persona 3 — Enterprise Security / Compliance Admin
*Approves signing policy, runs audits, manages approver quorums.*

**Needs:**
- Signed, versioned policy bundles that cannot be bypassed.
- Maker / checker / approver separation of duties enforced at the protocol level.
- Immutable, hash-chained audit ledger with evidence pack export.
- Freeze / break-glass capabilities for incident response.

**Pain points today:**
- Policy engine, approvals, audit ledger, and freeze capabilities are not yet built.

---

## Functional Requirements

### FR-0: Interface Stability (Epic 0)
- FR-0.1: All four public traits (`MpcProtocol`, `Transport`, `KeyStore`, `ChainProvider`) must
  be explicitly versioned and documented.
- FR-0.2: `KeyStore` trait must include `freeze` / `unfreeze` methods (H3 story — coordinate R0/R1).
- FR-0.3: `CryptoScheme` must enumerate all schemes with a real implementation.

### FR-A: Identity & Access (Epic A)
- FR-A.1: OIDC JWT validation middleware with JWKS caching.
- FR-A.2: RBAC permission model (initiator / approver / admin roles).
- FR-A.3: ABAC attribute extensions (cost center, risk tier, department).
- FR-A.4: Step-up MFA requirement for admin-level actions.

### FR-B: Policy Engine (Epic B)
- FR-B.1: JSON Schema + semantic versioning for policy documents.
- FR-B.2: Signed policy bundle releases (required quorum of SECURITY role).
- FR-B.3: Evaluator: allowlists (addresses, contract methods), velocity limits, per-chain limits.
- FR-B.4: Policy templates for Exchange, Treasury, and Custodian use cases.
- FR-B.5: **"No policy → no sign"** — the session manager must gate on a valid, loaded policy
  before any signing session can be created.

### FR-C: Approvals & SoD (Epic C)
- FR-C.1: Approver must sign the full approval payload with their Ed25519 / P256 key.
- FR-C.2: Quorum enforcement: configurable M-of-N approvers per policy.
- FR-C.3: Hold periods: time-locked approvals (configurable minimum wait).
- FR-C.4: Maker / checker / approver separation — same person cannot fill two roles.
- FR-C.5: Break-glass flow: requires additional evidence and higher quorum.

### FR-D: Session Manager (Epic D)
- FR-D.1: Persistent state machine for signing sessions (Pending → Approved → Signing → Done /
  Failed).
- FR-D.2: Idempotent session creation: `tx_fingerprint` uniqueness lock prevents duplicate signs.
- FR-D.3: Retry budget: configurable max retries with exponential back-off.
- FR-D.4: Quorum degrade policy: configurable behavior when a node is unavailable.
- FR-D.5: Anti-tamper: canonical `tx_fingerprint` (hash of fully built transaction) is locked
  the moment a session is created and verified before signing.

### FR-E: Transport Hardening (Epic E)
- FR-E.1: `NatsTransport` fully implements the `Transport` trait (no `todo!()` stubs).
- FR-E.2: mTLS with certificate rotation support.
- FR-E.3: Per-session ECDH layer (X25519 key exchange + ChaCha20-Poly1305 payload encryption).
- FR-E.4: Signed message envelopes (Ed25519 node identity) with monotonic `seq_no` + TTL.
- FR-E.5: JetStream subjects with ACL configuration for multi-tenant deployments.

### FR-F: Audit Ledger (Epic F)
- FR-F.1: Append-only ledger entries with Ed25519 service signature.
- FR-F.2: Hash-chained entries (each entry commits the hash of the previous entry).
- FR-F.3: Evidence pack exporter: policy version + approval signatures + tx hashes in one bundle.
- FR-F.4: `audit-verify` CLI command to verify ledger integrity.
- FR-F.5: WORM storage integration (S3 Object Lock or immudb) for production deployments.

### FR-G: Transaction Simulation (Epic G)
- FR-G.1: EVM: `eth_call` simulation + ABI decoding + proxy contract detection.
- FR-G.2: Bitcoin: PSBT pre-sign validation + fee sanity checks.
- FR-G.3: Solana: program allowlist check + writable account validation.
- FR-G.4: Risk scoring output + policy hook (block or warn based on score).

### FR-H: Key Lifecycle (Epic H)
- FR-H.1: Proactive refresh: time-scheduled or on-demand share rotation without changing the
  group public key or on-chain address.
- FR-H.2: Resharing: add or remove nodes, change threshold — requires strict approval quorum.
- FR-H.3: Freeze / unfreeze: `KeyStore::freeze(group_id)` denies new sessions and aborts pending
  ones; `unfreeze` re-enables. Freeze state persisted in storage.
- FR-H.4: Disaster recovery: documented playbook, tested key reconstruction from backup shards.

### FR-I: Multi-cloud Ops (Epic I)
- FR-I.1: Node distribution constraints: no quorum possible with nodes from a single cloud
  provider (enforced at policy level, not just documentation).
- FR-I.2: Health/heartbeat service: reports quorum risk as a Prometheus metric and structured
  log event.
- FR-I.3: RPC provider failover: broadcaster retries across a ranked list of RPC endpoints.
- FR-I.4: Chaos test suite: node kill mid-round, NATS partition, replay attack.

### FR-J: Production Hardening (Epic J)
- FR-J.1: Replace simulated GG20 with real multi-party ECDSA. No secret reconstruction in
  production code paths.
- FR-J.2: Full BCS transaction serialization for Sui (`TransactionData` struct, not JSON).
- FR-J.3: Real Solana transaction using Solana SDK wire format (or equivalent correct
  serialization).
- FR-J.4: `zeroize` applied to all secret scalars, share data, and ephemeral signing material
  across all protocol implementations.

---

## Non-Functional Requirements

| Category | Requirement |
|----------|-------------|
| **Security** | No single party reconstructs full private key in production. Secrets zeroized in memory. All network messages signed and replay-protected. Encryption at rest. |
| **Performance** | 2-of-3 signing round-trip < 2s on local transport; < 500ms crypto cost per party. |
| **Correctness** | Signatures verify on-chain for all four supported chains. Replay protection tests must pass. |
| **`no_std` compat** | `mpc-wallet-core` crypto logic must be `no_std` capable (no `std::fs`, no `std::net`). |
| **Semver** | Public API in `mod.rs` files frozen at `0.1.0`. Breaking changes require `1.0.0`. |
| **Dependency hygiene** | `cargo audit` must pass with no HIGH/CRITICAL CVEs. Optional deps behind feature flags. |
| **SDK ergonomics** | `cargo add mpc-wallet-core` + 20 lines gets a local 2-of-3 keygen running. |
| **Observability** | OpenTelemetry traces + structured logs (no raw key material in logs) + Prometheus metrics. |
| **CI gate** | `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test --workspace`, `cargo audit` all pass. |

---

## Success Metrics

1. **All chain adapter tests pass** with real wire-format serialization (no JSON stubs).
2. **GG20 never reconstructs the full secret** — verified by unit test that inspects the signing
   path and confirms no `lagrange_interpolate` call in production mode.
3. **NATS transport integration test passes** with two parties in separate Tokio tasks.
4. **Signed envelope replay protection test passes** — a replayed message with stale seq_no is
   rejected.
5. **Policy gate test passes** — a signing session without a loaded policy returns
   `CoreError::PolicyRequired`.
6. **Audit ledger tamper detection test passes** — mutating a ledger entry causes `audit-verify`
   to fail.
7. **`cargo audit` reports zero HIGH/CRITICAL CVEs** at time of v1.0 release.
8. **Proactive key refresh completes** in a 3-of-5 simulated cluster without changing the group
   public key.

---

## MVP Exit Criteria

The following must all be true before the v1.0 release tag is applied:

- [ ] **Real GG20 / TSS** — `Gg20Protocol::sign` does not reconstruct the full private key.
      Signing is distributed across all threshold parties.
- [ ] **All chain adapters green** — `cargo test -p mpc-wallet-chains` passes with wire-format
      Solana and BCS Sui transactions.
- [ ] **NATS transport** — `NatsTransport` has no `todo!()` stubs; integration test with two
      parties passes.
- [ ] **Policy gate** — session manager enforces "no policy → no sign" at runtime.
- [ ] **Approvals quorum** — 2-of-3 approver quorum is enforced before signing session starts.
- [ ] **Freeze** — `KeyStore::freeze` blocks new signing sessions.
- [ ] **Audit ledger** — every signing event is recorded with hash-chain linkage.
- [ ] **Zeroize complete** — all secret scalars and share data use `zeroize::ZeroizeOnDrop`.
- [ ] **`cargo audit` clean** — no unresolved HIGH/CRITICAL advisories.
- [ ] **CI green** — `cargo test --workspace` passes in CI with no skipped tests in critical paths.
