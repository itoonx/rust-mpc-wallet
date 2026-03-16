# MPC Wallet SDK — Shared Agent Memory

> This file is auto-loaded by Claude Code at every session start.
> Every agent reads this first. No need to re-explain project context.

---

## What This Project Is

**MPC Wallet SDK** — a Rust workspace for threshold multi-party computation wallets.
No single party ever holds a complete private key. Supports EVM, Bitcoin, Solana, Sui.
Target: open-source SDK for enterprise custody systems.

**Workspace root:** `/Users/thecoding/git/project/mpc-wallet`

```
crates/
  mpc-wallet-core/    ← MPC protocols, transport, key store (traits + impls)
  mpc-wallet-chains/  ← Chain providers: EVM, Bitcoin, Solana, Sui
  mpc-wallet-cli/     ← CLI binary (demo only)
docs/
  AGENTS.md           ← Agent roles, ownership, instructions (READ THIS NEXT)
  SPRINT.md           ← Current sprint tasks + Gate Status table
  SECURITY_FINDINGS.md← Open findings — R6 maintains this
  PRD.md              ← Product requirements
  EPICS.md            ← Epic A–J breakdown
  DECISIONS.md        ← DEC-001..N decision log
LESSONS.md            ← Bugs found, root causes, fixes, key insights (READ BEFORE CODING)
```

---

## The Team — Agent Roles

| Role | ID | Worktree | Owns |
|------|----|----------|------|
| Architect | R0 | `/Users/thecoding/git/worktrees/mpc-r0` | traits, types, error, Cargo.toml |
| Crypto | R1 | `/Users/thecoding/git/worktrees/mpc-r1` | protocol/*.rs |
| Infra | R2 | `/Users/thecoding/git/worktrees/mpc-r2` | transport/nats.rs, key_store/rocksdb.rs, audit-ledger |
| EVM Chain | R3a | `/Users/thecoding/git/worktrees/mpc-r3a` | chains/evm/ |
| Bitcoin Chain | R3b | `/Users/thecoding/git/worktrees/mpc-r3b` | chains/bitcoin/ |
| Solana Chain | R3c | `/Users/thecoding/git/worktrees/mpc-r3c` | chains/solana/ |
| Sui Chain | R3d | `/Users/thecoding/git/worktrees/mpc-r3d` | chains/sui/ |
| Service | R4 | — | services/, mpc-wallet-cli/ |
| QA | R5 | — | tests/, .github/workflows/ |
| Security | R6 | `/Users/thecoding/git/worktrees/mpc-r6` | docs/SECURITY*.md (read-only source) |
| PM | R7 | `/Users/thecoding/git/worktrees/mpc-r7` | docs/PRD.md, EPICS.md, SPRINT.md, DECISIONS.md |

**Full role definitions, ownership maps, and instruction templates → `docs/AGENTS.md`**

---

## The One Workflow (non-negotiable)

```
1. R7 PM  →  reads codebase + findings  →  writes Task Specs with Security Checklists
             ends report with: "PROPOSED TASKS — awaiting human approval"

2. Human  →  approves / adjusts plan

3. Agents →  work in their OWN worktree on their OWN branch
             checkpoint commit after EVERY cargo test pass
             "[R{N}] checkpoint: what changed — tests pass"

4. R6     →  audits each branch against R7's Security Checklist
             issues VERDICT: APPROVED or DEFECT per branch
             CRITICAL/HIGH finding = DEFECT = merge blocked

5. Merge  →  orchestrator merges ONLY branches with R6 APPROVED verdict
```

---

## Checkpoint Commit Rule

Every agent commits after **every** `cargo test` pass — no exceptions:

```bash
git add -A
git commit -m "[R{N}] checkpoint: {what changed} — tests pass"
# final:
git commit -m "[R{N}] complete: {task summary}"
```

---

## Current State (as of Sprint 14 — all epics complete, CI green)

### Tests on `main`
```
233 tests pass  (cargo test --workspace)  1 ignored (NATS live-server test)
cargo fmt        clean
cargo clippy     clean (0 warnings, -D warnings)
cargo audit      clean (.cargo/audit.toml ignores unmaintained transitive deps)
CI pipeline      ALL GREEN (fmt + clippy + test + audit)
```

### Sprint Status
- **Sprint 1–8:** COMPLETE — core MPC protocols, transport, key store, policy, approvals, audit
- **Sprint 9:** COMPLETE — ABAC, MFA, EVM simulation, GG20 key refresh
- **Sprint 10:** COMPLETE — FROST Ed25519/Secp256k1 refresh, signed policy bundles, Bitcoin simulation
- **Sprint 11:** COMPLETE — Policy templates, Solana/Sui simulation, CLI simulate, ChainRegistry
- **Sprint 12:** COMPLETE — GG20 key resharing, multi-cloud ops (distribution + quorum risk)
- **Sprint 13:** COMPLETE — FROST reshare, DR plan, RPC failover, chaos framework
- **Sprint 14:** COMPLETE — JetStream ACL (E5), WORM storage config (F4), CI fixes (clippy + audit)

**All 10 epics: 100% COMPLETE**

### New in Sprint 12–14
- `mpc_wallet_core::protocol` — Epic H2: GG20 key resharing (change threshold + add/remove parties)
- `mpc_wallet_core::ops` — Epic I: multi-cloud node distribution constraints, quorum risk assessment, RPC failover pool, chaos test framework, disaster recovery plan
- `mpc_wallet_core::transport::jetstream` — Epic E5: JetStream stream config + per-party ACL with subject isolation
- `mpc_wallet_core::audit` — Epic F4: WORM storage config (S3 Object Lock + local append-only)
- FROST Ed25519 + Secp256k1 reshare (DKG-based, new group key)
- CI fully green: clippy -D warnings, cargo audit with .cargo/audit.toml

### New in Sprint 11
- `mpc_wallet_core::policy::templates` — Epic B4: policy templates (Exchange/Treasury/Custodian presets) with `PolicyTemplate::apply()` convenience
- `mpc_wallet_chains::solana::simulate` — Epic G3: Solana transaction simulation (program allowlist + value checks)
- `mpc_wallet_chains::sui::simulate` — Epic G4: Sui transaction simulation (value + gas budget checks)
- `mpc-wallet-cli` — Epic G5: `simulate` command for pre-sign transaction risk assessment
- `mpc_wallet_chains::registry` — `ChainRegistry` unified provider factory (DEC-007)

### New in Sprint 10
- `mpc_wallet_core::protocol::frost_refresh` — Epic H1: FROST Ed25519 key refresh (DKG-based re-sharing preserves group pubkey)
- `mpc_wallet_core::protocol::frost_secp_refresh` — Epic H1: FROST Secp256k1 key refresh (additive re-sharing for Taproot)
- `mpc_wallet_core::policy::signed_bundle` — Epic B3: policy signed bundles (Ed25519 sign+verify for policy integrity)
- `mpc_wallet_chains::bitcoin::simulate` — Epic G2: Bitcoin transaction simulation (fee/dust/RBF checks)

### New in Sprint 9
- `mpc_wallet_core::identity::abac` — Epic A3: ABAC attribute extensions (dept/cost_center/risk_tier extracted from JWT claims)
- `mpc_wallet_core::identity::mfa` — Epic A4: MFA step-up enforcement (require_mfa flag + admin-gated operations)
- `mpc_wallet_chains::evm::simulate` — Epic G1: EVM transaction simulation (risk scoring + proxy detection)
- `mpc_wallet_core::protocol::gg20_refresh` — Epic H1: GG20 key refresh (additive re-sharing preserves group pubkey)

### New in Sprint 8
- `mpc_wallet_core::transport::session_key` — Epic E3: per-session X25519 ECDH + ChaCha20-Poly1305 encryption, HKDF key derivation, nonce counter
- `mpc_wallet_core::identity` — Epic A1 (FR-A.1): JWT token validation (RS256/ES256/HS256), claims extraction, `AuthContext` population from JWT
- `mpc_wallet_core::policy` — Epic B3: daily velocity limit enforcement in `PolicyStore::check()`, rolling 24h window counter, `record_transaction()` + `prune_velocity()`
- `mpc_wallet_core::protocol::MpcProtocol` — Epic H1 prep: `refresh()` default stub on trait (returns not-implemented)
- `mpc_wallet_chains::provider::ChainProvider` — Epic G1 prep: `simulate_transaction()` default stub + `SimulationResult` type

### New in Sprint 7
- `mpc_wallet_core::transport::nats` — Epic E2: mTLS support via `NatsTlsConfig` + `connect_signed_tls()`, PEM cert loading, client key zeroization (SEC-004 pattern)
- `mpc_wallet_core::rbac` — Epic A2 (FR-A.2): RBAC permission model with `ApiRole` (initiator/approver/admin), `AuthContext`, `Permissions` guards, `CoreError::Unauthorized`
- `mpc_wallet_chains::solana::tx` — Solana v0 versioned transactions with `0x80` version prefix, `AddressLookupTable` support, legacy backward-compatible
- `mpc-wallet-cli` — Epic F3: `audit-verify --pack-file <path>` command using `AuditLedger::verify_pack()`
- `mpc_wallet_core::session::state` — `Session.initiator_id` field for RBAC audit trail + SoD enforcement

### New in Sprint 6
- `NatsTransport` — SEC-007 WIRED: SignedEnvelope on every send/recv, peer key registry, monotonic seq_no
- `mpc_wallet_core::session` — FR-D3: `save_to_dir` / `load_from_dir` persistence across restarts
- `mpc_wallet_core::audit` — FR-F.2: `export_evidence_pack` JSON bundle + `verify_pack` tamper-check
- EVM `tx.rs` — SEC-012 FIX: auto-normalise high-S ECDSA signatures (EIP-2 low-S enforcement)

### New in Sprint 5
- `mpc_wallet_core::approvals` — Approval workflow: Ed25519 quorum enforcement, maker/checker/approver SoD (FR-C)
- `mpc_wallet_core::audit` — Append-only hash-chained audit ledger with Ed25519 service signatures + `verify()` tamper detection (FR-F)
- `mpc_wallet_core::transport::signed_envelope` — SEC-007 FIX: Ed25519 signed envelope + seq_no replay protection + TTL
- Bitcoin `tx.rs` — SEC-009 FIX: require `prev_script_pubkey` for Taproot sighash (invalid tx prevention)
- Bitcoin `tx.rs` — SEC-016 FIX: `SerializableTx::to_tx()` unwrap → proper error propagation

### New in Sprint 4
- `mpc_wallet_core::policy` — Policy Engine with "no policy → no sign" gate (FR-B5)
- `mpc_wallet_core::session` — Session Manager with tx_fingerprint idempotency lock (FR-D1/D2)
- Real freeze/unfreeze persistence in `EncryptedFileStore` (FR-H3)
- SEC-004 ROOT FIX: `KeyShare.share_data` is now `Zeroizing<Vec<u8>>`
- SEC-015 FIX: `KeyShare::Debug` redacts `share_data` → `"[REDACTED]"`

### Open CRITICAL Security Findings (block production)
| ID | Summary | Owner | Sprint |
|----|---------|-------|--------|
| (none) | All CRITICAL findings resolved | — | — |

### Resolved CRITICAL Findings
| ID | Summary | Resolved |
|----|---------|---------|
| SEC-001 | GG20 reconstructed full private key | Sprint 2 T-S2-01 — distributed additive-share signing |
| SEC-002 | Hardcoded "demo-password" in CLI | Sprint 2 T-S2-03 — rpassword interactive prompt |
| SEC-003 | NatsTransport = all `todo!()` stubs | Sprint 3 T-S3-01 — real async-nats implementation |
| SEC-011 | Sui tx was JSON stub | Sprint 2 T-S2-04 — real BCS encoding |

### Open HIGH Findings (block merge)
| ID | Summary | Owner |
|----|---------|-------|
| (none) | All HIGH findings resolved | — |

### Resolved HIGH Findings
| ID | Summary | Resolved |
|----|---------|---------|
| SEC-004 | `KeyShare.share_data` Vec<u8> not zeroized | Sprint 4 T-S4-00/T-S4-01 — `Zeroizing<Vec<u8>>` root fix |
| SEC-005 | EncryptedFileStore password not zeroized | Sprint 3 T-S3-02 — Zeroizing<String> |
| SEC-006 | Argon2 default params too weak | Sprint 3 T-S3-02 — 64MiB/3t/4p |
| SEC-007 | ProtocolMessage.from unauthenticated | Sprint 6 T-S6-01 — NatsTransport wired with SignedEnvelope Ed25519 + seq_no |
| SEC-009 | Bitcoin Taproot sighash uses empty script_pubkey | Sprint 5 T-S5-03 — require prev_script_pubkey |
| SEC-012 | EVM high-S ECDSA signatures not normalised | Sprint 6 T-S6-03 — auto-normalise via n-s + flip recovery_id |
| SEC-015 | KeyShare derives Debug — share bytes in logs | Sprint 4 T-S4-00 — manual Debug impl redacts share_data |
| SEC-016 | Bitcoin SerializableTx::to_tx() uses unwrap | Sprint 5 T-S5-03 — proper error propagation |

Full findings log → `docs/SECURITY_FINDINGS.md`

---

## Key Decisions Already Made

| DEC | Decision |
|-----|----------|
| DEC-001 | Sprint 2 delivered distributed ECDSA (additive-share signing, no key reconstruction) |
| DEC-002 | Solana: manual binary serialization + round-trip tests validate structure |
| DEC-003 | Sui: `bcs` crate for BCS encoding — DONE Sprint 2 |
| DEC-004 | Sprint 2 GG20 hard commitment — DELIVERED |
| DEC-005 | Sprint 7 RBAC: Epic A2 only (roles + guards); OIDC/ABAC/MFA deferred to Sprint 8 |
| DEC-006 | Solana v0: manual serialization continues (DEC-002 extended); no solana-sdk dependency |
| DEC-007 | ChainRegistry: unified provider factory pattern — single entry point for all chain providers |
| DEC-008 | FROST reshare = fresh DKG (new group key); GG20 reshare preserves group key via additive re-sharing |
| DEC-009 | Work on `dev` branch; PR to `main` only after CI green |

Full decision log → `docs/DECISIONS.md`

---

## What NOT to do

- **Never** merge a branch without R6 `APPROVED` verdict
- **Never** modify files outside your owned list (check `docs/AGENTS.md`)
- **Never** commit without `cargo test` passing first
- **Never** spawn agents — propose plan, wait for human approval
- **Never** add a new crate dependency without R0 approval + `cargo audit` check
- **Never** put secret material in logs, error messages, or debug output

---

## Quick Start for Any Agent

```
1. Read this file (CLAUDE.md) ✓ — you're doing it now
2. Read LESSONS.md            → know what bugs/mistakes have already happened
3. Read docs/AGENTS.md        → find your role, owned files, instruction template
4. Read docs/SPRINT.md        → find your assigned task + Security Checklist
5. Read docs/SECURITY_FINDINGS.md → know what's open and what to avoid
6. Do your task in YOUR worktree (see table above)
7. Checkpoint commit after every cargo test pass
8. Report complete → R6 will audit before merge
```
