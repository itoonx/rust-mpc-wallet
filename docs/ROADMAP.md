# MPC Wallet SDK — Roadmap

> Updated: 2026-05-07

## Current State (post Sprint 37, PR #23 merged to `main`)

- 970 tests, 7 production threshold protocols
- 68/68 security findings resolved (0 CRITICAL / 0 HIGH open)
- HD wallet derivation (BIP32) for secp256k1 MPC
- OpenAPI spec, SDK quickstart, error code catalog
- Helm chart, Prometheus metrics, /health endpoints
- Audit preparation deliverables: threat model, SBOM, CVE-2025-66016 verification, scope doc

## Completed Sprints

### Sprint 32–33 — Benchmarks + mpc-node coverage
- Benchmark baseline for all 7 protocols
- mpc-node test coverage 0 → 35
- CI benchmark gate
- Protocol common module

### Sprint 34 — Deployment readiness
- mpc-node `/health` endpoint
- Prometheus metrics
- Helm chart (gateway, nodes, NATS, Redis)
- Docker compose E2E

### Sprint 35 — Audit preparation
- Threat model refresh (`docs/THREAT_MODEL.md`)
- Security regression test suite
- CVE-2025-66016 verification (`docs/CVE_2025_66016_VERIFICATION.md`)
- SBOM (`docs/SBOM.txt`)
- Audit scope (`docs/AUDIT_SCOPE.md`)

### Sprint 36 — HD wallet
- BIP32 derivation for GG20 + CGGMP21 (secp256k1)
- `crates/mpc-wallet-core/src/protocol/hd.rs`

### Sprint 37 — SDK & DX
- OpenAPI export via `utoipa` → `docs/openapi.json`
- SDK quickstart (`docs/SDK_QUICKSTART.md`)
- Error code catalog (`docs/ERROR_CODES.md`)

## Open Items (non-blocking, MEDIUM/LOW)

- SEC-009 — Bitcoin Taproot sighash uses empty `prev_out.script_pubkey` (caller must supply)
- SEC-011 — Sui transaction serialization uses JSON instead of BCS
- SEC-012 — EVM finalization does not enforce low-S ECDSA normalization
- SEC-015 — `KeyShare` Debug verification (likely already fixed via SEC-004 — needs re-audit)
- SEC-016 — Bitcoin `SerializableTx::to_tx()` uses `.unwrap()` (panic on malformed input)

## Next Phase Candidates

- **External audit kickoff** — package `v0.1.0-audit` tag, hand off scope doc + SBOM
- **Production hardening** — SLO/SLI definition, runbook drills, on-call docs
- **Chain expansion** — TON / TRON / Cosmos per `specs/CHAIN_ROADMAP.md`
- **SDK clients** — TypeScript / Python / Go wrappers around REST API
