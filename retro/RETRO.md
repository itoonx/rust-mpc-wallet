# MPC Wallet — Retrospective Archive

> Central index for decisions, lessons learned, and security retrospectives.
> This folder captures team knowledge that isn't derivable from code or git history.

---

## Structure

```
retro/
  RETRO.md              ← This file (index)
  decisions/            ← Architectural & product decisions
  lessons/              ← Bugs, root causes, fixes, insights
  security/             ← Security audit reports & finding retrospectives
```

---

## Decisions

| ID | Date | Title | Status |
|----|------|-------|--------|
| [DEC-001](decisions/DEC-001_ecdsa-library.md) | 2026-03-15 | Real GG20 vs alternative ECDSA TSS library | Decided: Zengo GG20 |
| [DEC-002](decisions/DEC-002_solana-serialization.md) | 2026-03-15 | Solana tx serialization approach | Decided: manual binary |
| [DEC-003](decisions/DEC-003_sui-bcs.md) | 2026-03-15 | Sui BCS encoding | Decided: bcs crate |
| [DEC-004](decisions/DEC-004_gg20-commitment.md) | 2026-03-15 | Sprint 2 GG20 as hard commitment | Decided: locked goal |
| [DEC-005](decisions/DEC-005_rbac-scope.md) | 2026-03-15 | Sprint 7 RBAC scope | Decided: Epic A2 only |
| [DEC-006](decisions/DEC-006_solana-v0.md) | 2026-03-15 | Solana v0 versioned tx | Decided: manual serialization |
| [DEC-007](decisions/DEC-007_chain-registry.md) | 2026-03-15 | ChainRegistry unified factory | Decided: single entry point |
| [DEC-008](decisions/DEC-008_frost-reshare.md) | 2026-03-15 | FROST reshare = fresh DKG | Decided: new group key |
| [DEC-009](decisions/DEC-009_dev-branch.md) | 2026-03-15 | Work on dev branch, PR to main | Decided: enforced |
| [DEC-010](decisions/DEC-010_auth-lib-split.md) | 2026-03-17 | Split api-gateway into lib+bin | Decided: for integration tests |
| [DEC-011](decisions/DEC-011_auth-hardening.md) | 2026-03-17 | Auth production hardening architecture | Decided: rate limit + session cap + dynamic revoke + zeroize |
| [DEC-012](decisions/DEC-012_sign-authorization.md) | 2026-03-17 | MPC node independent verification | Decided: SignAuthorization proof before every sign |
| [DEC-013](decisions/DEC-013_remove-api-keys.md) | 2026-03-18 | Remove API key auth | Decided: simplify to mTLS + Session JWT + Bearer JWT |
| [DEC-014](decisions/DEC-014_redis-kms-migration.md) | 2026-03-18 | Redis + KMS/HSM migration | Decided: trait-based backends, encrypted session storage |

---

## Lessons

| ID | Date | Category | Severity | Title |
|----|------|----------|----------|-------|
| [L-001](lessons/L-001_gg20-trusted-dealer.md) | 2026-03-15 | Security | Critical | GG20 trusted-dealer = not real MPC |
| [L-002](lessons/L-002_key-share-not-zeroized.md) | 2026-03-15 | Security | High | KeyShare.share_data Vec<u8> not zeroized |
| [L-003](lessons/L-003_nats-unauthenticated.md) | 2026-03-15 | Security | High | ProtocolMessage.from unauthenticated |
| [L-004](lessons/L-004_auth-method-confusion.md) | 2026-03-17 | Security | Medium | Non-UTF8 header bypasses auth priority — **FIXED** |
| [L-005](lessons/L-005_session-store-unbounded.md) | 2026-03-17 | Security | High | SessionStore has no size limit — **FIXED** |
| [L-006](lessons/L-006_no-rate-limit-auth.md) | 2026-03-17 | Security | High | No rate limiting on auth endpoints — **FIXED** |
| [L-007](lessons/L-007_session-keys-not-zeroized.md) | 2026-03-17 | Security | High | Session key material not zeroized on drop — **FIXED** |
| L-008 | 2026-03-18 | Bug | High | NatsTransport::recv() re-subscribes per call — message loss — **FIXED** |
| L-009 | 2026-03-18 | Architecture | Medium | GG20 signing requires Party 1 (coordinator) in signer subset — **DOCUMENTED** |
| L-010 | 2026-03-18 | Testing | Low | E2E test ordering matters with shared NATS infrastructure — **MITIGATED** |
| L-018 | 2026-03-20 | Architecture | Medium | Don't inflate timeouts to work around slow algorithms — **FIXED** |
| L-019 | 2026-03-20 | Security | Medium | Skip hacks accumulate security debt — **FIXED** |
| [L-011](lessons/L-011_ecdsa-double-hash-sign.md) | 2026-05-07 | Crypto correctness | Critical | GG20/CGGMP21 sign double-hashed the message — **FIXED** |
| [L-012](lessons/L-012_chainregistry-network-not-propagated.md) | 2026-05-07 | Configuration | High | ChainRegistry didn't propagate NetworkEnv to EvmProvider — **FIXED** |
| [L-013](lessons/L-013_value-parsed-as-hex-first.md) | 2026-05-07 | Input parsing | High | build_evm_transaction parsed bare-decimal `value` as hex — **FIXED** |
| [L-014](lessons/L-014_bitcoin-frost-tr-not-tweak-aware.md) | 2026-05-07 | Crypto correctness | High | FROST-Secp256k1-TR doesn't apply BIP-341 tweak — **WORKAROUND** (P2WPKH+ECDSA default) |
| [L-015](lessons/L-015_sui-bcs-must-match-upstream-shape.md) | 2026-05-10 | Wire format | High | Sui hand-rolled BCS struct + raw_tx layout must match validator-side decoder — **FIXED** (ref-vector test enforced) |
| [L-016](lessons/L-016_aptos-double-hash-and-authenticator-order.md) | 2026-05-10 | Wire format | High | Aptos: Ed25519 signs raw `prefix ‖ bcs` (not its SHA3-256 digest), authenticator is pubkey-before-sig with length prefixes — **FIXED** |
| [L-017](lessons/L-017_tron-broadcast-body-shape-and-swagger-reflection.md) | 2026-05-10 | Wire format / API | High | TRON broadcast needs structured `raw_data` JSON alongside `raw_data_hex`; TransferContract omits `fee_limit`; v=27+parity; TronGrid hides errors behind swagger reflection — **FIXED** |

---

## Security

| Report | Date | Scope | Findings |
|--------|------|-------|----------|
| [AUTH-AUDIT-001](security/AUTH-AUDIT-001.md) | 2026-03-17 | Auth system (handshake, middleware) | 46 tests, all HIGH/MED fixed, API keys removed |

---

## Session Retrospectives

| Report | Dates | Scope | Key Metrics |
|--------|-------|-------|-------------|
| [SESSION_RETRO_AUTH](SESSION_RETRO_AUTH.md) | 2026-03-17 ~ 2026-03-18 | Auth system build (mTLS, Session JWT, Bearer JWT, Redis) | ~30 commits, +147 tests, 5 decisions, v0.2.0 |
| [SESSION_RETRO_SPRINT15](SESSION_RETRO_SPRINT15.md) | 2026-03-18 | Production readiness (errors, Vault, NATS fix, sig verify, gateway wiring, benchmarks, CI E2E) | 5 phases, +18 tests, 5 bugs found, ~35 benchmarks |
| [sessions/SESSION_RETRO_S18_S26](sessions/SESSION_RETRO_S18_S26.md) | 2026-03-19~20 | Sprints 18-26 (M1-M4 complete) | 9 sprints, +748 tests, 4 milestones |
| [sessions/SESSION_RETRO_S28_PAILLIER_PERF](sessions/SESSION_RETRO_S28_PAILLIER_PERF.md) | 2026-03-20 | Sprint 28 Paillier perf fix (glass_pumpkin) | 801 tests, CI 19min→2.5min, all ZK proofs enabled |
| [sessions/SESSION_RETRO_S38_S39_LIVE_TESTNET](sessions/SESSION_RETRO_S38_S39_LIVE_TESTNET.md) | 2026-05-06~07 | Sprint 38-39: first live MPC tx on Sepolia + Solana devnet | 2 branches, 4 bugs found+fixed, 3 lessons (L-011..013), 930 tests |

---

## How to Add Entries

### Decisions
Use the ADR (Architecture Decision Record) format:
```
# DEC-NNN: Title
- **Date:** YYYY-MM-DD
- **Status:** Proposed | Decided | Superseded
- **Context:** Why this decision was needed
- **Options:** What was considered
- **Decision:** What was chosen and why
- **Consequences:** What changes as a result
```

### Lessons
```
# L-NNN: Title
- **Date:** YYYY-MM-DD
- **Category:** Bug | Security | Architecture | Workflow
- **Severity:** Critical | High | Medium | Low | Insight
- **What happened:** Description
- **Root cause:** Why
- **Fix:** What was done
- **Takeaway:** What to do/avoid in future
```

### Security Reports
Link to the full report in `docs/SECURITY_*.md` or keep a summary here.
