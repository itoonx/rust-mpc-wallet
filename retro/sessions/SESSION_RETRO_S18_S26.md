# Session Retrospective — Sprint 18-26

> **Date:** 2026-03-19 ~ 2026-03-20
> **Sprints:** 18-26 (9 sprints in one session)
> **Milestones:** M1 (Security Hardening) → M2 (CGGMP21) → M3 (HSM/SGX) → M4 (Policy v2)
> **Tests:** 540 → 748 (+208 tests, +38.5%)
> **Commits:** ~60 commits across dev + main

---

## What We Shipped

| Sprint | Theme | Tests | Key Deliverables |
|--------|-------|-------|-----------------|
| 18 | Security Hardening | 553 | SEC-026 signed control plane, AuthorizationCache dedup |
| 19 | CGGMP21 Foundation | 565 | CryptoScheme variant, Feldman VSS keygen, Paillier/Pedersen aux |
| 20 | CGGMP21 Signing | 572 | Pre-signing, 1-round online signing, identifiable abort |
| 21 | CGGMP21 Integration | 623 | Key refresh, 50 chains wired, 32 protocol tests, R6 audit |
| 22 | KMS/HSM | 639 | AES-256-GCM wrapping, KMS envelope interface, Vault rotation |
| 23 | SGX Prototype | 657 | SGX design doc, MockEnclaveProvider, AttestationVerifier |
| 24 | Policy DSL | 693 | PolicyRule AND/OR/NOT, JSON parser, recursive evaluator |
| 25 | Delegation | 720 | DelegationToken, Org→Team→Vault, team-scoped RBAC |
| 26 | Whitelist + Webhooks | 748 | Address whitelist, velocity limits, HMAC-SHA256 webhooks |

## Decisions Made

| ID | Decision | Rationale |
|----|----------|-----------|
| DEC-016 | KMS for DEK wrapping only, not Ed25519 signing | AWS KMS doesn't support Ed25519 |
| DEC-017 | SGX feature-gated, mock in CI | No SGX hardware available |
| DEC-018 | JSON policy DSL, max depth 10, schema v2 | No YAML dep, prevent stack overflow |
| DEC-019 | Webhooks via NATS JetStream, HMAC-SHA256 | At-least-once delivery, standard signing |

## What Went Well

1. **Agent parallelization works** — launching R1+R2 or R2+R4 parallel cut sprint time in half
2. **Worktree isolation** — each agent gets its own git worktree, no file conflicts during work
3. **Trait-first architecture pays off** — `AuthSigner`, `KeyEncryptionProvider`, `EnclaveProvider`, `OrgStore` etc. all had traits defined before implementation, making agent work clean
4. **Test count grew steadily** — 208 new tests = ~23 per sprint average
5. **CI optimization** — merged 5 jobs into 3, eliminated `cargo install cargo-audit` from source
6. **9 sprints in one session** — continuous execution without asking for approval

## What Went Wrong

1. **NATS E2E tests broke on CI** — subscribe race condition wasted ~2 hours debugging
   - Root cause: parties broadcast before peers subscribe on slow CI runners
   - Fix: `client.flush()` + 2-second delay + timeouts on all NATS tests
   - **Lesson L-011, L-012, L-013**

2. **Merge conflicts from parallel agents** — R0 and R4 both defined `PolicyRule` differently (Sprint 24), R0 and R1 both defined `EnclaveProvider` differently (Sprint 23)
   - Workaround: manual conflict resolution or agent fix
   - **Root cause:** agents branch from main (not dev), miss each other's work

3. **Agent silence during long tasks** — user frustrated by `sleep 300` with no status updates
   - Fix: monitor every 60s, report progress
   - **Lesson: feedback_status_updates.md**

4. **`#[cfg(test)]` doesn't work in integration tests** — caused CI compile failure
   - Fix: always pass `--features local-transport` for integration tests
   - **Lesson L-012**

5. **`--test-threads=1` removal broke tests** — NATS tests share wildcard subjects, parallel = message collision
   - **Lesson L-013**

6. **`cargo install cargo-audit` compiled from source every CI run** (2m 48s)
   - Fix: switched to `rustsec/audit-check@v2` pre-built action (~5s)
   - **Lesson L-014**

## Process Observations

### Sprint Velocity
- Average sprint completion: **~15 minutes** (agent work + merge + verify + push)
- Fastest sprint: S25 (8 min — clean parallel, no conflicts)
- Slowest sprint: S23 (25 min — 3-way merge conflicts, type mismatches)

### Agent Performance
- **Most productive:** R1 Crypto (CGGMP21 keygen/sign/refresh, DelegationToken — complex crypto)
- **Most versatile:** R4 Service (KMS, Vault, policy parser, org hierarchy, whitelist, webhooks — 6 features across 5 sprints)
- **Least used:** R3 Chain (only Sprint 21), R7 PM (not used S18-26)

### Merge Conflict Rate
- 4 out of 9 sprints had merge conflicts (S21, S23, S24 had significant ones)
- **Root cause:** agents branch from latest main/dev but don't see each other's in-flight work
- **Mitigation:** merge agents sequentially (implementation → tests → audit), not all at once

## Recommendations for Next Session

1. **Pre-merge R0 before launching other agents** — R0 defines types, others implement. Always merge R0 to dev first.
2. **Use `--test-threads=1` for any tests sharing infrastructure** — NATS, Redis, etc.
3. **Always `client.flush()` after NATS subscribe** — prevent race conditions
4. **Report status every 60 seconds** during agent execution
5. **Run `cargo fmt --all --check` before pushing** — caught 1 fmt issue in CI
6. **Consider R5 comprehensive test sprint** at end of each milestone — catches cross-feature integration issues
7. **R6 audit every 2 sprints** is the right cadence — Sprint 23 and Sprint 26 audits worked well

## CI Pipeline Final State

```
Format check     → 7s
Build & Test     → ~2.5 min (clippy + test + build gateway)
Security audit   → ~5s (pre-built action)
E2E tests        → ~2.5 min (download artifact + run with Vault+Redis+NATS)
Total wall time  → ~5 min
```

## Files Changed (session total)

- **New modules:** `enclave/`, `delegation.rs`, `org/`, `whitelist.rs`, `webhooks/`, `policy/parser.rs`, `policy/evaluator.rs`
- **New docs:** `SGX_DESIGN.md`
- **Modified:** `hsm.rs`, `kms_signer.rs`, `vault.rs`, `schema.rs`, `rbac/mod.rs`, `ci.yml`, `nats.rs`, `CLAUDE.md`, `SECURITY_FINDINGS.md`
