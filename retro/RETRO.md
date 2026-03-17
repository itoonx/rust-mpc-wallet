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

---

## Security

| Report | Date | Scope | Findings |
|--------|------|-------|----------|
| [AUTH-AUDIT-001](security/AUTH-AUDIT-001.md) | 2026-03-17 | Auth system (handshake, middleware, HMAC) | 57 tests, all HIGH/MED fixed, 3 LOW + 1 INFO accepted |

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
