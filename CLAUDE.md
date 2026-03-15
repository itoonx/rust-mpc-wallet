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

## Current State (as of Sprint 2 complete)

### Tests on `main`
```
52 tests pass  (cargo test --workspace)
cargo check    clean
.github/workflows/ci.yml  ← CI pipeline active
```

### Sprint Status
- **Sprint 1:** COMPLETE — all 5 tasks merged (T-01, T-02, T-05, T-06, T-07)
- **Sprint 2:** COMPLETE — all 5 tasks merged (T-S2-00 through T-S2-05)
- **Sprint 3:** PENDING — NATS transport (SEC-003), Key Lifecycle real impl, Policy Engine

### Open CRITICAL Security Findings (block production)
| ID | Summary | Owner | Sprint |
|----|---------|-------|--------|
| SEC-003 | NatsTransport = all `todo!()` stubs | R2 | Sprint 3 Epic E |

### Resolved CRITICAL Findings
| ID | Summary | Resolved |
|----|---------|---------|
| SEC-001 | GG20 reconstructed full private key | Sprint 2 T-S2-01 — distributed additive-share signing |
| SEC-002 | Hardcoded "demo-password" in CLI | Sprint 2 T-S2-03 — rpassword interactive prompt |
| SEC-011 | Sui tx was JSON stub | Sprint 2 T-S2-04 — real BCS encoding |

### Open HIGH Findings (block merge)
| ID | Summary | Owner |
|----|---------|-------|
| SEC-004 | `KeyShare.share_data` Vec<u8> not zeroized | R0/R1 |
| SEC-005 | EncryptedFileStore password not zeroized | R2 |
| SEC-006 | Argon2 default params too weak | R2 |
| SEC-007 | ProtocolMessage.from unauthenticated | R2/R0 |

Full findings log → `docs/SECURITY_FINDINGS.md`

---

## Key Decisions Already Made

| DEC | Decision |
|-----|----------|
| DEC-001 | Sprint 2 delivered distributed ECDSA (additive-share signing, no key reconstruction) |
| DEC-002 | Solana: manual binary serialization + round-trip tests validate structure |
| DEC-003 | Sui: `bcs` crate for BCS encoding — DONE Sprint 2 |
| DEC-004 | Sprint 2 GG20 hard commitment — DELIVERED |

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
