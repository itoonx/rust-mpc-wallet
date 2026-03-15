# MPC Wallet SDK — Lessons Learned

> **Purpose:** Capture bugs found, root causes, fixes, and key insights so the whole team
> learns together and doesn't repeat the same mistakes.
>
> **Who updates this:** Any agent that finds a bug, resolves a finding, or discovers an insight.
> R6 (Security) and R7 (PM) review this at the start of every sprint.
>
> **Format:** Each entry has a date, category, severity, what happened, root cause, fix, and takeaway.

---

## How to Add an Entry

```markdown
### LESSON-{NNN}: Short Title
- **Date:** YYYY-MM-DD
- **Category:** Bug | Security | Architecture | Workflow | Tooling
- **Severity:** Critical | High | Medium | Low | Insight
- **Found by:** R{N} during {activity}
- **Related finding:** SEC-{NNN} (if applicable)

**What happened:**
[Describe the bug or insight — what was observed]

**Root cause:**
[Why did this happen — the underlying reason]

**Fix / Resolution:**
[What was done to fix it — code change, process change, etc.]

**Takeaway:**
[The lesson — what to do or avoid in future]
```

---

## Security Lessons

### LESSON-001: GG20 Trusted-Dealer = Not Real MPC
- **Date:** 2026-03-15
- **Category:** Security
- **Severity:** Critical
- **Found by:** R6 during initial security audit
- **Related finding:** SEC-001

**What happened:**
The initial GG20 implementation used a trusted-dealer model. During `sign()`, every participating
party called `lagrange_interpolate()` on all collected shares — reconstructing the **full private key**
in memory. This completely negates the MPC security guarantee: if any process is compromised
during signing, the attacker gets the full key.

**Root cause:**
Lagrange interpolation is the mathematically correct way to combine Shamir shares into the secret.
It was used for simplicity in the initial prototype, but the prototype was treated as production code.
The distinction between "threshold key reconstruction" and "threshold signing without reconstruction"
was not enforced.

**Fix / Resolution:**
- Sprint 1 (T-01): Gated the simulation behind `#[cfg(feature = "gg20-simulation")]` feature flag
  so it is **off by default** and cannot be used accidentally.
- Sprint 2 (T-S2-01): Will replace with real Zengo GG20/CGGMP21 where signing is done with
  additive share arithmetic — the full key is never assembled.

**Takeaway:**
> "Simulated MPC" is not MPC. Before writing any protocol shortcut, explicitly state in code and
> docs whether it is production-safe. Use `#[cfg(feature = "...")]` to make unsafe paths
> opt-in, never opt-out.

---

### LESSON-002: Hardcoded Fallback Password Silently Breaks Encryption
- **Date:** 2026-03-15
- **Category:** Security
- **Severity:** Critical
- **Found by:** R6 during initial security audit
- **Related finding:** SEC-002

**What happened:**
All four CLI commands (`keygen`, `sign`, `address`, `keys`) had:
```rust
let password = args.password.unwrap_or_else(|| "demo-password".into());
```
Any user who didn't pass `--password` got silently encrypted with a known, hardcoded string.
The AES-256-GCM + Argon2id encryption layer was completely bypassed in practice.

**Root cause:**
Developer convenience during prototyping. The fallback was added to avoid prompting during
automated testing and was never removed before the code was treated as a real implementation.

**Fix / Resolution:**
Tracked as SEC-002 (CRITICAL). Sprint 2 task: remove fallback, require either `--password` flag
or an interactive prompt (using `rpassword` crate). Tests must use an explicit password.

**Takeaway:**
> Never use `unwrap_or` with a hardcoded secret. If a password is required for security,
> make its absence a compile-time or runtime **error**, not a silent fallback.
> Test code should use a clearly-named constant like `TEST_PASSWORD_DO_NOT_USE_IN_PROD`.

---

### LESSON-003: Truncated Transaction Hash Is Not a Hash
- **Date:** 2026-03-15
- **Category:** Bug
- **Severity:** Medium → Fixed
- **Found by:** R6 during initial audit (SEC-010), fixed by R3c in T-07
- **Related finding:** SEC-010

**What happened:**
`finalize_solana_transaction` returned:
```rust
let tx_hash = hex::encode(&signature[..8]);
```
This is only the first 8 bytes of the 64-byte Ed25519 signature as hex — a 16-character string.
A real Solana transaction ID is the full base58-encoded 64-byte signature (~88 characters).
Any downstream code trying to look up or verify the transaction by hash would fail silently.

**Root cause:**
Placeholder code from the initial stub that was never updated. `[..8]` was likely chosen
to produce a "short enough" string for display purposes, without considering correctness.

**Fix / Resolution:**
T-07 (R3c, Sprint 1): Changed to `bs58::encode(signature).into_string()` — full 64-byte
base58 encoding. `bs58` was already a workspace dependency. One-line fix.

**Takeaway:**
> A "tx hash" must be the canonical identifier for the transaction on that chain.
> For Solana: it's the base58-encoded 64-byte signature.
> For EVM: it's the keccak256 of the RLP-encoded signed transaction.
> Never truncate or approximate a hash — it breaks lookup, verification, and debugging.

---

### LESSON-004: JSON Stub Transactions Cannot Be Signed or Broadcast
- **Date:** 2026-03-15
- **Category:** Bug
- **Severity:** Medium
- **Found by:** R6 during initial audit (SEC-011, pre-R3c fix)
- **Related finding:** SEC-011 (Sui), SEC-010 (Solana — fixed)

**What happened:**
Both Solana and Sui `build_transaction` implementations returned a **JSON blob** as `tx_data`
and passed the raw JSON bytes as `sign_payload`. The MPC protocol would then sign these JSON
bytes — producing a valid Ed25519 signature over meaningless data. The resulting "signed
transaction" could never be accepted by any node.

**Root cause:**
Chain-specific transaction binary formats (Solana wire format, Sui BCS) are complex to implement
correctly. Stubs were created to "wire up" the pipeline end-to-end without implementing the format,
with the intention to fix later — but "later" wasn't scheduled.

**Fix / Resolution:**
- Solana (R3c, Sprint 0 + T-07): Replaced with real binary Solana legacy message format.
  `sign_payload` is now the actual message bytes per the Solana spec.
- Sui: Partially fixed (Blake2b hash of intent prefix + tx_data). Full BCS encoding is
  Sprint 2 (T-S2 via R3d).

**Takeaway:**
> Never ship a stub that produces a valid-looking output for an incorrect format.
> A stub should either `todo!()` (panics visibly) or return a clearly-labeled test payload.
> "Works in tests" with fake data ≠ "works in production" with real chain nodes.

---

### LESSON-005: Sui Zero-Byte Public Key Bug
- **Date:** 2026-03-15
- **Category:** Bug
- **Severity:** High → Fixed (pre-sprint)
- **Found by:** Research phase, fixed by R3d before Sprint 1

**What happened:**
`finalize_sui_transaction` built the Sui signature as:
```rust
let mut sig = vec![0x00];   // Ed25519 flag
sig.extend_from_slice(&signature_bytes);
sig.extend_from_slice(&[0u8; 32]);  // ← always 32 zero bytes!
```
The Sui signature format requires `[flag | signature(64) | pubkey(32)]`. The pubkey was hardcoded
as 32 zero bytes — meaning every signature would be rejected by any Sui validator because the
pubkey doesn't match the signing address.

**Root cause:**
The public key was available in `GroupPublicKey` but wasn't threaded through to the finalization
function. Placeholder zeros were used and not caught in code review because there were no tests
for the finalized signature format.

**Fix / Resolution:**
R3d (pre-sprint): Embedded the pubkey as hex in `tx_data` JSON during `build_transaction`,
then extracted and embedded it correctly in `finalize_transaction`. 4 new tests verify the
exact 97-byte signature format.

**Takeaway:**
> For every chain-specific signature format, write a test that checks the **exact byte layout**,
> not just that finalization "returns Ok". A test like:
> ```rust
> assert_eq!(raw[0], 0x00);         // flag byte
> assert_eq!(&raw[1..65], &sig);    // signature
> assert_eq!(&raw[65..97], &pubkey); // pubkey
> ```
> catches format bugs immediately.

---

## Architecture Lessons

### LESSON-006: Trait Boundaries Prevent Parallel Work Conflicts
- **Date:** 2026-03-15
- **Category:** Architecture
- **Severity:** Insight
- **Found by:** Orchestrator during parallel agent planning

**What happened:**
6 agents (R1, R2, R3a, R3b, R3c, R3d) were spawned simultaneously to work on different parts
of the codebase. Despite working in parallel, they produced **zero merge conflicts on source files**.
The only conflicts were in `chain_integration.rs` (a shared test file), which were trivially resolved
by keeping all additions.

**Root cause (positive):**
The codebase is structured around 4 public traits (`MpcProtocol`, `Transport`, `KeyStore`,
`ChainProvider`). Each agent owns the implementation files for its trait — and no two agents
own the same files. The trait layer acts as a hard boundary between concerns.

**Fix / Resolution:**
N/A — this was working as intended. The lesson is to preserve and reinforce this pattern.

**Takeaway:**
> **Trait boundaries = parallel work boundaries.**
> When designing new features, ask: "which trait does this cross?" and assign it to one owner.
> If a feature requires two agents to touch each other's files, it's a design problem — not a
> coordination problem. Fix the design first.

---

### LESSON-007: Shared Test File = Guaranteed Merge Conflict
- **Date:** 2026-03-15
- **Category:** Workflow
- **Severity:** Medium
- **Found by:** Orchestrator during Sprint 0 and Sprint 1 parallel merges

**What happened:**
`crates/mpc-wallet-chains/tests/chain_integration.rs` is the only integration test file for all
4 chain agents (R3a, R3b, R3c, R3d). Every parallel sprint that touched ≥2 chain agents produced
a merge conflict in this file because all agents appended tests to the same file.

**Root cause:**
One test file for all chains. When 4 agents append simultaneously, Git cannot auto-merge
because the additions are at the same "end of file" location.

**Fix / Resolution:**
Conflicts were resolved manually (trivially — keep all additions). But the pattern will repeat
every sprint. Long-term fix (tracked for R5): split into per-chain test files:
```
tests/
  chain_evm_integration.rs
  chain_bitcoin_integration.rs
  chain_solana_integration.rs
  chain_sui_integration.rs
  chain_common.rs   ← shared helpers
```

**Takeaway:**
> For parallel agent work, **one agent = one file** applies to test files too.
> Shared test files cause deterministic conflicts every sprint. Split them early.
> Each chain agent should own its own test file, not a shared one.

---

### LESSON-008: `cargo test` Must Run in the Correct Worktree
- **Date:** 2026-03-15
- **Category:** Tooling
- **Severity:** Low
- **Found by:** Orchestrator during worktree setup

**What happened:**
When agents ran `cargo test` in the main repo (`/project/mpc-wallet`) while their changes were
only on their branch (in their worktree), tests passed against the wrong code. The worktree's
changes weren't reflected in the main repo's working tree.

**Root cause:**
Git worktrees are separate checkouts of the same repo. Running commands in the main repo path
tests the `main` branch code, not the agent's branch. This can produce false positives
(tests pass but against old code) or false negatives (compilation fails because main is ahead).

**Fix / Resolution:**
Each agent instruction template now explicitly specifies:
```bash
# ✓ Correct — run in YOUR worktree
cd /Users/thecoding/git/worktrees/mpc-r1
cargo test -p mpc-wallet-core

# ✗ Wrong — this tests main, not your branch
cd /Users/thecoding/git/project/mpc-wallet
cargo test -p mpc-wallet-core
```

**Takeaway:**
> Always specify `workdir` in agent instructions as the agent's own worktree path.
> Never run validation commands in the main repo when the changes are on a branch.

---

### LESSON-009: R6 as Reporter vs. R6 as Gate
- **Date:** 2026-03-15
- **Category:** Workflow
- **Severity:** Insight
- **Found by:** Orchestrator + human review

**What happened:**
In the first iteration, R6 was spawned alongside implementation agents (parallel) and produced
a security report **after** branches were already merged to main. The findings were accurate but
had no enforcement power — work was already merged. R6 was a reporter, not a gatekeeper.

**Root cause:**
R6 was designed as an auditor, not a gate. The workflow was:
`spawn agents → merge → spawn R6 → report findings`
instead of:
`spawn agents → R6 audit → verdict → merge (if APPROVED)`

**Fix / Resolution:**
Redesigned the workflow. R6 now runs **before any merge**, issues a `VERDICT: APPROVED | DEFECT`
per branch, and CRITICAL/HIGH findings block merge. The orchestrator only merges
branches with explicit R6 `APPROVED` verdict.

**Takeaway:**
> A security auditor has no value if they audit after the fact.
> Gate = auditor runs BEFORE merge, has blocking power.
> Reporter = auditor runs after, has no blocking power.
> Design security as a gate from day one, not as an afterthought.

---

### LESSON-010: Agent Prompts Need Explicit Scope Limits
- **Date:** 2026-03-15
- **Category:** Workflow
- **Severity:** Medium
- **Found by:** R5 QA Agent during verification

**What happened:**
In an early test, an agent (R3d) was given a task without explicit file scope. The agent's
report mentioned modifying `transport/mod.rs` (R2's file) to add a pub mod declaration
because the task logically "needed" it. The modification was minor but violated ownership.

**Root cause:**
Agent prompts said "implement X feature" without explicitly listing which files were in scope.
The agent inferred what files needed changing based on logic, not on ownership rules.

**Fix / Resolution:**
Every agent instruction now contains:
```
## Files you OWN (can modify — nothing else)
[explicit list]

## Files you READ ONLY (never modify)
[explicit list]
```
The ownership list is derived from `docs/AGENTS.md`, not inferred.

**Takeaway:**
> "Implement feature X" is insufficient as an agent instruction.
> Always include: (1) exact files allowed to modify, (2) exact files read-only, (3) what
> to do if a needed change is outside scope (escalate to R7, don't do it yourself).

---

### LESSON-011: `gg20-simulation` Feature Must Be Off by Default
- **Date:** 2026-03-15
- **Category:** Security
- **Severity:** Critical
- **Found by:** R6 during T-01 audit

**What happened:**
When gating the GG20 simulation, the initial implementation considered putting `gg20-simulation`
in the `default` features list so that existing tests would continue to pass without changes.
R6 caught this during the Security Checklist review: a CRITICAL security vulnerability
opt-in-to-disable is worse than one that is opt-in-to-enable.

**Root cause:**
Convenience vs. security tradeoff. Keeping `gg20-simulation` enabled by default would have
meant CI would always compile and test the insecure path, making it easy for a developer to
ship with the simulation enabled without realizing it.

**Fix / Resolution:**
`default = []` — empty. The simulation is **off by default**. Integration tests that need it
must explicitly pass `--features gg20-simulation`. This makes the insecure path visible
and intentional, never accidental.

**Takeaway:**
> Security-critical feature flags must be **opt-in**, never opt-out.
> `default = []` with explicit `--features dangerous-feature` for unsafe paths.
> If tests break because the feature is off by default, fix the tests — don't enable the feature.

---

### LESSON-012: Sui Address Validation Must Be Fail-Fast
- **Date:** 2026-03-15
- **Category:** Security
- **Severity:** Medium
- **Found by:** R6 during T-06 audit (SEC-023)

**What happened:**
R6 noted during the T-06 audit that `validate_sui_address` correctly validated prefix and length,
but the test suite was missing a case for `"0x" + non-hex characters` (e.g., `"0x" + "gg" * 32`).
The implementation was correct (`hex::decode` would return Err), but the test gap meant the
behavior wasn't proven. Logged as SEC-023 (LOW).

**Root cause:**
Test cases were written from the happy path and two obvious error paths (missing prefix, wrong
length) but missed the third rejection case (invalid hex characters in a correctly-prefixed,
correctly-sized string).

**Fix / Resolution:**
Tracked as SEC-023 (LOW, non-blocking). R3d should add:
```rust
#[test]
fn test_sui_validate_address_invalid_hex_chars() {
    // 0x + 64 chars but not valid hex
    let bad = "0xgggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
    assert!(validate_sui_address(bad).is_err());
}
```

**Takeaway:**
> For any input validation function, the test matrix should cover:
> 1. ✓ Valid input (happy path)
> 2. ✗ Wrong prefix/format
> 3. ✗ Wrong length
> 4. ✗ Correct format + correct length + invalid character set
> All 4 cases must have tests. Missing any one leaves a gap R6 will flag.

---

## Workflow Lessons

### LESSON-013: PM Must Read Security Findings Before Planning
- **Date:** 2026-03-15
- **Category:** Workflow
- **Severity:** Insight
- **Found by:** R7 PM Agent (self-identified)

**What happened:**
In the first sprint planning iteration, R7 proposed tasks (T-01 through T-07) without fully
cross-referencing all 22 open security findings. Several proposed tasks would have introduced
new code in areas with open HIGH findings, potentially making those areas harder to fix later.
After the workflow was tightened, R7's instruction template was updated to read
`SECURITY_FINDINGS.md` **first**, before reading `EPICS.md` or source code.

**Root cause:**
Planning was driven by feature backlog (Epics) rather than security debt. Security findings
were treated as a separate track instead of a constraint on planning.

**Fix / Resolution:**
R7 instruction template now mandates reading order:
```
1. AGENTS.md
2. SECURITY_FINDINGS.md   ← before anything else
3. SPRINT.md
4. EPICS.md
5. Source files
```

**Takeaway:**
> Security findings are planning constraints, not a separate backlog.
> Before deciding what to build next, know what's broken.
> The PM must read the security state before reading the feature backlog — every sprint.

---

### LESSON-014: CLAUDE.md = Shared Memory, Must Stay Current
- **Date:** 2026-03-15
- **Category:** Workflow
- **Severity:** Insight
- **Found by:** Orchestrator after Sprint 1 complete

**What happened:**
Before `CLAUDE.md` existed, every agent prompt needed to include 200-400 lines of context:
project description, team structure, workflow rules, sprint state, security findings summary.
This context was repeated in every spawn call, was prone to getting out of date between
spawns, and made prompts large and error-prone.

After creating `CLAUDE.md`, a cold-start agent with zero prior context read only one file
and correctly answered all 7 context questions, including owned files, workflow, sprint status,
and security findings.

**Root cause:**
No persistent shared memory mechanism existed. Each session started from zero.

**Fix / Resolution:**
`CLAUDE.md` at repo root, auto-loaded by Claude Code every session. Updated at the end of
every sprint (sprint status, test count, open findings). Propagated to all worktrees via
`git rebase main` after each update.

**Takeaway:**
> `CLAUDE.md` is living documentation. It must be updated every sprint — stale memory is
> worse than no memory because it creates false confidence.
> Rule: **before closing a sprint, update CLAUDE.md with new sprint status and any resolved/new findings.**

---

### LESSON-015: Parallel Agents Need Independent File Ownership
- **Date:** 2026-03-15
- **Category:** Architecture
- **Severity:** Insight
- **Found by:** Orchestrator designing Sprint 0 parallel execution

**What happened:**
Planning the first parallel sprint (6 agents simultaneously), we discovered that `Chain::Polygon`
and `Chain::Bsc` needed to be added to `provider.rs` — but `provider.rs` is owned by R0
(Architect), not by R3a (EVM). If R3a had been allowed to modify `provider.rs`, and R0 was
also modifying it, a conflict would have been guaranteed.

The fix was to have the orchestrator (acting as R0) add the enum variants to `provider.rs`
**before** spawning the parallel agents. This unblocked R3a without creating a conflict.

**Root cause:**
Shared interface files (`provider.rs`, `mod.rs` trait files) are touched by the orchestrator
before parallel work, not by individual agents. This is the correct pattern.

**Fix / Resolution:**
Rule established: **before spawning parallel agents, the orchestrator does all Cargo.toml and
shared interface prep**. Agents only touch their own impl files.

**Takeaway:**
> Parallel agent work is safe only when file ownership is truly non-overlapping.
> Any file that multiple agents "need" must be prepared by the orchestrator before spawning.
> The orchestrator is R0's proxy for interface-level changes between sprints.

---

### LESSON-016: Additive Shares — The Key to Distributed Signing Without Reconstruction
- **Date:** 2026-03-16
- **Category:** Architecture
- **Severity:** Insight
- **Found by:** R1 during T-S2-01 implementation

**What happened:**
The core challenge of SEC-001 was: how do you compute an ECDSA signature across N parties where
no single party holds the full private key, but the signature must mathematically verify?

The naive fix would be to just not log the reconstructed key — but that leaves the full key
sitting in memory on one machine, still vulnerable.

**Root cause of the original bug:**
The GG20 simulation used Lagrange interpolation on the **key shares** to reconstruct `x`:
`x = sum(λ_i * x_i)` — this is the textbook way to recover a Shamir secret. The mistake was
applying this during signing instead of during a setup phase (or not at all).

**Fix / Resolution:**
Use additive shares. The insight is:
- Instead of computing `x` and then `s = k^{-1}(hash + x*r)`, compute it as:
- `s = hash*k_inv + sum(x_i_add * r * k_inv)` where `x_i_add = λ_i * x_i`
- Each party computes `s_i = x_i_add * r * k_inv` (only their part)
- The coordinator sums: `s = hash*k_inv + sum(s_i)`
- `x = sum(x_i_add)` by construction, but this sum is **never computed** — only its contribution to `s` is assembled, distributed across parties

**Takeaway:**
> The key to distributed signing is: apply the signing formula AFTER distributing the work,
> not before. The Lagrange weighting (λ_i) should be applied to the **partial signatures**,
> not to the **key shares**. This way the full key never needs to be assembled.
> Formula: `s = hash/k + sum(λ_i * x_i * r/k)` — distribute the last term, not the first.

---

### LESSON-017: Wave-based Dependency Management for Parallel Agents
- **Date:** 2026-03-16
- **Category:** Workflow
- **Severity:** Insight
- **Found by:** Orchestrator during Sprint 2 planning

**What happened:**
Sprint 2 had a dependency: T-S2-00 (R0 adds `bcs` and `rpassword` to `Cargo.toml`) must
complete before T-S2-01 (R1 uses them), T-S2-03 (R4 uses `rpassword`), and T-S2-04 (R3d
uses `bcs`). Spawning all agents at once would have caused them to fail on missing dependencies.

**Root cause:**
Cargo workspace dependencies are defined in a shared file (`Cargo.toml`) owned by R0.
Any agent that needs a new crate cannot add it themselves (boundary violation) and cannot
proceed without it (compile error).

**Fix / Resolution:**
Structured sprint into waves:
- **Wave 1:** R0 (dep prep) + R5 (CI, no new deps) — parallel, fast
- Orchestrator merges Wave 1 to main before Wave 2 starts
- **Wave 2:** R1 + R4 + R3d — parallel, all rebased onto main with deps available

**Takeaway:**
> When planning parallel sprints, identify "prep tasks" (Cargo.toml changes, interface
> additions, shared file modifications) and run them as Wave 1. Only start Wave 2 after
> Wave 1 is merged. Wave 2 tasks can then run fully parallel with no dep issues.
> Rule: **Wave 1 = orchestrator/R0 prep. Wave 2 = implementation agents.**
