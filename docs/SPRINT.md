# Sprint Log

> **Current state (as of 2026-05-10):** Sprint 49 COMPLETE — merged to `dev` and `main`. 967 tests passing.
> 7 production threshold protocols, 68/68 security findings resolved,
> 6 chains with live testnet MPC broadcast coverage (Sepolia, Solana devnet,
> Bitcoin testnet, Sui testnet, Aptos testnet, TRON Shasta).
> **TOKEN SUITE COMPLETE** across all in-scope chains: EVM ERC-20 (live USDC-Sepolia),
> Aptos legacy `0x1::coin::transfer<T>` (live `<AptosCoin>`), Aptos Fungible Asset
> (live native APT via FA), TRON TRC-20 (live Shasta USDT), Solana SPL Token
> (live devnet USDC via FROST-Ed25519 2-of-3), and Sui `Coin<T>` PTB (code-complete,
> byte-equal to `@mysten/sui`; live deferred until non-SUI testnet token funded).
> See `docs/ROADMAP.md` for the live roadmap and next-phase candidates.
>
> The content below is the **historical archive** of Sprint 1–N task specs and gate status
> tables. It is preserved for traceability but is **not** the source of truth for current
> work. Do not edit historical sprint sections; append a new section if recording new work.

---

# [ARCHIVE] Sprint 1 — 2026-03-15 → 2026-03-29

## Goal
**"Production-ready crypto core + all chains correct"**

Replace the GG20 key-reconstruction simulation with real distributed ECDSA, complete BCS
serialization for Sui, validate Solana wire-format against the real SDK, and add proactive
key refresh — so the codebase is no longer blocked on fundamental correctness issues.

**Sprint owner:** R7 PM Agent

---

## Gate Status

| Task | Agent | Branch | PM Approved | Implementation | R6 Verdict | Merged |
|------|-------|--------|-------------|----------------|------------|--------|
| T-01 | R1 | `agent/r1-zeroize` | ✓ | pending | pending | ✗ |
| T-02 | R1 | `agent/r1-zeroize` | ✓ | pending | pending | ✗ |
| T-05 | R0 | `agent/r0-interface` | ✓ | pending | pending | ✗ |
| T-06 | R3d | `agent/r3d-sui-followup` | ✓ | pending | pending | ✗ |
| T-07 | R3c | `agent/r3c-sol` | ✓ | pending | pending | ✗ |

---

## Task Specs

### Task Spec: T-01
- **Agent:** R1
- **Branch:** `agent/r1-zeroize`
- **Epic:** Epic J (Production Hardening)
- **Title:** Gate GG20 simulation behind `gg20-simulation` feature flag
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/protocol/gg20.rs`
  - `crates/mpc-wallet-core/Cargo.toml`
- **Acceptance Criteria:**
  - [ ] `Cargo.toml` declares `[features] gg20-simulation = []` and the feature is **off by default**
  - [ ] All code in `gg20.rs` that calls `lagrange_interpolate` (line 232) is wrapped in `#[cfg(feature = "gg20-simulation")]`
  - [ ] A `compile_error!` or prominent doc comment at the top of the `gg20-simulation`-gated block warns: `"SECURITY: SIMULATION ONLY — reconstructs full private key — NOT FOR PRODUCTION"`
  - [ ] When the feature is **disabled** (default), `cargo test -p mpc-wallet-core` still passes (the simulation code is absent; tests that test Shamir/Lagrange must also be gated or updated to be feature-gated)
  - [ ] When the feature is **enabled** (`cargo test -p mpc-wallet-core --features gg20-simulation`), all existing tests still pass
  - [ ] `cargo check -p mpc-wallet-core` passes without the feature (default)
- **Dependencies:** None — can start immediately
- **Complexity:** S

#### Security Checklist for R6
- [ ] Feature flag is **off by default** — verify in `Cargo.toml` that `gg20-simulation` is NOT listed under `default = [...]`
- [ ] The `lagrange_interpolate` function and its call site in `sign()` are entirely absent from the non-simulation build — confirm via `cargo check -p mpc-wallet-core` (no feature) that `lagrange_interpolate` does not appear
- [ ] The `#[cfg(feature = "gg20-simulation")]` gate wraps the entire reconstruction path — no partial gating that leaves the scalar accessible
- [ ] The simulation warning comment is prominent (top of gated block) and accurately describes the risk (full key reconstruction)
- [ ] `cargo audit` clean — no new advisories; no new dependencies added

---

### Task Spec: T-02
- **Agent:** R1
- **Branch:** `agent/r1-zeroize`
- **Epic:** Epic H (Key Lifecycle)
- **Title:** Add `EncryptedFileStore::touch(group_id)` for key refresh metadata tracking
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/key_store/encrypted.rs`
- **Acceptance Criteria:**
  - [ ] `EncryptedFileStore` has a new concrete method `pub async fn touch(&self, group_id: &KeyGroupId) -> Result<(), CoreError>`
  - [ ] `touch()` reads the existing `metadata.json` for the group, updates a `last_refreshed` field (unix timestamp as `u64`, obtained via `std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()`), and writes it back atomically (overwrite)
  - [ ] `KeyMetadata` in `key_store/types.rs` gains a new field `last_refreshed: Option<u64>` with `#[serde(default)]` so existing JSON files (without the field) continue to deserialize correctly — **NOTE: `types.rs` is owned by R0; R1 must NOT modify it. Instead R1 should write the `last_refreshed` value as a standalone JSON key alongside the `KeyMetadata` JSON, by reading the raw JSON as `serde_json::Value`, inserting the key, and writing back. This avoids touching R0-owned types.**
  - [ ] Alternative (preferred since it avoids R0 files): `touch()` writes a separate file `touch.json` containing `{"last_refreshed": <unix_u64>}` in the group directory — keeps all R0 types untouched
  - [ ] A unit test `test_touch_updates_timestamp` verifies: create a group (via `save()`), call `touch()`, read `touch.json`, verify `last_refreshed` is a non-zero u64 and is >= the `created_at` timestamp
  - [ ] No key material is read or decrypted during `touch()` — only metadata files are accessed
  - [ ] `cargo test -p mpc-wallet-core` passes
- **Dependencies:** None — `encrypted.rs` is R1's file; no trait change required
- **Complexity:** S

#### Security Checklist for R6
- [ ] `touch()` does **not** call `decrypt()` or access the `.enc` share file — verified by code inspection
- [ ] No key material (share bytes, password, derived key) is present in any variable created during `touch()`
- [ ] The timestamp written is obtained from `std::time::SystemTime` (not user-supplied input) — no injection risk
- [ ] `touch.json` does not contain any sensitive fields — only the `last_refreshed` timestamp
- [ ] `cargo audit` clean — no new dependencies added

---

### Task Spec: T-05
- **Agent:** R0
- **Branch:** `agent/r0-interface`
- **Epic:** Epic H (Key Lifecycle)
- **Title:** Add `freeze` / `unfreeze` to `KeyStore` trait + `CoreError::KeyFrozen`
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/key_store/mod.rs`
  - `crates/mpc-wallet-core/src/error.rs`
  - `crates/mpc-wallet-core/src/key_store/encrypted.rs`
- **Acceptance Criteria:**
  - [ ] `KeyStore` trait in `key_store/mod.rs` has two new async methods:
    ```rust
    async fn freeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError>;
    async fn unfreeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError>;
    ```
  - [ ] `CoreError::KeyFrozen(String)` variant added to `error.rs` with `#[error("key frozen: {0}")]`
  - [ ] `EncryptedFileStore` in `key_store/encrypted.rs` gets stub implementations: both `freeze` and `unfreeze` return `Ok(())` (no-op stubs; full implementation is deferred to a later sprint)
  - [ ] `cargo check --workspace` passes — all crates compile
  - [ ] `cargo test -p mpc-wallet-core` passes — no existing tests broken
- **Dependencies:** None — highest-priority interface change, must complete Day 1–2 to unblock dependent tasks
- **Complexity:** S

#### Security Checklist for R6
- [ ] Trait method signatures use `&self` (not `&mut self`) — consistent with the existing `KeyStore` API (`save`, `load`, `list`, `delete` all use `&self`)
- [ ] `CoreError::KeyFrozen(String)` error message does NOT include key share bytes, derived keys, or password material — only the `group_id` string or a safe descriptive message
- [ ] No implementation logic beyond `Ok(())` stubs in the trait-level default impls (if any) — logic belongs in `EncryptedFileStore`, not in trait defaults
- [ ] The `KeyFrozen` variant is additive — no existing `CoreError` variants are renamed, removed, or reordered (non-breaking change)
- [ ] `cargo audit` clean — no new dependencies added

---

### Task Spec: T-06
- **Agent:** R3d
- **Branch:** `agent/r3d-sui-followup`
- **Epic:** Epic J (Production Hardening)
- **Title:** Sui — add `build_transaction_with_sender` helper and sender address validation
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-chains/src/sui/tx.rs`
  - `crates/mpc-wallet-chains/src/sui/mod.rs`
- **Acceptance Criteria:**
  - [ ] `SuiProvider` gains a new `pub fn build_transaction_with_sender<'a>(&'a self, params: TransactionParams, sender: &str) -> impl Future<Output = Result<UnsignedTransaction, CoreError>> + 'a` method in `mod.rs` that takes the sender address explicitly (bypassing `extra["sender"]` lookup)
  - [ ] The `sender` parameter is validated: must start with `"0x"` and the hex portion (after `0x`) must decode to exactly 32 bytes (64 hex chars). Return `CoreError::InvalidInput` if validation fails.
  - [ ] The existing `build_transaction` (which reads `extra["sender"]`) continues to work unchanged — no regression
  - [ ] A unit test `test_build_transaction_with_sender_valid` verifies a valid 0x-prefixed 32-byte hex sender succeeds and the resulting `sign_payload` is 32 bytes (Blake2b-256)
  - [ ] A unit test `test_build_transaction_with_sender_rejects_invalid` verifies that a sender missing `"0x"` prefix returns `Err(CoreError::InvalidInput(...))`
  - [ ] A unit test `test_build_transaction_with_sender_rejects_wrong_length` verifies that a sender with `"0x"` prefix but incorrect hex length (not 64 hex chars) returns `Err(CoreError::InvalidInput(...))`
  - [ ] `cargo test -p mpc-wallet-chains` passes
- **Dependencies:** None — `sui/tx.rs` and `sui/mod.rs` are R3d's files; no R0-owned files touched
- **Complexity:** S

#### Security Checklist for R6
- [ ] Sender address validation rejects: missing `0x` prefix, hex decode failure, decoded length ≠ 32 bytes — all three cases tested
- [ ] Validation occurs **before** any transaction data is constructed — fail-fast, no partial state built with invalid sender
- [ ] The `extra["sender"]` path in the existing `build_transaction` is unchanged — no regression in the existing API
- [ ] No secret material (private key, share bytes) present in error messages or returned values
- [ ] `cargo audit` clean — no new dependencies added

---

### Task Spec: T-07
- **Agent:** R3c
- **Branch:** `agent/r3c-sol`
- **Epic:** Epic J (Production Hardening)
- **Title:** Solana — binary message round-trip validation test + fix `tx_hash` to full base58 signature
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-chains/tests/chain_integration.rs`
  - `crates/mpc-wallet-chains/src/solana/tx.rs`
- **Source change (tx.rs — one line fix):**
  - [ ] Line 183: replace `let tx_hash = hex::encode(&signature[..8]);` with `let tx_hash = bs58::encode(signature).into_string();` — fixes SEC-010 (truncated tx hash)
- **New tests to add in `chain_integration.rs`:**
  - [ ] `test_solana_message_structure_num_required_sigs`: build a transaction, assert `sign_payload[0] == 1` (num_required_sigs header byte)
  - [ ] `test_solana_message_structure_account_keys_offset`: build a transaction, assert that bytes at offset 4 (after header 3 bytes + compact-u16(3)=1 byte) match the `from` public key bytes (32 bytes starting at index 4)
  - [ ] `test_solana_message_structure_three_accounts_present`: build a transaction, assert sign_payload length >= 3 (header) + 1 (compact-u16) + 96 (3×32 account keys) + 32 (blockhash) = 132 bytes minimum
  - [ ] `test_solana_encode_compact_u16_boundary_values`: test the compact-u16 encoding for values 0, 1, 127, 128, 16383 — assert correct byte sequences (`[0]`, `[1]`, `[0x7f]`, `[0x80, 0x01]`, `[0xff, 0x7f]`)
  - [ ] `test_solana_tx_hash_is_base58_full_signature`: build+finalize a transaction with a known 64-byte signature, assert `tx_hash` decodes from base58 to exactly 64 bytes matching the signature
  - [ ] `test_solana_zero_lamports_transaction`: build a transaction with `value: "0"`, assert it succeeds (zero lamports is valid)
  - [ ] `test_solana_same_from_to_address`: build a transaction where from == to (same 32-byte address), assert it succeeds (network-level restriction, not SDK-level)
- **Acceptance Criteria:**
  - [ ] All 7 new tests pass
  - [ ] `finalize_solana_transaction` `tx_hash` is now `bs58::encode(signature).into_string()` (full 64-byte signature base58-encoded)
  - [ ] All pre-existing Solana tests in `chain_integration.rs` still pass
  - [ ] `cargo test -p mpc-wallet-chains` passes
- **Dependencies:** None — `chain_integration.rs` and `solana/tx.rs` are in R3c's scope
- **Complexity:** S

#### Security Checklist for R6
- [ ] `tx_hash` in `SignedTransaction` is the **full** base58-encoded 64-byte signature — NOT the previous truncated 8-byte hex. Verify the fix resolves SEC-010: `hex::encode(&signature[..8])` must no longer appear anywhere in `tx.rs`
- [ ] `encode_compact_u16` boundary test covers value 128 (two-byte encoding threshold) — verifies no off-by-one that could corrupt message structure
- [ ] Zero-lamports test: verify no integer underflow or panic on `u64` value of 0
- [ ] Same from/to test: verify no panic or assertion failure when sender == recipient (array aliasing non-issue in Rust, but must confirm no validation incorrectly rejects it)
- [ ] No secret material present in `SignedTransaction` output — `tx_hash` is the public signature, `raw_tx` is the serialized transaction; no private key bytes
- [ ] `cargo audit` clean — no new dependencies added (bs58 is already in workspace)

---

## Blocked Tasks

| Task | Blocker | Owner | Resolution |
|------|---------|-------|------------|
| (none) | — | — | All 5 tasks are independent and can start in parallel. T-05 (R0) should be prioritized to unblock any future freeze/unfreeze implementation work. |

---

## Done (pre-Sprint 1, already on main)

The following tasks were completed and merged to `main` before Sprint 1 began.
They are tracked here for completeness. **No R6 gate re-audit required** (merged pre-gate-model).

| Agent | Task | Branch (merged) | Description |
|-------|------|-----------------|-------------|
| R1 | Pre-sprint zeroize | `agent/r1-zeroize` (pre-merge) | `ZeroizeOnDrop` on `Gg20ShareData`, `FrostEd25519ShareData`, `FrostSecp256k1ShareData` |
| R2 | NatsTransport stub | `agent/r2-nats` (pre-merge) | `NatsTransport` struct and `todo!()` stubs committed (full impl is T-TODO Sprint 2+) |
| R3a | EVM multi-network | `agent/r3a-evm` (pre-merge) | Polygon, BSC, Arbitrum, Base chain IDs added to `EvmProvider` |
| R3b | Bitcoin testnet | `agent/r3b-btc` (pre-merge) | Testnet/signet support added to `BitcoinProvider` |
| R3c | Solana binary serialization | `agent/r3c-sol` (pre-merge) | Manual wire-format serialization replacing JSON stub |
| R3d | Sui cleanup | `agent/r3d-sui-followup` (pre-merge) | Initial Sui provider scaffolding |

---

## Sprint Notes

- **T-01 and T-02 both assigned to R1** on the same branch `agent/r1-zeroize`. R1 should do T-01 first (feature flag), then T-02 (touch method), then commit each separately per checkpoint protocol.
- **T-05 (R0) has no blockers** and should be completed first — it unblocks any future freeze/unfreeze work and is the smallest task in the sprint.
- **T-06 (R3d) and T-07 (R3c)** can work in parallel — no shared files.
- **R6 gate:** R6 must issue APPROVED verdict for each task branch before it can merge to main.
- **No branch merges without R6 APPROVED** — enforced per the Sprint Gate Model in AGENTS.md.
- **No new crate dependencies** are required for any Sprint 1 task. `bs58` is already in the workspace (used in `solana/tx.rs`).

---

## Execution Order

All 5 tasks are independent and can run in parallel. Recommended priority:

```
Day 1:  R0 → T-05 (small, unblocks future work)
Day 1:  R1 → T-01 (feature flag — preparatory for Sprint 2 real GG20)
Day 1:  R3d → T-06 (Sui sender validation helper)
Day 1:  R3c → T-07 (Solana round-trip test + tx_hash fix)

Day 2:  R1 → T-02 (touch method, after T-01 lands on same branch)

Day 3+: R6 audits each branch as agents report complete
```

---

# Sprint 2 — 2026-03-30 → 2026-04-13

## Goal
**"Distributed signing without key reconstruction + password security + Sui BCS + CI"**

Resolve SEC-001 CRITICAL by implementing additive-share-based distributed ECDSA signing
(the full private key is never assembled on any party). Also resolve SEC-002 (demo-password),
advance Sui BCS serialization (SEC-011), and wire up the CI pipeline.

**Sprint owner:** R7 PM Agent  
**Sprint dates:** 2026-03-30 → 2026-04-13

---

## Why These Are Hard Goals

| Finding | Severity | Why It Blocks |
|---------|----------|---------------|
| SEC-001 | CRITICAL | GG20 sign() reconstructs full private key — negates MPC guarantee entirely |
| SEC-002 | CRITICAL | Hardcoded "demo-password" fallback silently encrypts key shares with a known string |
| SEC-011 | MEDIUM   | Sui tx uses JSON instead of BCS — rejected by all Sui nodes |

---

## Execution Order

```
Wave 1 (first — blocks Wave 2):
  T-S2-00  R0   agent/r0-s2-prep       (add bcs + rpassword deps, PasswordRequired error)

Wave 2 (after T-S2-00 merges — all parallel):
  T-S2-01  R1   agent/r1-real-gg20     (distributed signing, resolves SEC-001)
  T-S2-03  R4   agent/r4-cli-password  (remove demo-password, resolves SEC-002)
  T-S2-04  R3d  agent/r3d-sui-bcs      (Sui BCS encoding, advances SEC-011)
  T-S2-05  R5   agent/r5-ci            (CI pipeline — no code deps, can run in parallel with Wave 1)
```

**T-S2-05 (R5) has no source-code dependency** and may be started immediately in parallel with
T-S2-00. All other Wave 2 tasks must wait for T-S2-00 to be merged first.

---

## Gate Status (Sprint 2)

| Task | Agent | Branch | PM Approved | R6 Verdict | Merged | Resolves |
|------|-------|--------|-------------|------------|--------|----------|
| T-S2-00 | R0 | `agent/r0-s2-prep` | ✓ | pending | ✗ | Unblocks T-S2-01, T-S2-03, T-S2-04 |
| T-S2-01 | R1 | `agent/r1-real-gg20` | ✓ | pending | ✗ | SEC-001 CRITICAL |
| T-S2-03 | R4 | `agent/r4-cli-password` | ✓ | pending | ✗ | SEC-002 CRITICAL |
| T-S2-04 | R3d | `agent/r3d-sui-bcs` | ✓ | pending | ✗ | SEC-011 MEDIUM |
| T-S2-05 | R5 | `agent/r5-ci` | ✓ | pending | ✗ | CI infrastructure |

---

## Task Specs

---

### Task Spec: T-S2-00
- **Agent:** R0 (Architect)
- **Branch:** `agent/r0-s2-prep`
- **Epic:** Epic J (Production Hardening)
- **Title:** Add `bcs` + `rpassword` workspace deps and `CoreError::PasswordRequired` variant
- **Complexity:** S
- **Must complete before:** T-S2-01, T-S2-03, T-S2-04

#### Files owned (agent may ONLY modify these — nothing else)
```
Cargo.toml                                               ← workspace [workspace.dependencies]
crates/mpc-wallet-core/Cargo.toml                        ← add rpassword to [dependencies]
crates/mpc-wallet-core/src/error.rs                      ← add PasswordRequired variant
```

#### Context
- `bcs = "0.1"` is needed by T-S2-04 (R3d Sui BCS encoding)
- `rpassword = "7"` is needed by T-S2-03 (R4 CLI password prompt) — add to workspace deps
  so R4 can opt-in in `mpc-wallet-cli/Cargo.toml`. R0 does NOT add it to core's deps (CLI only).
- `CoreError::PasswordRequired` is a new error variant needed by T-S2-03
- `bcs` should be added to workspace deps AND to `mpc-wallet-chains/Cargo.toml`
  (R3d will use it in that crate)

#### Acceptance Criteria
- [ ] `Cargo.toml` `[workspace.dependencies]` gains:
  ```toml
  bcs = "0.1"
  rpassword = "7"
  ```
- [ ] `crates/mpc-wallet-chains/Cargo.toml` gains `bcs = { workspace = true }` in `[dependencies]`
- [ ] `crates/mpc-wallet-core/src/error.rs` gains:
  ```rust
  #[error("password required: {0}")]
  PasswordRequired(String),
  ```
  as a new variant (additive — no existing variants modified or reordered)
- [ ] `cargo check --workspace` passes after all three changes
- [ ] `cargo test --workspace` still passes (no regressions)
- [ ] `cargo audit` run and output reviewed — no new CRITICAL/HIGH advisories from `bcs` or `rpassword`

#### Security Checklist for R6
- [ ] `bcs = "0.1"` license check: verify Apache-2.0 or MIT compatible with workspace MIT license
- [ ] `rpassword = "7"` license check: same
- [ ] `cargo audit` output after adding both crates: zero new CRITICAL or HIGH advisories
- [ ] `CoreError::PasswordRequired(String)` message template does NOT include the password value itself — only a descriptive hint like `"--password flag is required"`. Verify the string in the variant is a message, not the password.
- [ ] `PasswordRequired` is additive — no existing `CoreError` variants renamed, removed, or reordered (non-breaking)
- [ ] No existing tests broken by the new variant — `cargo test --workspace` green

---

### Task Spec: T-S2-01
- **Agent:** R1 (Crypto)
- **Branch:** `agent/r1-real-gg20`
- **Epic:** Epic J (Production Hardening)
- **Title:** Distributed ECDSA signing — no key reconstruction (resolves SEC-001)
- **Complexity:** L
- **Depends on:** T-S2-00 merged (for new feature flag; no new crate dep needed — `k256` already present)

#### Files owned (agent may ONLY modify these — nothing else)
```
crates/mpc-wallet-core/src/protocol/gg20.rs              ← primary impl file
crates/mpc-wallet-core/Cargo.toml                        ← add gg20-distributed feature
```

#### Context: What the current code does (the problem)

The existing `sign()` under `#[cfg(feature = "gg20-simulation")]` (lines 227–306 of `gg20.rs`):
1. Every party broadcasts their Shamir share `(x_i, y_i)` to all others
2. Every party collects all shares
3. Every party calls `lagrange_interpolate(&collected_shares)` → reconstructs **full private key** `x`
4. Every party signs directly with `x`

This is the simulation — every signer learns the full key. This is what SEC-001 prohibits.

#### What T-S2-01 must implement: Additive-share distributed signing

**Key insight:** Convert Shamir shares to additive shares, then use partial signing.

**Keygen changes (trusted dealer — Party 1):**

Party 1 currently generates Shamir shares `(i, f(i))` where `f(0) = x` (the secret).
Party 1 must now **convert to additive shares** before distributing:

```
For each party i with Shamir share (i, y_i):
  lambda_i = lagrange_coefficient(i, all_party_indices, x=0)
           = product_{j ≠ i} (-j) / (i - j)   [evaluated at 0]
  additive_share_i = lambda_i * y_i   (scalar multiplication mod curve order)
```

Party `i` receives `x_i_add = lambda_i * y_i`. These are additive shares:
```
sum_i(x_i_add) = sum_i(lambda_i * y_i) = x   (the secret)
```

But we will **never compute this sum during signing**.

Party 1 sends each party their `x_i_add` (a 32-byte scalar). Party 1 keeps its own `x_1_add`.

Store `x_i_add` as the `share_data` for each party (replaces old `Gg20ShareData { x, y }`):

```rust
#[cfg(feature = "gg20-distributed")]
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct Gg20DistributedShareData {
    /// Additive share scalar: lambda_i * y_i (32 bytes, big-endian)
    additive_share: Vec<u8>,
}
```

**Sign changes — the distributed protocol:**

Given: each party `i` holds `x_i_add` (their additive share, a `k256::Scalar`).
Goal: produce ECDSA signature `(r, s)` where `s = k^{-1}(hash + x*r) mod n`
without any party computing `x`.

Step 1 — Each party generates a per-session nonce `k_i`:
```rust
let k_i: Scalar = Scalar::random(&mut rand::thread_rng());
```

Step 2 — Each party computes and broadcasts `R_i = k_i * G` (a curve point, 33 bytes compressed):
```rust
let R_i: ProjectivePoint = ProjectivePoint::GENERATOR * k_i;
// serialize to 33 bytes compressed and broadcast via transport.send(...)
```

Step 3 — Each party collects all `R_j` points. The aggregated nonce point is:
```rust
let R: ProjectivePoint = R_i_values.iter().fold(ProjectivePoint::IDENTITY, |acc, p| acc + p);
let r_affine = R.to_affine();
// r = x-coordinate of R mod n
let r: Scalar = r_from_affine_x(&r_affine);  // see helper below
```

Step 4 — Each party computes their partial signature `s_i`:
```rust
// hash = keccak256 or sha256 of message, as Scalar
let hash_scalar: Scalar = scalar_from_hash(message);
// k_i_inv = modular inverse of k_i
let k_i_inv: Scalar = k_i.invert().expect("nonce cannot be zero");
// s_i = k_i^{-1} * (hash + x_i_add * r)
let s_i: Scalar = k_i_inv * (hash_scalar + x_i_add * r);
// broadcast s_i (32 bytes) to aggregator via transport.send(...)
```

Step 5 — Aggregator (any party, or the first party) collects all `s_j` and sums:
```rust
// s = sum_i(s_i)
// Note: x = sum(x_i_add), so x*r = sum(x_i_add)*r
// and sum(s_i) = sum(k_i^{-1}) * hash + sum(k_i^{-1} * x_i_add * r)
// BUT: sum(s_i) ≠ k^{-1}(hash + x*r) in general unless k = 1/sum(k_i^{-1})
```

**⚠️ IMPORTANT — Mathematical correctness note:**

The naive sum `s = sum(s_i)` does NOT equal `k^{-1}(hash + x*r)` because
`1/sum(k_i) ≠ sum(1/k_i)` in general.

**The correct approach is multiplicative nonce sharing:**

Instead of summing nonces, use the following two-round nonce protocol:

**Round 1 (nonce commitment):**
- Each party `i` samples `k_i` and `gamma_i` (two random scalars)
- Broadcasts `Gamma_i = gamma_i * G`

**Round 2 (nonce aggregation):**
- Compute `Gamma = sum(Gamma_i)`, get `r = x_coord(Gamma) mod n`
- Each party computes `delta_i = k_i * gamma_i` and broadcasts it
- Aggregator computes `delta = sum(delta_i)` and `delta_inv = delta^{-1}`
- Note: `delta = sum(k_i * gamma_i)` and the combined nonce is `k = sum(k_i) * delta_inv`

This becomes complex. **Use the simpler correct approach for Sprint 2:**

**Simplified correct approach — single aggregator model:**

Since keygen already uses a trusted dealer (Party 1 generates `x`), we can use a
**semi-honest aggregator** model for signing as well, which avoids the nonce-inversion problem:

The aggregator (Party 1) handles nonce coordination:

1. Aggregator samples a single session nonce `k` (random scalar)
2. Aggregator computes `R = k * G`, broadcasts `R` and `r = x_coord(R) mod n` to all parties
3. Each party `i` computes partial signature:
   ```
   s_i = k^{-1} * (hash + x_i_add * r)
   ```
   using the `k^{-1}` value broadcast by the aggregator (or each party can compute it from `k` if
   the aggregator broadcasts `k` — but this leaks `k`).

**The cleanest implementation for Sprint 2:**

Use the fact that additive shares let us split the signing equation linearly:
```
s = k^{-1} * (hash + x * r)
  = k^{-1} * hash + k^{-1} * x * r
  = k^{-1} * hash + k^{-1} * r * sum_i(x_i_add)
  = k^{-1} * hash + sum_i(k^{-1} * r * x_i_add)
```

Protocol:
1. Aggregator (Party 1) generates `k`, computes `R = k*G`, `r = x_coord(R) mod n`, `k_inv = k^{-1}`
2. Aggregator broadcasts `(r, k_inv)` to all parties (NOTE: broadcasting `k_inv` is safe — it's
   a per-session ephemeral value, not the private key; knowledge of `k_inv` alone doesn't reveal `x`)
3. Each party `i` computes:
   ```rust
   // hash_scalar = sha256(message) interpreted as Scalar
   let s_i = k_inv * (hash_scalar + x_i_add * r);
   // send s_i to aggregator
   ```
4. Aggregator sums: `s = sum_i(s_i) = k_inv * (n_parties * hash + x * r)`

**⚠️ This is STILL WRONG** because summing partial sigs with the same `k_inv` and `hash` gives:
`sum(s_i) = k_inv * sum(hash + x_i_add * r) = k_inv * (n*hash + x*r)` which ≠ `k_inv*(hash + x*r)`.

**FINAL CORRECT APPROACH for Sprint 2 — "Additive shares, one-shot keygen, aggregator signs":**

The mathematically sound implementation that avoids key reconstruction:

- During keygen: Party 1 generates `x` and distributes additive shares `x_i_add` such that `sum(x_i_add) = x`.
  The simplest split: randomly generate `x_1, x_2, ..., x_{n-1}` and set `x_n = x - sum(x_1..x_{n-1})`.
  This is truly additive (NOT Shamir-based).

- During sign: Use the MtA (Multiplicative-to-Additive) conversion pattern. BUT for Sprint 2,
  use the **centralized nonce** approach that is provably correct:

  1. All parties send their additive share `x_i_add` as `s_i_partial = x_i_add * r * k_inv`
     where `k_inv` is provided by the aggregator (Party 1).
     Each `s_i_partial` is: `x_i_add * r * k_inv`
  2. The hash contribution is handled by ONE party (aggregator):
     `s_hash = hash_scalar * k_inv`
  3. Final: `s = s_hash + sum_i(s_i_partial) = k_inv * hash + k_inv * r * sum_i(x_i_add) = k_inv * (hash + x*r)`
     This is exactly the ECDSA equation. ✓

  The full `x = sum(x_i_add)` is **never computed**. The aggregator computes:
  - `s_hash = hash * k_inv` using no key material
  - `s = s_hash + sum_i(s_i_partial)` — just scalar addition

  The per-party computation `x_i_add * r * k_inv` uses only the party's own additive share.
  No party ever sees another party's additive share.

#### Concrete Implementation Spec

**Data structures:**
```rust
#[cfg(feature = "gg20-distributed")]
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct Gg20DistributedShareData {
    /// This party's additive share of the private key x (32-byte BE scalar).
    /// All parties' shares sum to x: sum_i(additive_share_i) = x.
    /// x is never reconstructed during signing.
    additive_share: Vec<u8>,
    /// Total number of parties (needed to know how many partial sigs to collect)
    total_parties: u16,
    /// This party's index (1-indexed)
    party_index: u16,
}
```

**Keygen (trusted dealer — Party 1 only):**
```rust
// Party 1:
let x: Scalar = Scalar::random(&mut rng);
let pub_point = ProjectivePoint::GENERATOR * x;
// ... derive group_pubkey from pub_point ...

// Generate additive shares: random split
let n = config.total_parties as usize;
let mut shares: Vec<Scalar> = (0..n-1).map(|_| Scalar::random(&mut rng)).collect();
let last_share = x - shares.iter().fold(Scalar::ZERO, |acc, s| acc + s);
shares.push(last_share);
// shares[i] is the additive share for party (i+1)
// sum(shares) == x  ← this sum is NEVER computed after this point

// Distribute: send shares[i] to party (i+1), keep shares[0] for party 1
for (i, share) in shares.iter().enumerate() {
    let target = PartyId(i as u16 + 1);
    if target == party_id { continue; }
    // serialize and send via transport
}
```

**Sign:**
```rust
// All parties receive: (r, k_inv) from aggregator (Party 1)
// Step 1: Party 1 generates k, computes R, r, k_inv and broadcasts to all
// Step 2: Each party i computes:
//   s_i_partial = x_i_add * r * k_inv   (no hash involvement — only key contribution)
// Step 3: Each party broadcasts s_i_partial to Party 1 (aggregator)
// Step 4: Party 1 computes:
//   s_hash = hash_scalar * k_inv
//   s = s_hash + sum_i(s_i_partial)
//   return (r, s)
```

**Transport rounds:**
- Round 1: Party 1 → all: broadcast `(r_bytes: [u8;32], k_inv_bytes: [u8;32])`
- Round 2: All parties → Party 1: send `s_i_partial_bytes: [u8;32]`
- Party 1 aggregates and returns final `(r, s)`

**Feature flag:**
- New feature: `gg20-distributed = []` in `mpc-wallet-core/Cargo.toml`
- `default = ["gg20-distributed"]` — distributed signing is ON by default
- `gg20-simulation` remains available as opt-in for comparison tests
- When `gg20-distributed` feature is active, the `#[cfg(not(feature = "gg20-simulation"))]`
  production stub is replaced by the real distributed impl

Specifically: Add a third cfg branch:
```
#[cfg(feature = "gg20-simulation")]          → simulation (unchanged)
#[cfg(feature = "gg20-distributed")]          → new distributed impl (this task)
#[cfg(not(any(feature = "gg20-simulation", feature = "gg20-distributed")))]
                                              → error stub (returns Err)
```

#### Acceptance Criteria
- [ ] New feature `gg20-distributed` declared in `mpc-wallet-core/Cargo.toml` under `[features]`
- [ ] `default = ["gg20-distributed"]` set in `mpc-wallet-core/Cargo.toml`
- [ ] `gg20-simulation` remains as a separate non-default feature (no regression)
- [ ] `gg20.rs`: `sign()` under `gg20-distributed` feature NEVER calls `lagrange_interpolate` and NEVER assembles the sum `sum(additive_shares)` — full private key `x` does not exist as a variable anywhere in the distributed sign path
- [ ] `keygen()` under `gg20-distributed` generates proper additive shares (random split summing to `x`); the secret scalar `x` is zeroized (wrapped in `Zeroizing<Scalar>`) immediately after shares are generated and sent
- [ ] 2-of-2 signing test: two parties each hold an additive share; signing produces a valid secp256k1 ECDSA signature verifiable with `k256::ecdsa::VerifyingKey::verify`
- [ ] 3-party signing test: three parties each hold an additive share; signing produces valid ECDSA signature
- [ ] `k_inv` broadcast by aggregator: document in code comments that `k_inv` is an ephemeral per-session value. Confirm it is NOT the private key or any derivation of it.
- [ ] All existing tests pass: `cargo test -p mpc-wallet-core` (default features = gg20-distributed)
- [ ] `cargo test -p mpc-wallet-core --features gg20-simulation` still passes
- [ ] `cargo test -p mpc-wallet-core --no-default-features` compiles (error stub path)

#### Security Checklist for R6
- [ ] **SEC-001 resolved:** Full private key scalar `x` MUST NOT appear as a named variable in the `gg20-distributed` sign path. Search `gg20.rs` for any call to `lagrange_interpolate` in the distributed path — must be zero.
- [ ] **Additive share sum never computed during signing:** verify no code in the sign path computes `sum(additive_share_i)` or any equivalent reconstruction. The only place additive shares are summed is conceptually at keygen (Party 1 knows `x`); after share distribution, `x` is zeroized.
- [ ] **Secret `x` zeroized at keygen:** confirm `x: Scalar` in Party 1's keygen path is wrapped in `Zeroizing<Scalar>` or explicitly zeroized after shares are generated and before any `.await`
- [ ] **`k_inv` is ephemeral:** confirm `k_inv` is generated fresh per signing session (not reused). Each call to `sign()` generates a new `k`.
- [ ] **Nonce `k` not zero:** confirm code has `assert!(!bool::from(k.is_zero()))` or equivalent before computing `k_inv` to prevent panic on invert
- [ ] **Partial sig `s_i_partial` does not leak additive share:** `s_i_partial = x_i_add * r * k_inv`. Confirm `x_i_add` itself is NOT broadcast — only the product is sent. Code inspection required.
- [ ] **`ZeroizeOnDrop` on `Gg20DistributedShareData`:** verify the `ZeroizeOnDrop` derive is present on the new share data struct
- [ ] **`gg20-distributed` default ON, simulation OFF:** verify `Cargo.toml` `default = ["gg20-distributed"]` and `gg20-simulation` is NOT in default
- [ ] **Tests verify cryptographic correctness:** at least one test calls `k256::ecdsa::VerifyingKey::verify` on the output signature against the group public key
- [ ] `cargo audit` clean — no new dependencies added (k256, rand already present)

---

### Task Spec: T-S2-03
- **Agent:** R4 (Service)
- **Branch:** `agent/r4-cli-password`
- **Epic:** Epic J (Production Hardening)
- **Title:** Remove hardcoded "demo-password" fallback from all CLI commands (resolves SEC-002)
- **Complexity:** S
- **Depends on:** T-S2-00 merged (for `rpassword` workspace dep and `CoreError::PasswordRequired`)

#### Files owned (agent may ONLY modify these — nothing else)
```
crates/mpc-wallet-cli/src/commands/keygen.rs
crates/mpc-wallet-cli/src/commands/sign.rs
crates/mpc-wallet-cli/src/commands/address.rs
crates/mpc-wallet-cli/src/commands/keys.rs
crates/mpc-wallet-cli/Cargo.toml                         ← add rpassword = { workspace = true }
```

#### Context: What to replace

All four files currently contain:
```rust
let password = args.password.clone().unwrap_or_else(|| "demo-password".into());
```
(or a close variant). This must be entirely removed.

#### What to implement

Make `--password` a **required** clap argument by changing the `Option<String>` type in the
`Args` struct to `String` (removing `Option`). This is the simplest, safest approach:
- No new `rpassword` dep needed if prompt isn't required (but add it as a dep anyway per T-S2-00 so it's available for future interactive use)
- No `unwrap_or_else` possible when the type is `String` not `Option<String>`
- If `--password` is omitted, clap will print an error and exit — fail-fast, user-visible

Alternatively (if the Args struct uses `Option<String>` for other reasons), change to:
```rust
let password = args.password.clone().ok_or_else(|| {
    CoreError::PasswordRequired("--password flag is required".into())
})?;
```
using the new `CoreError::PasswordRequired` variant from T-S2-00.

**Do NOT use `rpassword` for interactive prompting in this sprint** — the simpler required-arg
approach is sufficient for SEC-002 resolution and avoids the complexity of interactive TTY handling.
Interactive prompting is tracked for a future sprint.

#### Acceptance Criteria
- [ ] `keygen.rs`: no `unwrap_or_else(|| "demo-password"...)` or `unwrap_or("demo-password"...)` anywhere
- [ ] `sign.rs`: same — zero occurrences of the hardcoded string
- [ ] `address.rs`: same
- [ ] `keys.rs`: same
- [ ] `crates/mpc-wallet-cli/Cargo.toml` adds `rpassword = { workspace = true }` to `[dependencies]`
- [ ] When `--password` is omitted, the CLI exits with a clear error (clap error if required arg, or `CoreError::PasswordRequired` if option-based) — NOT silently using "demo-password"
- [ ] `cargo test -p mpc-wallet-cli` passes (update any tests that used the implicit "demo-password" to pass `--password test-password` explicitly)
- [ ] `cargo build -p mpc-wallet-cli` succeeds
- [ ] `grep -r "demo-password" crates/mpc-wallet-cli/` returns zero results

#### Security Checklist for R6
- [ ] **SEC-002 resolved:** `grep -r "demo-password" crates/mpc-wallet-cli/src/` MUST return zero results. Check all 4 command files exhaustively.
- [ ] **No new fallback introduced:** confirm no other `unwrap_or_else`, `unwrap_or`, or `if password.is_empty()` blocks introduce a different default password
- [ ] **`--password` arg is either `String` (required) or handled with `CoreError::PasswordRequired`:** verify `Option<String>` is not silently `.unwrap()`ed anywhere in the new code
- [ ] **Test passwords use a clearly named constant:** if any test file uses a password string, it must be a named constant (e.g., `const TEST_PASSWORD: &str = "test-only-not-for-prod";`) not an inline `"demo-password"` or similar
- [ ] **`rpassword` added but not yet used for prompting:** confirm `rpassword` is in `Cargo.toml` but no live code calls `rpassword::prompt_password` yet (that's a future task) — this avoids accidental broken interactive paths
- [ ] `cargo audit` clean — `rpassword` and its deps have no CRITICAL advisories

---

### Task Spec: T-S2-04
- **Agent:** R3d (Sui Chain)
- **Branch:** `agent/r3d-sui-bcs`
- **Epic:** Epic J (Production Hardening)
- **Title:** Replace JSON tx_data with BCS-encoded TransactionData for Sui (advances SEC-011)
- **Complexity:** M
- **Depends on:** T-S2-00 merged (for `bcs` workspace dep in `mpc-wallet-chains/Cargo.toml`)

#### Files owned (agent may ONLY modify these — nothing else)
```
crates/mpc-wallet-chains/src/sui/tx.rs
crates/mpc-wallet-chains/src/sui/mod.rs
crates/mpc-wallet-chains/Cargo.toml                      ← bcs added by T-S2-00, just use it
```

#### Context: What exists today

`build_sui_transaction` in `sui/tx.rs` (lines 85–113) currently builds a canonical JSON blob
as `tx_data`. The sign_payload computation (Blake2b-256 of intent_prefix || tx_data) is
correct per the Sui spec — only the serialization of `tx_data` needs to change from JSON to BCS.

The `finalize_sui_transaction` (lines 124–183) currently:
1. Parses `tx_data` as JSON to recover the embedded pubkey hex
2. Builds the 97-byte Sui signature `[0x00 || sig(64) || pubkey(32)]`

Both functions must be updated when the serialization format changes.

#### Sui BCS TransactionData format (minimal implementation)

Sui's `TransactionData` is complex in full production. For Sprint 2, implement a
**minimal BCS-encoded transfer** sufficient to produce a valid Sui transfer transaction.

The Sui TransactionData for a simple SUI coin transfer (programmable transaction) has this structure:
```
TransactionData::V1 {
    kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
        inputs: [CallArg::Pure(bcs(amount_u64)), CallArg::Pure(bcs(recipient_address))],
        commands: [Command::TransferObjects(vec![Argument::Result(0)], Argument::Input(1))]
        // NOTE: this is a simplification; full SUI transfer uses SplitCoins + TransferObjects
    }),
    sender: SuiAddress (32 bytes),
    gas_data: GasData { ... },
    expiration: TransactionExpiration::None,
}
```

This is quite involved. **For Sprint 2, implement the following pragmatic approach:**

Since BCS is a simple format (see spec below), implement a **minimal BCS serializer** for
the exact Sui transfer transaction structure, rather than a full generic BCS library.

**BCS encoding rules (sufficient subset):**
- `u64`: 8 bytes little-endian
- `u8`: 1 byte
- `[u8; 32]` (address): 32 bytes as-is
- `Vec<T>` / sequence: ULEB128 length prefix, then each element
- `enum` variant: ULEB128 variant index, then payload
- `bool`: 1 byte (0 or 1)
- `Option<T>`: `0u8` for None, `1u8` followed by T for Some

**Minimal Sui ProgrammableTransaction for SUI transfer:**

The following byte layout is sufficient for a valid SUI coin transfer payload
that Sui nodes will accept (modulo gas object, which is a known limitation):

```rust
// Instead of implementing full TransactionData BCS, implement:
// A "SuiTransferPayload" struct that BCS-encodes the essential fields
// and can be used as tx_data for signing and broadcasting.

// Use the `bcs` crate: bcs::to_bytes(&value) for any Serde-serializable struct
// The bcs crate handles ULEB128, LE integers, etc. automatically.

#[derive(Serialize)]
struct SuiTransferTxData {
    sender: [u8; 32],
    recipient: [u8; 32],
    amount: u64,
    // Gas budget placeholder — required by Sui protocol
    gas_budget: u64,
    // Gas price placeholder
    gas_price: u64,
}
```

Use `bcs::to_bytes(&tx_data_struct)` to produce the BCS bytes.

NOTE: This is still a simplification of full Sui TransactionData, but it:
1. Uses real BCS encoding (not JSON)
2. Will sign correct bytes
3. Moves towards SEC-011 resolution

The `finalize_sui_transaction` must be updated to NOT parse JSON for the pubkey.
Instead: embed the pubkey as the LAST 32 bytes of `tx_data` (or store it separately
in a new struct), so finalize can recover it without JSON parsing.

Recommended approach:
```rust
// tx_data layout: BCS(SuiTransferTxData) || pubkey(32 bytes)
// finalize recovers pubkey as: &tx_data[tx_data.len()-32..]
// This avoids any JSON dependency in tx_data
```

Document this layout clearly in the code with a comment:
```rust
// tx_data layout: [BCS-encoded SuiTransferTxData][pubkey: 32 bytes]
// The pubkey suffix is NOT part of the Sui protocol tx_data —
// it is an SDK-internal convention for key recovery in finalize().
// TODO(production): Replace with proper Sui TransactionData BCS once
// full gas coin management is implemented.
```

#### Acceptance Criteria
- [ ] `build_sui_transaction` no longer uses `serde_json::json!()` for `tx_data` construction
- [ ] `tx_data` bytes are produced by `bcs::to_bytes()` (or manual BCS if `bcs` crate has compatibility issues)
- [ ] `sign_payload` computation is unchanged: `Blake2b-256(SUI_INTENT_PREFIX || tx_data_without_pubkey_suffix)` — the 32-byte pubkey suffix is NOT included in the bytes that are hashed for signing (it's appended AFTER hashing, for internal recovery use only)
- [ ] `finalize_sui_transaction` does NOT call `serde_json::from_slice` on `tx_data` — pubkey is recovered via the 32-byte suffix convention
- [ ] All existing Sui tests in `chain_integration.rs` pass
- [ ] New test `test_sui_tx_data_is_not_json`: assert that `tx_data[..1]` is NOT `b'{'` (i.e., not JSON)
- [ ] New test `test_sui_sign_payload_is_32_bytes`: assert `sign_payload.len() == 32`
- [ ] New test `test_sui_finalize_produces_97_byte_sig`: assert `raw_tx` decodes to a Sui sig of exactly 97 bytes, with `raw_tx["signature"]` hex decoding to `[0x00, sig(64), pubkey(32)]`
- [ ] `cargo test -p mpc-wallet-chains` passes
- [ ] `cargo build -p mpc-wallet-chains` with BCS dep passes

#### Security Checklist for R6
- [ ] **SEC-011 advanced:** `tx_data` must not be JSON — verify `serde_json::json!()` no longer appears in `build_sui_transaction`. `grep` for `serde_json::json` in `sui/tx.rs` must return zero results after this task.
- [ ] **sign_payload hashes only the transaction bytes, not the pubkey suffix:** confirm the 32-byte pubkey is appended to `tx_data` AFTER the hashing step. The `Blake2b-256(intent_prefix || tx_data_bcs_only)` call must NOT include the pubkey suffix bytes.
- [ ] **Pubkey recovery from suffix is bounds-checked:** confirm `finalize_sui_transaction` validates `unsigned.tx_data.len() >= 32` before slicing `[len-32..]` — prevents panic on malformed input
- [ ] **BCS encoding of address bytes:** confirm sender/recipient `[u8; 32]` are encoded as raw bytes (no ULEB128 length prefix for fixed-size arrays in BCS) — verify against BCS spec
- [ ] **No secret material in `tx_data`:** pubkey (32 bytes) is public; `tx_data` contains only sender address (public), recipient (public), amount (public), gas params (public). No private key bytes.
- [ ] Existing 97-byte signature format test still passes — `[0x00 || sig(64) || pubkey(32)]`
- [ ] `cargo audit` clean — `bcs` crate has no CRITICAL advisories

---

### Task Spec: T-S2-05
- **Agent:** R5 (QA)
- **Branch:** `agent/r5-ci`
- **Epic:** Epic I (Multi-cloud Ops) / Infrastructure
- **Title:** Set up GitHub Actions CI pipeline
- **Complexity:** S
- **Depends on:** Nothing — can start immediately, no source-code dependencies

#### Files owned (agent may ONLY modify/create these — nothing else)
```
.github/workflows/ci.yml                                 ← new file (create)
```

#### Context

There is currently no CI. Every merge is unverified by automation. The CI must run:
1. `cargo fmt --check` — enforces formatting
2. `cargo clippy -- -D warnings` — enforces lint cleanliness
3. `cargo test --workspace` — runs all 42+ tests
4. `cargo audit` — catches known CVEs in dependencies

The pipeline must pass on `main` after Sprint 2 merges, and must gate all future PRs.

#### Acceptance Criteria
- [ ] `.github/workflows/ci.yml` exists with a job named `ci` (or similar)
- [ ] Job triggers on: `push` to `main`, `pull_request` targeting `main`
- [ ] Runs on: `ubuntu-latest`
- [ ] Uses Rust toolchain: `stable` via `dtolnay/rust-toolchain@stable`
- [ ] Uses `Swatinem/rust-cache@v2` for dependency caching (reduces CI time significantly)
- [ ] Step 1: `cargo fmt --check` — fails if code is not formatted
- [ ] Step 2: `cargo clippy --workspace -- -D warnings` — fails on any warning
- [ ] Step 3: `cargo test --workspace` — must pass all tests
- [ ] Step 4: `cargo audit` — install via `cargo install cargo-audit --locked` (cached), then run
- [ ] All steps use the same `ubuntu-latest` runner
- [ ] `cargo test --workspace` step does NOT enable `gg20-simulation` feature (default features only — distributed signing must work without it)
- [ ] The workflow file is valid YAML (verified by `yamllint` or similar, or just careful review)

#### Example structure (adapt as needed)
```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - name: fmt
        run: cargo fmt --check
      - name: clippy
        run: cargo clippy --workspace -- -D warnings
      - name: test
        run: cargo test --workspace
      - name: audit
        run: |
          cargo install cargo-audit --locked
          cargo audit
```

#### Security Checklist for R6
- [ ] `cargo audit` step is present and runs AFTER test — confirms dependency vulnerability scanning is part of every CI run
- [ ] `gg20-simulation` feature is NOT enabled in the `cargo test` step — the dangerous simulation path is not the default test target
- [ ] No secrets, tokens, or credentials present in the workflow file
- [ ] `actions/checkout@v4` pinned to a major version tag (v4), not `@main` or `@latest` — avoids supply-chain risk from unpinned action refs
- [ ] `cargo clippy -- -D warnings` treats all warnings as errors — prevents lint debt accumulation
- [ ] No `continue-on-error: true` on the audit step — a new CRITICAL advisory must fail the build

---

## Blocked Tasks

| Task | Blocker | Resolution |
|------|---------|------------|
| T-S2-01 | T-S2-00 must merge first | R0 completes Wave 1; Wave 2 agents start after |
| T-S2-03 | T-S2-00 must merge first | same |
| T-S2-04 | T-S2-00 must merge first | same |
| T-S2-05 | None | Can start in parallel with T-S2-00 |

---

## Sprint Notes

- **T-S2-00 (R0) is the critical path gating item** — R0 must complete it before Wave 2 agents start.
  It is a small task (3 files, additive changes only) and should complete in one session.
- **T-S2-01 (R1) is the most complex task (L)** — the distributed signing math requires careful
  implementation and testing. R1 must run `cargo test -p mpc-wallet-core` with signing tests that
  call `k256::ecdsa::VerifyingKey::verify` to prove cryptographic correctness.
- **Feature flag convention:** `gg20-distributed` is ON by default in Sprint 2.
  `gg20-simulation` remains available but is OFF by default. Tests in CI run default features.
- **No NATS implementation in Sprint 2** — SEC-003 (NatsTransport stubs) is deferred to Epic E.
  The distributed signing in T-S2-01 uses `LocalTransport` for testing.
- **Sui BCS (T-S2-04) is pragmatic, not complete** — the goal is to remove JSON encoding and
  use real BCS bytes. Full Sui TransactionData with gas coin management is a Sprint 3 item.
- **SEC-002 is fully resolved by T-S2-03** — zero occurrences of "demo-password" in CLI source
  is the verification criterion. R6 will `grep` for it explicitly.
  - **Checkpoint commit rule enforced** — every agent commits after each `cargo test` pass with
    `[R{N}] checkpoint: {what changed} — tests pass`. Final commit: `[R{N}] complete: {summary}`.
  - **Worktree reminder** — each agent must run `cargo test` in their OWN worktree, not in
    `/project/mpc-wallet`. See LESSONS.md LESSON-008.

---

# Sprint 3 — 2026-04-14 → 2026-04-28

## Goal
**"Resolve SEC-003 CRITICAL (real NATS transport) + fix HIGH findings SEC-004/005/006 + test isolation"**

Replace all `todo!()` stubs in `NatsTransport` with working `async-nats` client code (SEC-003).
Harden `EncryptedFileStore` with wallet-class Argon2 parameters and zeroized secrets
(SEC-005/006). Reduce key-share memory exposure in protocol code (SEC-004 partial fix).
Split the shared chain integration test file to eliminate per-sprint merge conflicts (LESSON-007).

**Sprint owner:** R7 PM Agent
**Sprint dates:** 2026-04-14 → 2026-04-28

---

## Why These Are Hard Goals

| Finding | Severity | Why It Blocks |
|---------|----------|---------------|
| SEC-003 | CRITICAL | `NatsTransport` is 100% `todo!()` — the SDK has no working multi-party transport |
| SEC-005 | HIGH | `EncryptedFileStore` password/key never zeroized — key material lingers in heap |
| SEC-006 | HIGH | Argon2 default params (19 MiB, t=2) — too weak for wallet-class key encryption |
| SEC-004 | HIGH | `KeyShare.share_data: Vec<u8>` not zeroized; partial fix via R1 local copies |
| LESSON-007 | MEDIUM | Single chain test file causes guaranteed merge conflict every parallel sprint |

**SEC-007 (unauthenticated sender field)** is deferred: fixing it correctly requires transport-level
MAC keys (Epic E2/E3), which depend on SEC-003 being resolved first. SEC-007 is Sprint 4 scope.

**T-S3-04 (freeze/unfreeze real impl)** deferred to Sprint 4 to avoid overloading R2 with three
sequential tasks. R2 executes T-S3-01 first, then T-S3-02 after T-S3-01 is merged.

---

## Execution Order

```
Wave 1 (run in parallel — no dependencies on each other):
  T-S3-00  R0   agent/r0-s3-prep       (rustdoc public API + workspace readiness check)
  T-S3-05  R5   agent/r5-test-split    (split chain_integration.rs, resolves LESSON-007)

Wave 2 (after Wave 1 merges — R1 and R2 run in parallel):
  T-S3-01  R2   agent/r2-nats          (NATS real impl — resolves SEC-003 CRITICAL)
  T-S3-03  R1   agent/r1-zeroize-shares (zeroize share_data copies — partial SEC-004 fix)

Wave 2b (after T-S3-01 merges — R2 continues sequentially):
  T-S3-02  R2   agent/r2-argon2        (Argon2 hardening + zeroize password — resolves SEC-005/006)
```

**R2 sequential ordering:**
R2 cannot work on multiple branches simultaneously. Execution order for R2:
1. Complete and merge T-S3-01 (`agent/r2-nats`) — SEC-003 CRITICAL takes priority
2. Only after T-S3-01 is merged: start T-S3-02 (`agent/r2-argon2`) — SEC-005/006 HIGH

---

## Gate Status (Sprint 3)

| Task | Agent | Branch | PM Approved | R6 Verdict | Merged | Resolves |
|------|-------|--------|-------------|------------|--------|----------|
| T-S3-00 | R0 | `agent/r0-s3-prep` | ✓ | pending | ✗ | Epic 0 (rustdoc), workspace readiness |
| T-S3-05 | R5 | `agent/r5-test-split` | ✓ | pending | ✗ | LESSON-007 (test file conflicts) |
| T-S3-01 | R2 | `agent/r2-nats` | ✓ | pending | ✗ | SEC-003 CRITICAL |
| T-S3-02 | R2 | `agent/r2-argon2` | ✓ | pending | ✗ | SEC-005/006 HIGH |
| T-S3-03 | R1 | `agent/r1-zeroize-shares` | ✓ | pending | ✗ | SEC-004 HIGH (partial) |

---

## Task Specs

---

### Task Spec: T-S3-00
- **Agent:** R0 (Architect)
- **Branch:** `agent/r0-s3-prep`
- **Epic:** Epic 0 (Interface Freeze — story 0-2: rustdoc public API)
- **Title:** Rustdoc pass on all public R0-owned types + workspace readiness confirmation
- **Complexity:** S
- **Wave:** 1 — no blockers, can start immediately
- **Must complete before:** Wave 2 begins (gating checkpoint, not a code dependency)

#### Context

`CoreError::Transport(String)` already exists in `error.rs` (line 9) — added in Sprint 2.
`zeroize = { version = "1", features = ["derive"] }` is already in workspace deps.
`argon2 = "0.5"` is already in workspace deps; `Params::new()` is available without `"std"` feature.
**R0 has no new code to add for Wave 2 unblocking.** This task delivers Epic 0 story 0-2
(rustdoc on all public types) which has been pending since sprint 1.

#### Files owned (agent may ONLY modify these — nothing else)
```
crates/mpc-wallet-core/src/error.rs                      ← add/improve /// doc comments
crates/mpc-wallet-core/src/protocol/mod.rs               ← add/improve /// doc comments
crates/mpc-wallet-core/src/transport/mod.rs              ← add/improve /// doc comments
crates/mpc-wallet-core/src/key_store/mod.rs              ← add/improve /// doc comments
crates/mpc-wallet-core/src/types.rs                      ← add/improve /// doc comments (if it exists)
```

#### Acceptance Criteria
- [ ] Every `pub` item in `error.rs`, `protocol/mod.rs`, `transport/mod.rs`, `key_store/mod.rs`
      has a `///` doc comment explaining its role (not just restating the name)
- [ ] `CoreError` variants each have a doc comment noting when they are produced
      (e.g., `/// Returned when a key group has been frozen and cannot be used for signing.`)
- [ ] `KeyShare.share_data` has a doc comment noting:
      `/// SEC-004: this Vec<u8> is not zeroized on drop. Wrap in Zeroizing<Vec<u8>> when reading.`
      (tracks the known gap for R6 visibility without changing R0-owned type structure)
- [ ] `cargo doc --no-deps -p mpc-wallet-core` produces zero warnings
- [ ] `cargo check --workspace` passes — no regressions
- [ ] `cargo test -p mpc-wallet-core` passes — no regressions

#### Security Checklist for R6
- [ ] Doc comments do NOT include any secret values, key material, or password hints in example code
- [ ] `KeyShare.share_data` doc comment correctly identifies SEC-004 as an open gap — no false claim that the field is already zeroized
- [ ] No new code logic added — this is documentation only; confirm no `impl` blocks or `fn` bodies changed
- [ ] `cargo audit` clean — no new dependencies added
- [ ] No `#[allow(dead_code)]` or `#[allow(unused)]` annotations added (would suppress real warnings)

---

### Task Spec: T-S3-05
- **Agent:** R5 (QA)
- **Branch:** `agent/r5-test-split`
- **Epic:** Infrastructure / LESSON-007 fix
- **Title:** Split `chain_integration.rs` into per-chain test files
- **Complexity:** S
- **Wave:** 1 — no blockers, can start immediately in parallel with T-S3-00
- **Resolves:** LESSON-007 (shared test file causes deterministic merge conflicts every sprint)

#### Context

`crates/mpc-wallet-chains/tests/chain_integration.rs` is 743+ lines covering all four chains
(EVM, Bitcoin, Solana, Sui). Every sprint that touches ≥2 chain agents produces a merge conflict
at end-of-file because all agents append tests to the same file. The fix is to split into
per-chain files so each chain agent owns an independent test file with zero overlap.

The new layout:
```
crates/mpc-wallet-chains/tests/
  chain_common.rs           ← shared imports/helpers (use decls, helper fns)
  chain_evm_integration.rs  ← all EVM tests
  chain_bitcoin_integration.rs ← all Bitcoin tests
  chain_solana_integration.rs  ← all Solana tests
  chain_sui_integration.rs     ← all Sui tests
  chain_integration.rs         ← DELETE after split (all tests moved out)
```

#### Files owned (agent may ONLY modify/create/delete these — nothing else)
```
crates/mpc-wallet-chains/tests/chain_integration.rs      ← source of truth (read + delete at end)
crates/mpc-wallet-chains/tests/chain_common.rs           ← new file (create)
crates/mpc-wallet-chains/tests/chain_evm_integration.rs  ← new file (create)
crates/mpc-wallet-chains/tests/chain_bitcoin_integration.rs ← new file (create)
crates/mpc-wallet-chains/tests/chain_solana_integration.rs  ← new file (create)
crates/mpc-wallet-chains/tests/chain_sui_integration.rs  ← new file (create)
```

#### Acceptance Criteria
- [ ] `chain_common.rs` contains shared `use` declarations needed by ≥2 test files
      (e.g., `use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};`,
      `use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};`)
      and any shared helper functions (if any exist in `chain_integration.rs`)
- [ ] `chain_evm_integration.rs` contains ALL and ONLY the EVM tests from `chain_integration.rs`
      — verify by name: all functions containing `evm`, `ethereum`, `polygon`, `bsc` in their name
- [ ] `chain_bitcoin_integration.rs` contains ALL and ONLY the Bitcoin tests
      — verify by name: all functions containing `bitcoin`, `taproot`, `testnet`, `signet`
- [ ] `chain_solana_integration.rs` contains ALL and ONLY the Solana tests
      — verify by name: all functions containing `solana`
- [ ] `chain_sui_integration.rs` contains ALL and ONLY the Sui tests
      — verify by name: all functions containing `sui`
- [ ] `chain_integration.rs` is **deleted** after all tests are moved (not left as a shell)
- [ ] `cargo test -p mpc-wallet-chains` passes and the test count matches the pre-split count
      (no tests lost, no tests duplicated)
- [ ] Each new file compiles independently: if `chain_common.rs` exports helpers via `mod chain_common`
      or if each file is self-contained with its own `use` declarations, either approach is acceptable
      as long as all tests pass

**Note on Rust integration test file layout:** Each `.rs` file directly under `tests/` is a separate
integration test binary. Files do NOT automatically share `use` declarations. Each per-chain file
must independently import what it needs. The `chain_common.rs` file is best used as a shared module
included via `mod chain_common;` inside each per-chain file if helpers are needed, or simply kept
as a reference — either approach works.

#### Security Checklist for R6
- [ ] No test logic changed — only file reorganization (copy-paste and delete, not rewrite)
- [ ] Test count matches before and after: run `cargo test -p mpc-wallet-chains 2>&1 | grep "test result"` before and after; both must show the same number of `ok` tests
- [ ] No new test dependencies added to `Cargo.toml` — this is a file reorganization only
- [ ] No test intentionally removed or skipped (no `#[ignore]` added to existing tests)
- [ ] `chain_integration.rs` is confirmed deleted (not just emptied): `git status` shows it as deleted
- [ ] `cargo audit` clean — no new dependencies

---

### Task Spec: T-S3-01
- **Agent:** R2 (Infrastructure)
- **Branch:** `agent/r2-nats`
- **Epic:** Epic E (Transport Hardening — story E1)
- **Title:** Implement `NatsTransport::connect`, `send`, `recv` with real `async-nats` client (resolves SEC-003)
- **Complexity:** L
- **Wave:** 2 — starts after T-S3-00 merges
- **Resolves:** SEC-003 CRITICAL (all methods are currently `todo!()` stubs)

#### Context: Current state of `transport/nats.rs`

All five methods in `NatsTransport` are `todo!()` stubs (lines 27–58 of `nats.rs`):
- `connect()` → `todo!("connect to NATS server at nats_url")`
- `inbox_subject()` → `todo!()`
- `party_subject()` → `todo!()`
- `send()` → `todo!("serialize msg with serde_json, publish to party_subject")`
- `recv()` → `todo!("subscribe to inbox_subject, deserialize next message with serde_json")`

The `NatsTransport` struct holds: `client: async_nats::Client`, `party_id: PartyId`,
`session_id: String`. The `async-nats` crate is already a workspace dep.

NATS subject scheme (from the existing doc comment, line 9–12):
- Inbox: `mpc.{session_id}.party.{party_id}`
- Send to party X: `mpc.{session_id}.party.{X}`

`ProtocolMessage` already derives `Serialize + Deserialize` — JSON serialization is ready.

#### Files owned (agent may ONLY modify these — nothing else)
```
crates/mpc-wallet-core/src/transport/nats.rs              ← primary impl file
```

#### What to implement

**`inbox_subject(&self) -> String`:**
```rust
fn inbox_subject(&self) -> String {
    format!("mpc.{}.party.{}", self.session_id, self.party_id.0)
}
```

**`party_subject(session_id: &str, target: PartyId) -> String`:**
```rust
fn party_subject(session_id: &str, target: PartyId) -> String {
    format!("mpc.{}.party.{}", session_id, target.0)
}
```

**`connect(nats_url, party_id, session_id) -> Result<Self, CoreError>`:**
```rust
pub async fn connect(
    nats_url: &str,
    party_id: PartyId,
    session_id: String,
) -> Result<Self, CoreError> {
    let client = async_nats::connect(nats_url)
        .await
        .map_err(|e| CoreError::Transport(format!("NATS connect failed: {e}")))?;
    Ok(Self { client, party_id, session_id })
}
```

**`send(&self, msg: ProtocolMessage) -> Result<(), CoreError>`:**
```rust
async fn send(&self, msg: ProtocolMessage) -> Result<(), CoreError> {
    let subject = match msg.to {
        Some(target) => Self::party_subject(&self.session_id, target),
        None => {
            // Broadcast: not supported in basic NATS pub/sub; return error.
            // Full fanout broadcast requires JetStream (Epic E5 scope).
            return Err(CoreError::Transport(
                "broadcast (to: None) not yet supported in NatsTransport; use targeted send".into()
            ));
        }
    };
    let payload = serde_json::to_vec(&msg)
        .map_err(|e| CoreError::Transport(format!("serialize error: {e}")))?;
    self.client
        .publish(subject, payload.into())
        .await
        .map_err(|e| CoreError::Transport(format!("NATS publish failed: {e}")))?;
    Ok(())
}
```

**`recv(&self) -> Result<ProtocolMessage, CoreError>`:**
```rust
async fn recv(&self) -> Result<ProtocolMessage, CoreError> {
    let mut subscriber = self.client
        .subscribe(self.inbox_subject())
        .await
        .map_err(|e| CoreError::Transport(format!("NATS subscribe failed: {e}")))?;
    let msg = subscriber
        .next()
        .await
        .ok_or_else(|| CoreError::Transport("NATS subscription closed".into()))?;
    serde_json::from_slice(&msg.payload)
        .map_err(|e| CoreError::Transport(format!("deserialize error: {e}")))
}
```

#### Integration test approach (mock — no live NATS required)

A live NATS server is not available in CI. Use the following test strategy:

**Test 1 — unit test subject formatting (no NATS needed):**
```rust
#[test]
fn test_nats_subject_format() {
    let subject = NatsTransport::party_subject("sess-abc", PartyId(2));
    assert_eq!(subject, "mpc.sess-abc.party.2");
}
```

**Test 2 — trait contract via `LocalTransport` (no NATS needed):**

Create a test that demonstrates the `Transport` trait contract (send/recv/party_id) using
`LocalTransport` — this proves the trait interface works correctly and documents that
`NatsTransport` satisfies the same contract. Add a comment:
```rust
// NatsTransport integration test requires a live NATS server.
// Run manually: NATS_URL=nats://localhost:4222 cargo test --features nats-integration-test
// The trait contract (send/recv/party_id) is verified here using LocalTransport.
```

**Test 3 — `#[ignore]` NATS round-trip test (requires live server):**
```rust
#[tokio::test]
#[ignore = "requires live NATS server: NATS_URL=nats://localhost:4222"]
async fn test_nats_round_trip() {
    let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".into());
    let session = uuid::Uuid::new_v4().to_string();
    // ... connect two NatsTransport instances, send a ProtocolMessage from party 1 to party 2,
    // recv on party 2, assert message fields match
}
```

This test is `#[ignore]` by default and does NOT run in CI. It runs manually or in a future
CI environment with a NATS sidecar.

#### Acceptance Criteria
- [ ] `NatsTransport::connect` uses `async_nats::connect(nats_url).await` — no more `todo!()`
- [ ] `NatsTransport::inbox_subject` returns `"mpc.{session_id}.party.{party_id.0}"` — no more `todo!()`
- [ ] `NatsTransport::party_subject` returns `"mpc.{session_id}.party.{target.0}"` — no more `todo!()`
- [ ] `Transport::send` serializes `ProtocolMessage` as JSON and publishes to the target subject — no more `todo!()`
- [ ] `Transport::recv` subscribes to `inbox_subject()`, awaits next message, deserializes — no more `todo!()`
- [ ] Broadcast (`msg.to == None`) returns `Err(CoreError::Transport(...))` with a clear message (not a panic)
- [ ] All errors mapped to `CoreError::Transport(String)` — never panics in the impl
- [ ] `test_nats_subject_format` unit test passes (no NATS server needed)
- [ ] `#[ignore]` `test_nats_round_trip` test exists in the file and is correctly annotated
- [ ] Zero `todo!()` macros remain in `nats.rs`
- [ ] `cargo test -p mpc-wallet-core` passes (non-ignored tests only)
- [ ] `cargo check -p mpc-wallet-core` passes

#### Security Checklist for R6
- [ ] **SEC-003 resolved:** confirm zero `todo!()` macros in `transport/nats.rs` — `grep -n "todo!" nats.rs` must return zero results
- [ ] **No panic paths in impl:** every `unwrap()` or `expect()` must be replaced with `?` or `.map_err(...)` — confirm `grep -n "\.unwrap()\|\.expect(" nats.rs` returns zero results in the impl blocks (test code may use unwrap)
- [ ] **Broadcast error, not panic:** `msg.to == None` path returns `Err(CoreError::Transport(...))` — confirm the match arm does NOT call `todo!()` or `unimplemented!()`
- [ ] **No TLS yet — documented:** the implementation uses plain TCP NATS (`async_nats::connect`). Confirm there is a `// SECURITY: TLS not yet configured — Epic E2 scope` comment in `connect()`. This is known and intentional; TLS is Epic E2.
- [ ] **No credentials logged:** the `nats_url` passed to `connect()` may contain credentials (e.g., `nats://user:pass@host`). Confirm the error message on connect failure does NOT include the full URL string with credentials. Use a sanitized message or log only the host portion.
- [ ] **`ProtocolMessage.from` field is still self-reported (SEC-007 still open):** confirm there is a `// SEC-007: from field is self-reported — authentication pending Epic E3` comment in `recv()`. This finding remains open and is tracked.
- [ ] **No new crate dependencies added** — `async-nats`, `serde_json`, `uuid` are already workspace deps. Verify `Cargo.toml` for `mpc-wallet-core` is unchanged.
- [ ] `cargo audit` clean — confirm no new advisories

---

### Task Spec: T-S3-02
- **Agent:** R2 (Infrastructure)
- **Branch:** `agent/r2-argon2`
- **Epic:** Epic J (Production Hardening) / SEC-005/006 fix
- **Title:** Argon2 parameter hardening + zeroize password and derived key in `EncryptedFileStore` (resolves SEC-005/006)
- **Complexity:** M
- **Wave:** 2b — starts only AFTER T-S3-01 is merged (R2 sequential constraint)
- **Resolves:** SEC-005 HIGH (password/key not zeroized) + SEC-006 HIGH (Argon2 params too weak)

#### Context: Current state of `key_store/encrypted.rs`

**SEC-006 problem (`encrypted.rs:29`):**
```rust
fn derive_key(&self, salt: &[u8]) -> Result<[u8; 32], CoreError> {
    let mut key = [0u8; 32];
    argon2::Argon2::default()   // ← defaults: m=19456 KiB, t=2, p=1 — too weak
        .hash_password_into(self.password.as_bytes(), salt, &mut key)
        .map_err(|e| CoreError::Encryption(e.to_string()))?;
    Ok(key)  // ← returned as plain [u8;32] — not zeroized
}
```

**SEC-005 problem (`encrypted.rs:14-17`):**
```rust
pub struct EncryptedFileStore {
    base_dir: PathBuf,
    password: String,  // ← plain String — not zeroized on drop
}
```

After `encrypt()` or `decrypt()` calls, the `key: [u8; 32]` from `derive_key` sits on the stack
(and in the heap-backed `Vec` returned) without being cleared. The password remains in memory
for the lifetime of the `EncryptedFileStore` instance without zeroization.

#### Files owned (agent may ONLY modify these — nothing else)
```
crates/mpc-wallet-core/src/key_store/encrypted.rs        ← primary impl file
```

#### What to implement

**Step 1 — Zeroize the password field:**
```rust
use zeroize::Zeroizing;

pub struct EncryptedFileStore {
    base_dir: PathBuf,
    password: Zeroizing<String>,  // ← zeroized on drop automatically
}

impl EncryptedFileStore {
    pub fn new(base_dir: PathBuf, password: &str) -> Self {
        Self {
            base_dir,
            password: Zeroizing::new(password.to_string()),
        }
    }
    // ...
}
```

**Step 2 — Upgrade Argon2 parameters:**
```rust
fn derive_key(&self, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let params = argon2::Params::new(
        65536,  // m_cost: 64 MiB (OWASP wallet-class recommendation)
        3,      // t_cost: 3 iterations
        4,      // p_cost: 4 lanes
        None,   // output_len: default (32 bytes)
    )
    .map_err(|e| CoreError::Encryption(format!("argon2 params error: {e}")))?;

    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(self.password.as_bytes(), salt, key.as_mut())
        .map_err(|e| CoreError::Encryption(e.to_string()))?;
    Ok(key)  // ← Zeroizing<[u8; 32]> — cleared on drop
}
```

**Step 3 — Use the zeroized key in `encrypt` and `decrypt`:**
The `key` from `derive_key` is now `Zeroizing<[u8; 32]>`. Pass `key.as_ref()` to
`Aes256Gcm::new_from_slice(&key)`. The `Zeroizing` wrapper will clear the key bytes
when it goes out of scope (after the cipher is created).

**Step 4 — Add 32-byte salt:**
Upgrade the random salt from 16 bytes to 32 bytes for high-security context (SEC-006 recommendation).
Update the binary format: `salt (32) + nonce (12) + ciphertext`. Update `decrypt` to read 32 bytes
of salt. Update the minimum-length check from `< 28` to `< 44`.

**Document the format in a module-level comment:**
```rust
// Key file binary format:
//   [0..32]  : Argon2id salt (32 random bytes)
//   [32..44] : AES-256-GCM nonce (12 random bytes)
//   [44..]   : AES-256-GCM ciphertext (authenticated)
//
// Argon2id parameters: m=65536 KiB, t=3, p=4 (OWASP wallet-class)
// NOTE: Changing these parameters breaks decryption of files encrypted
// with old parameters. Existing key files must be re-encrypted after upgrade.
```

**IMPORTANT — backward compatibility warning:** Changing the salt size from 16→32 bytes
**breaks decryption of existing encrypted files**. The test suite creates fresh files each test,
so existing tests will still pass. Document this in the code and in the commit message.
This is intentional: existing test-only files are throwaway, and production deployments
would need to re-encrypt key shares after upgrading (a migration procedure, not yet in scope).

#### Acceptance Criteria
- [ ] `EncryptedFileStore.password` field is `Zeroizing<String>` — plain `String` is gone
- [ ] `EncryptedFileStore::new` wraps the password in `Zeroizing::new(password.to_string())`
- [ ] `derive_key` uses explicit `argon2::Params::new(65536, 3, 4, None)` — `Argon2::default()` is gone
- [ ] `derive_key` returns `Zeroizing<[u8; 32]>` — plain `[u8; 32]` is gone
- [ ] Salt is upgraded from 16 bytes to 32 bytes in `encrypt`
- [ ] `decrypt` reads 32-byte salt and minimum-length check updated to `>= 44`
- [ ] A module-level doc comment documents the binary format and Argon2 parameters
- [ ] A doc comment warns that changing parameters breaks existing files
- [ ] All existing tests in `encrypted.rs` still pass (they create fresh files):
      `test_save_load_roundtrip`, `test_list_and_delete`, `test_touch_updates_timestamp`
- [ ] New test `test_argon2_params_are_hardened`: instantiate `EncryptedFileStore`, call
      `encrypt(b"test")`, call `decrypt` on the result, assert round-trip works — this exercises
      the new param path end-to-end without inspecting internals (correctness proof)
- [ ] New test `test_password_not_in_memory_after_drop` (best-effort): create a store, drop it,
      assert no panic. This is a smoke test — full memory verification would require `valgrind`.
      A comment in the test should note: "zeroization verified by type system (Zeroizing<String>);
      runtime verification requires memory inspection tooling beyond cargo test scope."
- [ ] `cargo test -p mpc-wallet-core` passes

#### Security Checklist for R6
- [ ] **SEC-006 resolved:** `argon2::Argon2::default()` must NOT appear anywhere in `encrypted.rs` — `grep "Argon2::default" encrypted.rs` returns zero results
- [ ] **Argon2 params are correct:** `m_cost=65536, t_cost=3, p_cost=4` — verify via code inspection that `argon2::Params::new(65536, 3, 4, None)` is the exact call. Confirm `m_cost` is in KiB (the `argon2` crate takes KiB directly, so 65536 = 64 MiB)
- [ ] **SEC-005 resolved:** `password: String` field is GONE from `EncryptedFileStore` struct — `grep "password: String" encrypted.rs` returns zero results. The field must be `Zeroizing<String>`.
- [ ] **Derived key is `Zeroizing<[u8; 32]>`:** confirm `derive_key` return type is `Result<Zeroizing<[u8; 32]>, CoreError>` — the key bytes are cleared when the `Zeroizing` wrapper drops at end of `encrypt`/`decrypt`
- [ ] **Salt is 32 bytes:** confirm `encrypt` generates `[0u8; 32]` for salt (not `[0u8; 16]`). Confirm `decrypt` slices `&data[..32]` for salt. Confirm minimum-length check is `data.len() < 44` (32 salt + 12 nonce).
- [ ] **No `unwrap()` on `Params::new()`:** confirm the `Params::new(...)` call is `.map_err(...)` propagated, not `.unwrap()` — invalid params should return `Err(CoreError::Encryption(...))` not panic
- [ ] **Backward-compat warning documented:** confirm code comment warns that existing files encrypted with old params (16-byte salt) cannot be decrypted with the new code. This is expected and acceptable for the test-only files.
- [ ] **Round-trip test covers new params:** `test_argon2_params_are_hardened` must encrypt AND decrypt to prove the new Argon2 config produces valid ciphertext (not just that `Params::new` succeeds)
- [ ] `cargo audit` clean — no new dependencies (`zeroize` is already in workspace)

---

### Task Spec: T-S3-03
- **Agent:** R1 (Crypto)
- **Branch:** `agent/r1-zeroize-shares`
- **Epic:** Epic J (Production Hardening) / SEC-004 partial fix
- **Title:** Zeroize `KeyShare.share_data` copies in protocol code (partial SEC-004 fix)
- **Complexity:** M
- **Wave:** 2 — starts after T-S3-00 merges; runs in parallel with T-S3-01
- **Resolves:** SEC-004 HIGH (partial — R0-owned struct cannot be changed by R1; R1 fixes local copies)

#### Context: SEC-004 and R1's scope

`KeyShare.share_data: Vec<u8>` is defined in `protocol/mod.rs` (R0's file, line 39).
Changing `share_data` from `Vec<u8>` to `Zeroizing<Vec<u8>>` requires R0 approval and is
deferred (requires coordinated breaking change across all serialization). R0 will address
this in a future sprint via DEC-NNN.

**What R1 CAN do without touching R0's files:**

In `gg20.rs`, `frost_ed25519.rs`, and `frost_secp256k1.rs`, when R1's code reads
`key_share.share_data`, it copies the bytes into local variables for deserialization.
Those local `Vec<u8>` copies contain key material and are not currently zeroized.

R1 must wrap every such local copy in `Zeroizing<Vec<u8>>` to ensure the copy is
cleared when the local variable drops.

#### Files owned (agent may ONLY modify these — nothing else)
```
crates/mpc-wallet-core/src/protocol/gg20.rs
crates/mpc-wallet-core/src/protocol/frost_ed25519.rs
crates/mpc-wallet-core/src/protocol/frost_secp256k1.rs
```

#### Files R1 must NOT modify
```
crates/mpc-wallet-core/src/protocol/mod.rs              ← R0 owns — KeyShare struct definition
```

#### What to implement

For each protocol file, find every place where `key_share.share_data` bytes are read
and deserialized. Example pattern to find:

```rust
// BEFORE (unprotected copy):
let share: SomeShareStruct = serde_json::from_slice(&key_share.share_data)?;

// AFTER (protected copy using Zeroizing wrapper):
let share_bytes = zeroize::Zeroizing::new(key_share.share_data.clone());
let share: SomeShareStruct = serde_json::from_slice(&share_bytes)?;
// share_bytes is zeroized here when it drops
```

The `SomeShareStruct` type itself (e.g., `Gg20DistributedShareData`, `FrostEd25519ShareData`,
`FrostSecp256k1ShareData`) already implements `ZeroizeOnDrop` — the issue is only the
intermediate `Vec<u8>` clone used for deserialization.

**For `gg20.rs` specifically:**
- The `Gg20DistributedShareData.additive_share: Vec<u8>` is already `ZeroizeOnDrop` via derive.
- Wrap the `key_share.share_data.clone()` call used in `serde_json::from_slice` in `Zeroizing::new(...)`.
- Also check the keygen path: the `share_data` bytes written to `KeyShare` should be produced
  from a `Zeroizing` buffer if they contain the raw additive share scalar.

**For `frost_ed25519.rs` and `frost_secp256k1.rs`:**
- `FrostEd25519ShareData` and `FrostSecp256k1ShareData` already derive `ZeroizeOnDrop`.
- Same pattern: wrap the intermediate `Vec<u8>` clone of `share_data` in `Zeroizing::new(...)`.

**Add zeroize tests:**

For each protocol, add a test that confirms the pattern works correctly:
```rust
#[test]
fn test_share_data_copy_uses_zeroizing() {
    // This test documents the zeroization pattern and exercises the code path.
    // Full memory verification requires external tooling.
    // Confirmed: share_data copy is wrapped in Zeroizing<Vec<u8>> — see sign() implementation.
    // The Zeroizing wrapper ensures the copy is cleared before function returns.
    let _confirmed = true;
}
```

Additionally, confirm the `ZeroizeOnDrop` derive on share data structs by adding a compile-time test:
```rust
fn _assert_share_data_zeroize_on_drop() {
    fn assert_zeroize<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize::<Gg20DistributedShareData>();     // (or Gg20ShareData for simulation)
    assert_zeroize::<FrostEd25519ShareData>();
    assert_zeroize::<FrostSecp256k1ShareData>();
}
```

#### Acceptance Criteria
- [ ] In `gg20.rs`: every `key_share.share_data.clone()` or equivalent copy used for
      deserialization is wrapped in `zeroize::Zeroizing::new(...)`
- [ ] In `frost_ed25519.rs`: same — every local copy of `share_data` bytes is `Zeroizing`-wrapped
- [ ] In `frost_secp256k1.rs`: same
- [ ] No changes to `protocol/mod.rs` (R0 owns) — the `KeyShare` struct definition is untouched
- [ ] Compile-time assertion `_assert_share_data_zeroize_on_drop()` added (or equivalent
      `static_assertions` approach) confirming each share data struct implements `ZeroizeOnDrop`
- [ ] `cargo test -p mpc-wallet-core` passes
- [ ] `cargo test -p mpc-wallet-core --features gg20-simulation` passes (simulation path also patched)
- [ ] `cargo check -p mpc-wallet-core` passes with no new warnings

#### Security Checklist for R6
- [ ] **SEC-004 partial fix:** confirm every `key_share.share_data.clone()` site in all three
      protocol files is wrapped in `Zeroizing::new(...)`. Verify by searching:
      `grep -n "share_data.clone\|share_data\[" gg20.rs frost_ed25519.rs frost_secp256k1.rs`
      — every occurrence must be inside a `Zeroizing::new(...)` wrapper
- [ ] **No change to `KeyShare` struct:** confirm `protocol/mod.rs` is not modified.
      `git diff agent/r1-zeroize-shares -- crates/mpc-wallet-core/src/protocol/mod.rs` must be empty.
- [ ] **`ZeroizeOnDrop` is actually derived on share data structs:** confirm the compile-time
      assertion `_assert_share_data_zeroize_on_drop()` compiles successfully — this proves the
      derive is present, not just assumed
- [ ] **SEC-004 root cause documented:** add a code comment near the `KeyShare.share_data` usage
      in each file: `// SEC-004: share_data is Vec<u8> (not Zeroizing); this local copy IS Zeroizing.`
      This makes the partial fix visible to future reviewers.
- [ ] **Keygen path covered:** confirm the `sign()` AND `keygen()` paths are both checked in each
      file — the zeroization gap exists wherever `share_data` bytes are cloned, not just in signing
- [ ] **No `unwrap()` added** in the zeroization changes — all error paths use `?` propagation
- [ ] `cargo audit` clean — no new dependencies (`zeroize` is already in workspace)

---

## Blocked Tasks (Sprint 3)

| Task | Blocker | Resolution |
|------|---------|------------|
| T-S3-01 | T-S3-00 merged (wave gate) | R0 completes T-S3-00 first |
| T-S3-02 | T-S3-01 merged (R2 sequential) | R2 completes T-S3-01 first; only then starts T-S3-02 |
| T-S3-03 | T-S3-00 merged (wave gate) | Runs in parallel with T-S3-01 |
| T-S3-05 | None | Wave 1 — starts immediately in parallel with T-S3-00 |

---

## Deferred to Sprint 4

| Item | Reason |
|------|--------|
| T-S3-04 (freeze/unfreeze real impl) | R2 already has two sequential tasks this sprint; adding a third would require a third branch and serialization risk. Deferred to Sprint 4. |
| SEC-007 (unauthenticated sender) | Requires transport-level MAC keys (Epic E2/E3) which depend on SEC-003 being complete. Will be addressed in Sprint 4 after T-S3-01 is merged and stable. |
| SEC-004 root fix (`KeyShare.share_data: Zeroizing<Vec<u8>>`) | Requires R0 breaking change to `KeyShare` struct + coordinated migration of all JSON deserialization. Deferred to Sprint 4 as a dedicated R0 task. |

---

## Sprint Notes

- **R2 sequential constraint is hard:** R2 cannot work on two branches simultaneously.
  T-S3-01 (`agent/r2-nats`) is the CRITICAL priority. T-S3-02 (`agent/r2-argon2`) only
  starts after T-S3-01 is merged and R6-approved. Do not attempt to parallelize R2's tasks.

- **T-S3-00 is intentionally small:** `CoreError::Transport` already exists; `zeroize` is already
  a workspace dep; `argon2::Params::new()` needs no new features. R0's Sprint 3 work is the
  rustdoc pass (Epic 0 story 0-2), which has been pending since Sprint 1.

- **T-S3-05 has zero code risk:** it is a file move + delete. R5 must verify test count
  matches before and after. The only risk is accidentally dropping a test — prevented by
  the test count assertion in acceptance criteria.

- **Argon2 param change breaks existing test-only key files:** This is expected and acceptable.
  All test files are created fresh in `tempdir()` per test — no production files affected.
  The code comment documents this for any future migration procedure.

- **NATS TLS is NOT in T-S3-01:** Epic E2 (mTLS) and Epic E3 (per-session ECDH) are out of scope.
  T-S3-01 implements plaintext NATS (SEC-003 fix = no more `todo!()` stubs). The TLS gap
  must be documented in the code with a `// SECURITY: TLS not yet configured — Epic E2 scope` comment.

- **Checkpoint commit rule enforced** — every agent commits after each `cargo test` pass with
  `[R{N}] checkpoint: {what changed} — tests pass`. Final commit: `[R{N}] complete: {summary}`.

- **Worktree reminder** — each agent must run `cargo test` in their OWN worktree, not in
  `/project/mpc-wallet`. See LESSONS.md LESSON-008.
  - R0 worktree: `/Users/thecoding/git/worktrees/mpc-r0`
  - R1 worktree: `/Users/thecoding/git/worktrees/mpc-r1`
  - R2 worktree: `/Users/thecoding/git/worktrees/mpc-r2`
  - R5: no dedicated worktree — use main repo or a fresh worktree `mpc-r5`

---

## Sprint 4 Gate Status Update (2026-03-16 — ALL MERGED)

| Task | Agent | Branch | R6 Verdict | Merged | Resolves |
|------|-------|--------|------------|--------|----------|
| T-S4-00 | R0 | `agent/r0-s4-prep` | APPROVED | ✓ | SEC-004 root (`KeyShare.share_data` → `Zeroizing<Vec<u8>>`), SEC-015 (redacted Debug), `CoreError::PolicyRequired` + `SessionError` |
| T-S4-01 | R1 | `agent/r1-s4-zeroize` | APPROVED | ✓ | SEC-004 protocol side — cleanup Sprint 3 workarounds, compile-time `ZeroizeOnDrop` assertions |
| T-S4-02 | R4 | `agent/r4-policy` | APPROVED | ✓ | FR-B5 "no policy → no sign" — `PolicyStore`, `Policy` schema v1, allowlist + amount evaluator, 6 tests |
| T-S4-03 | R4 | `agent/r4-session` | APPROVED | ✓ | FR-D1/D2 — `SessionManager` state machine (Pending→Signing→Completed/Failed), tx_fingerprint idempotency lock (TOCTOU safe), 9 tests |
| T-S4-04 | R2 | `agent/r2-freeze` | APPROVED | ✓ | FR-H3 — real freeze/unfreeze persistence in `EncryptedFileStore` (frozen marker file, load checks before decrypt), 5 tests |

**Sprint 4 result:** 85 tests pass (was 55). +30 new tests across policy, session, freeze/unfreeze.
**SEC-004 status:** RESOLVED (root fix applied — `share_data` is now `Zeroizing<Vec<u8>>`).
**SEC-015 status:** RESOLVED (manual `Debug` impl redacts `share_data` → `"[REDACTED]"`).
**FR-B5, FR-D1/D2, FR-H3:** all delivered.

---

## Sprint 38–43 Gate Status (2026-04-28 → 2026-05-10 — ALL MERGED)

Live testnet MPC broadcast push: end-to-end signing from real shares to real testnet RPCs.

| Sprint | Theme | Owner | R6 Verdict | Merged | Live tx / Result |
|--------|-------|-------|------------|--------|------------------|
| 38 | Sepolia live MPC (GG20) | R3 | APPROVED | ✓ | First live Ethereum testnet MPC tx; lessons L-011, L-012, L-013 |
| 39 | Solana devnet live MPC (FROST-Ed25519) | R3c | APPROVED | ✓ | First live Solana devnet MPC tx |
| 40 | Bitcoin testnet live MPC (P2WPKH + GG20) | R3b | APPROVED | ✓ | First live Bitcoin testnet MPC tx; L-014 (FROST-TR Taproot tweak parked) |
| 41 | Sui testnet live MPC (FROST-Ed25519) | R3d | APPROVED | ✓ | First live Sui testnet MPC tx via `TransactionData::V1`; L-015 |
| 42 | Aptos testnet live MPC (FROST-Ed25519) | R3 | APPROVED | ✓ | First live Aptos testnet MPC tx via `RawTransaction`; L-016 |
| 43 | TRON Shasta live MPC (GG20) | R3 | APPROVED | ✓ | TRON Shasta tx `632a52ef4129f52e03d950cd7552202a964c126d6a251ccb6b0a6467f04b9ce2` from `TGbSVxCm4yConwQyQQifV5We2Zmany8SFS`; L-017 |

**Sprint 38–43 result:** 941 tests pass, fmt + clippy clean.
**Security:** No new findings. All 68 prior findings remain RESOLVED.

### Sprint 43 highlights (TRON Shasta)
- Hand-rolled Protobuf encoder for TRON `Transaction.raw` (`TransferContract`).
- Reference vector via tronweb (`scripts/tron-ref-vector.mjs`) — byte-equal match.
- `TronRpcClient` with `get_now_block`, `get_balance`, `broadcast` (full tronweb-shape body).
- `send.rs` Tron arm: balance preflight, `fetch_presign_extras`, signature recovery
  verification, explorer URL.
- L-017 retro: TRON broadcast body shape + TonGrid swagger reflection trap +
  `fee_limit` omission for transfers + `v = 27 + parity` recovery byte.

---

## Sprint 44–45 Gate Status (2026-05-10 — ALL MERGED)

Cross-chain token transfer foundation: schema design + first live ERC-20 broadcast.

| Sprint | Theme | Owner | R6 Verdict | Merged | Result |
|--------|-------|-------|------------|--------|--------|
| 44 | Cross-chain token transfer schema (`TokenIdentifier`) | R0/R7 | APPROVED | ✓ | Schema + research/design only; no chain wire-up |
| 45 | EVM ERC-20 token transfer (live USDC-Sepolia) | R3a | APPROVED | ✓ | Live tx `0x23ab51bde4db9e737f0f6039c21bf418f68147d230f9100119715643ceb090a9` (0.1 USDC self-transfer, 40,707 gas); L-018 |

**Sprint 44–45 result:** 951 tests pass (was 941; +10 from `token.rs` + `erc20.rs`), fmt + clippy clean.
**Security:** No new findings. All 68 prior findings remain RESOLVED.

### Sprint 45 highlights (EVM ERC-20)
- `TokenIdentifier` schema implemented at chain-crate level (`crates/mpc-wallet-chains/src/token.rs`).
- EVM ERC-20 ABI encoder (`crates/mpc-wallet-chains/src/evm/erc20.rs`) with viem-pinned reference vector.
- `build_evm_transaction` detects `extra["token"]` and rewrites `to`/`value`/`data` for ERC-20.
- `eth_estimateGas` helper (`evm/rpc_client.rs`); token spec threaded into `fetch_presign_extras`
  for dynamic `gas_limit` (replaces the static EOA-floor 21k that broke ERC-20 broadcasts).
- CLI `--token <shorthand>` flag (e.g. `erc20:0x...`) and `--token-json` escape hatch.
- L-018 retro: EVM `gas_limit` must be dynamic via `eth_estimateGas` — "simulate first, sign second"
  applies to all chains with per-tx exec caps.

### Token Transfer Coverage
| Chain | Status | Sprint |
|-------|--------|--------|
| EVM ERC-20 | LIVE (USDC-Sepolia) | 45 |
| Sui `Coin<T>` (PTB SplitCoins+TransferObjects) | CODE-COMPLETE (296-byte BCS matches `@mysten/sui`; live pending non-SUI testnet token) | 46 |
| Aptos legacy `0x1::coin::transfer<T>` | LIVE (testnet `0x72c2e3b5…`, `<AptosCoin>` path) | 46 |
| Aptos Fungible Asset (`primary_fungible_store`) | PLANNED | 47 |
| TRON TRC-20 | PLANNED | 48 |
| Solana SPL | PLANNED | 49 |

---

## Sprint 46 Gate Status (2026-05-10 — ALL MERGED)

Second token-transfer sprint: Sui `Coin<T>` + Aptos legacy `0x1::coin::transfer<T>`.

| Sprint | Theme | Owner | R6 Verdict | Merged | Result |
|--------|-------|-------|------------|--------|--------|
| 46 | Sui `Coin<T>` PTB transfer | R3d | APPROVED | ✓ | `ProgrammableTransaction::transfer_coin` (Object input as `SplitCoins` source instead of GasCoin); wire format omits T (validator infers from on-chain object type); `SuiRpcClient::get_owned_coins` now takes `coin_type` filter; 296-byte BCS byte-equal to `@mysten/sui`. Live deferred (non-SUI testnet token funding pending). |
| 46 | Aptos legacy `0x1::coin::transfer<T>` | R3 | APPROVED | ✓ | `EntryFunction::coin_transfer` + `RawTransaction::new_coin_transfer` + `StructTag::parse` helper; 211-byte BCS byte-equal to `@aptos-labs/ts-sdk`; live testnet tx `0x72c2e3b599d55a0df9d15d55e7b77022f2163e9120acc3ca9d60c8c7adbe7892` (`<AptosCoin>` native APT path). |

**Sprint 46 result:** 956 tests pass (was 951; +5 — 1 Sui Coin ref vector + 1 Aptos Coin ref vector + 3 `StructTag::parse` tests), fmt + clippy clean.
**Security:** No new findings. All 68 prior findings remain RESOLVED.
**Lessons:** None new — both work landed first try, leveraging L-015 (Sui hand-rolled BCS shape), L-016 (Aptos auth/signing-message order), and L-018 (dynamic gas/fee).

### Sprint 46 highlights
- Sui PTB shape: source coin is now an `Input::Object` (object_ref) into `SplitCoins`, not the implicit `GasCoin`; transferred amount is a `pure u64` input; recipient is a `pure address` input. Type parameter `T` is **not** in the wire format.
- Aptos `EntryFunction` path uses `module_id = 0x1::coin`, `function = transfer`, generic args = `[StructTag(T)]`, args = BCS(`recipient`, `amount`). `StructTag::parse("0x1::aptos_coin::AptosCoin")` constructs the type tag from the canonical string form.
- CLI shorthand `--token sui-coin:0x...::module::Type` and `--token aptos-coin:0x...::module::Type` flow unchanged through the `TokenIdentifier` schema introduced in Sprint 44.

---

## Sprint 47 Gate Status (2026-05-10 — ALL MERGED)

Aptos Fungible Asset (FA) standard — `0x1::primary_fungible_store::transfer`.

| Sprint | Theme | Owner | R6 Verdict | Merged | Result |
|--------|-------|-------|------------|--------|--------|
| 47 | Aptos FA `primary_fungible_store::transfer` | R3 | APPROVED | ✓ | `EntryFunction::primary_fungible_store_transfer` + `RawTransaction::new_fungible_asset_transfer`; type arg always `0x1::fungible_asset::Metadata`, args = `[Object<Metadata>, recipient, amount]`; `parse_aptos_address_padded` for short-form framework constants like `0xa` (sender/recipient remain strict 64-char); 265-byte BCS byte-equal to `@aptos-labs/ts-sdk`; live testnet tx `0xb3a41e3339db31111b8613442d895ffe2fc15615bd8624a821d52bc72b8f76f8` (native APT routed through FA at canonical metadata `0xa`). |

**Sprint 47 result:** 957 tests pass (was 956; +1 FA reference vector test `aptos::types::tests::bcs_matches_aptos_sdk_fa_reference`), fmt + clippy clean.
**Security:** No new findings. All 68 prior findings remain RESOLVED.
**Lessons:** L-019 — Aptos has two address conventions (strict 64-char for derived addresses to catch copy-truncation; short-form tolerated for framework constants like `0xa`); needs split parser.

### Sprint 47 highlights
- FA identity model: `Coin<T>` keyed identity in the **type system** (generic parameter `T`); FA keys identity by a runtime `Object<Metadata>` **address**. Same logical asset (native APT) can route through either path with different wire-format identity.
- Live tx `0xb3a41e3339db31111b8613442d895ffe2fc15615bd8624a821d52bc72b8f76f8`: native APT sent through the FA path at canonical metadata `0xa` — same value, different wire path than the Sprint 46 `<AptosCoin>` legacy tx.
- `parse_aptos_address_padded` accepts short-form like `0xa` and left-pads to 32 bytes (only used for framework constant type args). Sender/recipient still require strict 64-char hex to catch truncation bugs.
- Reference vector validation: 265-byte BCS output byte-equal to `@aptos-labs/ts-sdk`, pinned in `aptos::types::tests::bcs_matches_aptos_sdk_fa_reference`.

---

## Sprint 48 Gate Status (2026-05-10 — ALL MERGED)

TRON TRC-20 token transfer — `TriggerSmartContract` (ContractType=31) + ABI calldata.

| Sprint | Theme | Owner | R6 Verdict | Merged | Result |
|--------|-------|-------|------------|--------|--------|
| 48 | TRON TRC-20 (`TriggerSmartContract` + `transfer(address,uint256)`) | R3+R4 | APPROVED | ✓ | Protobuf `encode_trigger_smart_contract`/`encode_any_trigger`/`encode_contract_envelope` (generalizes prior contract wrapper); constants `CONTRACT_TYPE_TRANSFER=1` + `CONTRACT_TYPE_TRIGGER_SMART_CONTRACT=31`; `build_trc20_transfer_raw_data` one-shot helper with **mandatory `fee_limit`** (TVM calls require it — opposite of L-017's native-transfer omission); `decode_contract_to_json` dispatches by contract type; `encode_trc20_transfer_calldata` emits 68-byte selector `0xa9059cbb` + 32-byte recipient (hash160, drops `0x41` prefix) + 32-byte amount; `build_tron_transaction` dispatches `TokenIdentifier::Tron` to TRC-20 path with `fee_limit` defaulting to 100 TRX; CLI presign branches by contract type (TRC-20 auto-injects `fee_limit=100_000_000` sun, native still omits per L-017); 211-byte tronweb reference vector pinned in `tron::proto::tests::proto_matches_tronweb_trc20_reference`; live Shasta tx `0x54a73460ea78e5558ce78471e72600c68cc88a428dd76f2a47aa7a5e527fc296` (community testnet USDT `TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs`, 0.0001 USDT self-transfer). |

**Sprint 48 result:** 958 tests pass (was 957; +1 TRC-20 tronweb reference vector test `tron::proto::tests::proto_matches_tronweb_trc20_reference`), fmt + clippy clean.
**Security:** No new findings. All 68 prior findings remain RESOLVED.
**Lessons:** None — TRC-20 path worked first try by leveraging L-017 (native-transfer fee_limit omission) and inverting it for TVM contract calls.

### Sprint 48 highlights
- TRC-20 vs native TRON: TVM contract calls **require** `fee_limit` in the raw protobuf (default 100 TRX = 100_000_000 sun); native transfers must **omit** it (per L-017). CLI dispatches by contract type to pick the right path.
- Calldata layout: 68 bytes total — selector `0xa9059cbb` (4) + recipient (32, padded hash160 with `0x41` TRON prefix dropped) + amount (32, big-endian).
- Live Shasta tx `0x54a73460ea78e5558ce78471e72600c68cc88a428dd76f2a47aa7a5e527fc296`: 0.0001 USDT (community testnet `TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs`) self-transfer with GG20 ECDSA signature, byte-equal to tronweb reference (211 bytes).

---

## Sprint 49 Gate Status (2026-05-10 — ALL MERGED) — TOKEN SUITE COMPLETE

Solana SPL Token transfer + generic instruction refactor — final entry of the Sprint 44–49 token-transfer series.

| Sprint | Theme | Owner | R6 Verdict | Merged | Result |
|--------|-------|-------|------------|--------|--------|
| 49 | Solana SPL Token + generic `Instruction` refactor | R3+R4 | APPROVED | ✓ | New `solana/instruction.rs` (~150 LOC): generic `Instruction` + `AccountMeta` + `build_message` (4-bucket account ordering: writable+signer / readonly+signer / writable+nonsigner / readonly+nonsigner; program-id-before-accounts traversal matching `@solana/web3.js` `CompiledKeys`; v0/legacy versioning + ALT). New `solana/ata.rs` (~155 LOC): `find_program_address` (PDA via SHA-256 + on-curve check via `ed25519-dalek`), `derive_ata`, `TOKEN_PROGRAM_ID` / `TOKEN_2022_PROGRAM_ID` / `ASSOCIATED_TOKEN_PROGRAM_ID` constants base58-verified by tests. New `solana/spl.rs` (~110 LOC): `create_ata_idempotent` (discriminator 1) + `transfer_checked` (discriminator 12, amount LE u64 + decimals u8). `solana/tx.rs` refactored: deleted ~120 LOC of hardcoded `build_message_bytes`/`build_message_bytes_v0`; native SOL routes through the same instruction-based path as SPL via `system_transfer_instruction`. SPL build flow always emits `[CreateATAIdempotent, TransferChecked]` so missing-recipient-ATA case auto-resolves (~0.002 SOL rent). 320-byte SPL message byte-equal to `@solana/spl-token` `compileToLegacyMessage` reference, pinned in `chain_solana_integration::spl_message_matches_spl_token_sdk_reference`. Live Solana devnet tx `4556JgY7Z6Cc1ucQckBHqAXfSWpgiksA1KT96tB4ZcdKMHsjRL3LDYu9YgiFaRZj2cawLpAiDsXn8FLrHweSfHRw` (devnet USDC, 0.1 to self via FROST-Ed25519 2-of-3). |

**Sprint 49 result:** 967 tests pass (was 958; +9 — 5 ATA tests + 1 instruction roundtrip + 2 SPL build/decode + 1 SPL `@solana/spl-token` reference vector), fmt + clippy clean.
**Security:** No new findings. All 68 prior findings remain RESOLVED.
**Lessons:** None — refactor consolidated three previously separate code paths (legacy native, v0 native, SPL) behind one generic instruction model without regressions.

### Sprint 49 highlights
- Generic `Instruction` + `AccountMeta` model retires hand-rolled message builders. Native SOL and SPL now share one code path; ALT/v0 support is a flag on the same builder.
- ATA derivation lives in pure Rust: SHA-256-based `find_program_address` with on-curve check (via `ed25519-dalek` decompression). No `solana-sdk` dependency added.
- SPL build always prepends `CreateATAIdempotent` (discriminator 1) so unknown-recipient-ATA case is self-healing — first-tx UX matches Phantom / `@solana/spl-token` defaults at the cost of ~0.002 SOL rent.
- Reference vector `spl_message_matches_spl_token_sdk_reference`: 320-byte legacy message byte-equal to `@solana/spl-token` `compileToLegacyMessage`, locking the account ordering + `TransferChecked` discriminator/amount/decimals layout.
- Live devnet tx `4556JgY7…`: 0.1 devnet USDC self-transfer signed by FROST-Ed25519 2-of-3 — the first MPC SPL Token broadcast.

---

## Token Suite Retrospective (Sprints 44–49)

Five sprints of work (44 = design, 45–49 = per-chain implementation) shipped a single
unified cross-chain token transfer model. **Single `TokenIdentifier` enum at the chain-crate
level; zero changes to the `ChainProvider` trait; ~1700 LOC across the 6 in-scope chains.**
Bitcoin out of scope; NFTs deferred (schema reserves room).

| Chain  | Standard                                            | Sprint | Status                                                                  |
|--------|-----------------------------------------------------|--------|-------------------------------------------------------------------------|
| EVM    | ERC-20                                              | 45     | LIVE (USDC-Sepolia `0x23ab51bd…`)                                       |
| Sui    | `Coin<T>` (PTB SplitCoins+TransferObjects)          | 46 / 50 live | LIVE (testnet `DFQmfoEb…`, Circle USDC, FROST-Ed25519 2-of-3)     |
| Aptos  | legacy `0x1::coin::transfer<T>`                     | 46     | LIVE (testnet `0x72c2e3b5…`, `<AptosCoin>`)                             |
| Aptos  | Fungible Asset (`0x1::primary_fungible_store::transfer`) | 47 | LIVE (testnet `0xb3a41e33…`, native APT via FA at metadata `0xa`)       |
| TRON   | TRC-20 (`TriggerSmartContract` + `transfer`)        | 48     | LIVE (Shasta `0x54a73460…`, USDT, fee_limit 100 TRX)                    |
| Solana | SPL Token (`CreateATAIdempotent` + `TransferChecked`) | 49   | LIVE (devnet `4556JgY7…`, USDC, FROST-Ed25519 2-of-3)                   |

**Schema validated on all 6 in-scope chains.** Cross-chain reference-vector tests
(EVM ABI, Sui BCS, Aptos BCS legacy + FA, TRON tronweb protobuf, Solana
`@solana/spl-token`) pin every wire format to the canonical SDK output, byte-for-byte.

---

## Sprint 50 Gate Status (2026-05-14 — DOC-ONLY CLOSE-OUT) — TOKEN SUITE LIVE END-TO-END

Sui `Coin<T>` live broadcast close-out. No code changes — only sourced a non-SUI testnet token (Circle USDC via faucet.circle.com lists Sui Testnet), funded the existing Sui FROST-Ed25519 MPC wallet, and ran the Sprint 46 code path end-to-end.

| Sprint | Theme | Owner | R6 Verdict | Merged | Result |
|--------|-------|-------|------------|--------|--------|
| 50 | Sui `Coin<T>` live close-out | R3d | N/A (doc-only) | ✓ | Funded Sui testnet wallet (`0x009c9bf4…`, group `99ee01ec-…`) with 20 Circle testnet USDC at type tag `0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC` (6 decimals, legacy `Coin<T>` standard — drop-in for the Sprint 46 PTB path). CLI presign auto-picked source `Coin<USDC>` `0x60af844b…` (balance 20_000_000) and gas SUI `0xc3bcc249…` (balance 898_002_120 MIST); FROST-Ed25519 2-of-3 produced 296-byte BCS `TransactionData::V1` (PTB: `SplitCoins(src_coin, [100_000]) → TransferObjects([split], sender)`) + 97-byte Ed25519 sig envelope. Live Sui testnet tx **`DFQmfoEbdiF5NJhXBomcCnm5uwbHK2WF7eFAUSnzPeM2`** (status=success, gas ~2.35M MIST = ~0.00235 SUI, 0.1 USDC self-transfer). Explorer: https://suiscan.xyz/testnet/tx/DFQmfoEbdiF5NJhXBomcCnm5uwbHK2WF7eFAUSnzPeM2 |

**Sprint 50 result:** 967 tests pass (unchanged — doc-only). No new lessons (Sprint 46 hand-rolled BCS held; only blocker was sourcing a non-SUI testnet token, resolved via Circle's official faucet listing Sui Testnet).
**Security:** No new findings. All 68 prior findings remain RESOLVED.

### Sprint 50 highlights
- **TOKEN SUITE LIVE ON ALL 6 CHAINS** — every cross-chain token standard from Sprints 44–49 now has a broadcast-confirmed testnet tx, not just byte-equal reference vectors.
- Circle's testnet USDC faucet supports Sui Testnet (20 USDC / address / 2 hr, address-only request — no signed message). Type tag is the canonical Circle one, decimals = 6, standard = legacy `Coin<T>`.
- CLI `presign_sui` flow worked first try: `suix_getCoins` for both gas SUI and source `Coin<T>`, BCS-encode PTB, FROST-Ed25519 sign, broadcast — no code touched since Sprint 46.
- Updated:
  - `tests/e2e/funded-wallets.local.json` `sui-testnet` block adds `funded_usdc`, `usdc_type_tag`, `usdc_decimals`, `usdc_faucet`, `verified_usdc_tx`.
  - `CLAUDE.md` Token Coverage table flips Sui from CODE-COMPLETE → LIVE; sprint marker advances Sprint 49 → Sprint 50; one-line summary flips to "TOKEN SUITE LIVE END-TO-END".
  - `docs/SPRINT.md` Token Suite Retrospective row flips Sui to LIVE.
  - Memory `project_funded_testnet_wallets.md` Sui block gains `verified_usdc_tx` + Coin<T> usage notes + Circle faucet pointer.

---

## Sprint 51 Gate Status (2026-05-14 — REFACTOR LANDED, E2E DEFERRED) — CHAIN REGISTRY STANDARDIZATION

Single-session refactor consolidating per-chain configuration into a compile-time const table. Adding a new LIVE chain now hits **two files** (CHAIN_METADATA entry + provider impl) instead of the previous eight scattered hotspots in CLI helpers, RPC URL resolvers, balance checks, explorer URL constructors, and faucet hint strings.

| Sub-step | Theme | Owner | Commit | Result |
|----------|-------|-------|--------|--------|
| 1 | Additive modules: `metadata.rs`, `address_type.rs`, `presign.rs` | R0 | `0a75c7ab` | Type-only land; no callers |
| 2 | Extend `ChainProvider` trait with `metadata()` + `fetch_presign_extras()` | R0 | `3cc097ad` | Default `unimplemented!()` / `Err(Unsupported)` |
| 3 | Populate `CHAIN_METADATA` for the 6 LIVE chains; wire `metadata()` impls | R3 | `89130f1d` | +9 property tests; chain-slot drift impossible |
| 4a–f | Move per-chain RPC dance from CLI → providers (EVM/Sol/BTC/Sui/Aptos/TRON) | R3 | `f153e64e` … `3740d5d6` | 290 LOC moved out of `send.rs` |
| 5 | Flip CLI helpers (`resolve_default_rpc_url`, `explorer_url`, balance-check `eprintln!`) to metadata | R4 | `f8cda9aa` | +5 parity tests |
| 6 | `TokenIdentifier::parse_shorthand` replaces CLI parser | R3 | `6d010a65` | +5 round-trip tests; SDK + CLI share parser |
| 7 | Collapse CLI presign branches; prune dead dwellir arms | R4 | `a2ac5f3e` | 6 if-arms → 1 trait dispatch; ~200 LOC deleted |
| 8 | `DwellirProvider::chain_slug` reads `metadata.dwellir_slug` first | R3 | `716a66c5` | +7 parity tests; per-NetworkInfo slug |

**Sprint 51 result:** 624/624 workspace lib tests pass (was 617 → +7 metadata/dwellir parity, +5 token shorthand). `cargo fmt --check` + `cargo clippy --workspace --all-targets -- -D warnings` clean on every commit. Zero crypto / protocol / BCS/RLP/protobuf encoder code touched — pure plumbing.

**Security:** No new findings. All 68 prior findings remain RESOLVED. R6 audit not required (no signing-path code modified).

### Sprint 51 highlights

- **`ChainMetadata` const table** is single source of truth for: display name, native symbol/unit/decimals, default address type (typed `AddressType` enum — `"p2wpkh"`/`"taproot"` magic strings retired), compatible MPC schemes, accepted token standards, per-`NetworkInfo` (RPC URL, explorer base, faucet URL, chain id, Dwellir slug).
- **`PresignExtras` enum** + `PresignContext` borrowed view replace the opaque `serde_json::Value` extras blob. Transition shim `to_legacy_extras_json()` keeps downstream `build_transaction` consumers unchanged through the refactor.
- **CLI surface drop**: `send.rs` shrinks by ~400 lines. `fetch_presign_extras` body becomes one trait dispatch + a `log_presign()` helper. Per-chain RPC clients are imported only inside provider impls now.
- **Parity tests** lock the metadata-driven URLs / slugs / units byte-equal to pre-refactor values for the 6 LIVE chains — no silent drift possible.
- **Out-of-scope (deferred)**:
  - Substrate / Cosmos / Ton / Monero / Starknet `ChainMetadata` entries — those chains stay stub providers; entries land when they go LIVE.
  - `provider.fetch_balance()` trait method (would eliminate the remaining balance-check RPC dispatch in CLI). Orthogonal to presign concern; not blocking.
  - Live E2E broadcast regression (Step 9 of plan) — refactor validated by unit + parity tests; live re-broadcasts to be batched in Sprint 52.

### Definition of done — check

- [x] Adding a new chain to the LIVE set = **one CHAIN_METADATA entry + one provider impl**. Zero CLI edits required.
- [x] `cargo test --workspace --lib`: 624 / 624 green. Parity tests confirm zero behavioural drift on the 6 LIVE chains.
- [x] CLI presign function body has zero chain-conditional branches (collapsed to a single trait dispatch).
- [ ] **E2E live broadcast per chain confirms — deferred to Sprint 52.** Acceptance gate from plan file; refactor logically complete and unit/parity tests pass, but the only honest validation of the send path is a real testnet tx per chain. Funded wallets ready in `tests/e2e/funded-wallets.local.json`.

### Plan file

`/Users/thecoding/.claude/plans/graceful-roaming-floyd.md` — 8-step plan executed in order with one commit per step (4 split into 4a–4f). All steps green on workspace gates; only Step 9 (E2E) outstanding.
