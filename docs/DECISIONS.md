# MPC Wallet SDK — Decision Log

**Maintained by:** R7 PM Agent  
**Format:** newest first within each DEC-NNN entry

---

## DEC-001: Real GG20 vs. Alternative ECDSA TSS Library

- **Date:** 2026-03-15
- **Context:** The current `gg20.rs` signing implementation reconstructs the full private key via
  Lagrange interpolation before signing with `k256::ecdsa::SigningKey`. This is a fatal security
  flaw for production custody: any party completing the sign round can recover the full key.
  We must replace it with a genuinely distributed signing protocol where no party ever holds the
  full secret scalar.

- **Options considered:**

  1. **`multi-party-ecdsa` (Zengo, GG20/CGGMP21)**
     - *What it is:* The gold-standard open-source MPC-ECDSA library. Implements the full GG20
       protocol (Gennaro–Goldfeder 2020) and the newer CGGMP21 variant. Used in production by
       Zengo wallet, many institutional custodians.
     - *Security:* Battle-tested; formal proof in the GG20 paper. No single-party secret
       reconstruction. Nonce commitment + decommitment prevents nonce-reuse attacks.
     - *Complexity:* High. Multi-round protocol (2 rounds for keygen, 5+ for signing). Requires
       Paillier encryption, range proofs, commitment schemes. The `curv` / `curv-kzen` dependency
       is a heavy transitive tree (~50 crates).
     - *Timeline:* L-XL — full integration is 3–5 weeks of careful work. Risk of version
       conflicts with `k256` 0.13 (Zengo's curv uses an older API).
     - *Compatibility:* Full secp256k1 ECDSA — exactly what EVM and Bitcoin ECDSA require.
     - *Verdict:* Correct and battle-tested, but high integration risk due to dependency
       conflicts and complexity.

  2. **FROST secp256k1-tr (ZF FROST) for ECDSA**
     - *What it is:* FROST (Flexible Round-Optimized Schnorr Threshold) on secp256k1 with
       Taproot signatures. Already in the workspace (`frost-secp256k1-tr`).
     - *Security:* Formally proven, actively maintained by the Zcash Foundation.
     - *Complexity:* Low — already partially integrated.
     - *Timeline:* Already started; could be production-ready in 1–2 weeks.
     - *Compatibility:* **Fatal flaw — Schnorr, not ECDSA.** Ethereum, Polygon, BSC, Arbitrum
       all require secp256k1 ECDSA (EIP-2098 / EIP-155). FROST secp256k1-tr produces Schnorr /
       BIP-340 signatures. These are incompatible with `ecrecover` in EVM smart contracts and
       with standard Ethereum wallet tooling. Cannot use for EVM chains.
     - *Verdict:* Correct for Bitcoin Taproot; unusable for EVM. Not a solution for GG20.

  3. **`threshold_crypto` (Dfinity BLS)**
     - *What it is:* Dfinity's BLS threshold signature library on BLS12-381 curve.
     - *Security:* Production-grade for BLS; Dfinity uses it in IC nodes.
     - *Complexity:* Moderate, but entirely different API from what is currently in the codebase.
     - *Timeline:* High migration cost — would require rewriting all key share formats.
     - *Compatibility:* **Fatal flaw — BLS12-381, not secp256k1.** BLS signatures cannot be
       verified by EVM `ecrecover`. Incompatible with Bitcoin, Ethereum, Solana.
     - *Verdict:* Wrong curve for this use case. Ruled out.

  4. **Keep simulated GG20 + add `// SIMULATION` disclaimer**
     - *What it is:* Mark the current implementation as simulation-only; gate it behind a
       `#[cfg(feature = "simulation")]` flag; block production builds.
     - *Security:* Explicitly not production-safe. Any compiled production binary that uses
       this path has a critical key-reconstruction vulnerability.
     - *Complexity:* Zero immediate work.
     - *Timeline:* Zero. But real GG20 is deferred, accumulating technical debt.
     - *Verdict:* Acceptable only as a transitional measure while real GG20 is being integrated.
       The simulation flag approach has value: it lets all other parts of the system be tested
       while the real protocol is being built.

  5. **Two-round distributed ECDSA via k256 primitives (custom)**
     - *What it is:* Implement a simplified but cryptographically sound distributed signing
       protocol directly using `k256` elliptic curve operations, without the full GG20 machinery.
       Each signer contributes a partial nonce `r_i` and a partial scalar `s_i`; the coordinator
       aggregates them. Based on Lindell 2017 / Doerner–Kondi–Lee–shelat two-party variant.
     - *Security:* Cryptographically sound if implemented correctly (no Paillier needed for
       2-of-n if using additive shares of the nonce). Requires careful nonce handling to avoid
       bias. Must be reviewed by R6 before production.
     - *Complexity:* Medium — ~200 lines of careful elliptic curve math in `k256`.
     - *Timeline:* M (1–2 weeks). Already have `k256` in workspace. No new dependencies.
     - *Compatibility:* Full secp256k1 ECDSA.
     - *Verdict:* Best risk/reward for Sprint 1. Avoids dependency conflicts. Custom code
       means R6 must audit it carefully.

- **Decision:** **Option 5 first, then Option 1 in Sprint 2.**

  Sprint 1 R1 implements a two-round distributed ECDSA using `k256` primitives — specifically
  using additive secret sharing of the signing nonce `k` (each party holds `k_i` such that
  `sum(k_i) = k`; combining partial `s_i` values gives the final `s` without any party
  knowing `k` or the full secret `x`). Gate the old simulation behind
  `#[cfg(feature = "gg20-simulation")]`.

  In Sprint 2, evaluate whether `multi-party-ecdsa` dependency conflicts can be resolved and
  migrate to the full GG20 protocol for the security properties of the Paillier-based version
  (malicious-secure vs. semi-honest-secure).

- **Rationale:**
  - Eliminates the key-reconstruction flaw immediately with no new crate dependencies.
  - Custom k256 implementation can be reviewed by R6 in the same sprint.
  - Avoids the 3–5 week integration risk of `multi-party-ecdsa` dependency conflicts.
  - The simulated GG20 flag ensures existing tests continue to pass while the new protocol
    is being wired up.

- **Affected agents:** R1 (implements), R6 (audits), R0 (may need to add `gg20-simulation`
  feature flag to `Cargo.toml`)

- **Follow-up tasks:**
  - T-01 (R1): Implement two-round distributed ECDSA
  - Sprint 2: Evaluate `multi-party-ecdsa` v0.7 for full GG20 upgrade
  - R6: Security review of T-01 output before sprint close

---

## DEC-002: Solana Transaction Approach

- **Date:** 2026-03-15
- **Context:** R3c has already replaced the original JSON stub with a manual binary serialization
  that follows the Solana legacy transaction wire format (`tx.rs` v2). This is a significant
  improvement. The question is: should we add the Solana SDK as a dependency for validation
  and/or as the production serializer, or maintain the manual implementation?

- **Options considered:**

  1. **Add `solana-sdk` crate (full SDK)**
     - *What it is:* The official Solana client SDK. Includes `Message`, `Transaction`,
       `Instruction`, `Pubkey`, all serialization, and RPC client.
     - *Fidelity:* Perfect — any serialization it produces is definitionally correct.
     - *Dependency cost:* Very high — `solana-sdk` transitively pulls in ~300 crates including
       `reqwest`, `openssl`, `hyper`, `tokio`, custom `solana-*` crates. Adds ~50MB to the
       dependency tree.
     - *Version conflicts:* High risk — Solana SDK pins specific versions of `tokio`, `serde`,
       `rand` that may conflict with workspace versions. Known conflicts with `k256` 0.13 exist
       in older Solana SDK versions.
     - *SDK consumer impact:* Anyone who `cargo add mpc-wallet-chains` gets ~300 transitive
       crates in their build. This is a deal-breaker for many SDK consumers.
     - *Verdict:* Too heavy for production dependency. Acceptable as dev-dependency for tests only.

  2. **Manual binary serialization (current approach — keep and harden)**
     - *What it is:* Hand-written serialization of the Solana legacy transaction format in
       `tx.rs`. The layout (header, account keys, recent blockhash, instructions) is manually
       implemented following the Solana spec.
     - *Fidelity:* Currently appears correct based on spec inspection. Not validated against SDK.
     - *Dependency cost:* Zero new crates. Lightweight.
     - *SDK consumer impact:* None. Already-present `bs58`, `serde_json`, `hex` crates.
     - *Maintenance risk:* Manual serialization must be kept in sync with any future Solana
       wire-format changes. Solana has been stable on the legacy format for years; v0 versioned
       transactions are a separate format that will be added in a future story.
     - *Verdict:* Best for production dependency cost. Must be validated with SDK-based tests.

  3. **`solana-program` crate only (lighter than full SDK)**
     - *What it is:* The on-chain program crate — contains `Pubkey`, `AccountMeta`,
       `Instruction`, and `Message` types but not the full RPC/client machinery.
     - *Dependency cost:* Medium — ~60 crates (significantly less than `solana-sdk`).
     - *Fidelity:* Contains the canonical types; can be used to validate message deserialization.
     - *Conflict risk:* Lower than `solana-sdk` but still pins some crate versions.
     - *Verdict:* Good as dev-dependency for test validation. Too heavy for production dependency.

- **Decision:** **Option 2 (manual serialization) as production code + Option 3 (`solana-program`)
  as dev-dependency for test validation only.**

  Production path: keep the manual binary serialization in `tx.rs`. It is already implemented
  and appears correct.

  Test path: add `solana-program` as a `[dev-dependencies]` entry (not `[workspace.dependencies]`)
  so it does not appear in the production dependency tree. Use `Message::deserialize` from
  `solana-program` in tests to validate the manual serializer output field-by-field.

- **Rationale:**
  - Keeps the production dependency tree minimal — critical for SDK adoption.
  - Validates correctness through SDK-based tests without bloating production builds.
  - The manual serializer is already written and works; adding tests is lower-risk than
    a full SDK migration.
  - If Solana changes the wire format (unlikely for legacy format), the test immediately
    catches it.

- **Affected agents:** R3c (implements test), R0 (approve `solana-program` dev-dep addition)

- **Follow-up tasks:**
  - T-07 (R3c): Add SDK-based validation tests for manual Solana serializer
  - R0: Approve `solana-program = "1.18"` in `crates/mpc-wallet-chains/Cargo.toml`
    `[dev-dependencies]` (NOT in workspace — to avoid forcing it on all crates)

---

## DEC-003: Sui Transaction Serialization Library

- **Date:** 2026-03-15
- **Context:** R3d's `tx.rs` uses a JSON blob as `tx_data` / `tx_bytes`. The Sui protocol
  requires BCS-encoded `TransactionData`. The `bcs` crate provides BCS serialization;
  the question is whether to use the full Sui SDK or a lightweight approach.

- **Options considered:**

  1. **Add `sui-sdk` / `sui-types` crate**
     - *Dependency cost:* Extremely high — the Sui SDK pulls in hundreds of crates, custom
       `move-*` language crates, and has complex version pinning.
     - *Fidelity:* Perfect — the exact types used on-chain.
     - *Conflict risk:* Very high. Sui SDK is not designed for embedding in other Cargo workspaces.
     - *Verdict:* Ruled out. Unacceptable for an SDK meant to be `cargo add`-friendly.

  2. **`bcs` crate + manually-defined transaction struct**
     - *What it is:* Use the `bcs` crate (lightweight BCS serializer, ~5 crates) and define a
       minimal `SuiTransactionData` struct in `sui/tx.rs` that matches the required on-chain
       layout for a simple SUI transfer.
     - *Fidelity:* High — BCS is deterministic and the struct field order determines encoding.
       The Sui spec for `TransactionData` v1 is documented and stable for simple transfers.
     - *Dependency cost:* Minimal — `bcs = "0.1"` is a tiny crate.
     - *Maintenance risk:* Must be kept in sync with Sui protocol changes. Covered by tests.
     - *Verdict:* Best approach. Same strategy used successfully by many Sui toolkits.

  3. **Keep JSON stub + add `bcs` encoding in a follow-up sprint**
     - *Verdict:* Acceptable for dev/test but cannot ship to production. Sprint 1 must fix this.

- **Decision:** **Option 2 — `bcs` crate + minimal manually-defined structs.**

- **Rationale:**
  - `bcs` is the correct, well-specified serializer for the Sui wire format.
  - Minimal structs keep the implementation auditable and the dependency tree light.
  - The current sign_payload computation (Blake2b-256 of intent_prefix || tx_bytes) is already
    correct; only the format of `tx_bytes` changes from JSON to BCS.

- **Affected agents:** R3d (implements), R0 (approve `bcs = "0.1"` addition to workspace)

- **Follow-up tasks:**
  - T-06 (R3d): Implement BCS transaction serialization
  - R0: Add `bcs = "0.1"` to `[workspace.dependencies]` in root `Cargo.toml`
  - R6: Verify BCS struct layout matches on-chain spec before sprint close
