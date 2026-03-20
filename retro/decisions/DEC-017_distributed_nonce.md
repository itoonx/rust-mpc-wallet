# DEC-017: GG20 Distributed Nonce Generation

- **Date:** 2026-03-20
- **Status:** Proposed
- **Context:** GG20 signing hardcodes Party 1 as coordinator (gg20.rs:525). Coordinator generates ephemeral nonce k, computes R = k·G, broadcasts (r, k_inv) to all signers, and assembles the final signature. If Party 1 is compromised, the attacker controls the nonce and can extract the full private key via lattice attack in as few as 2 signatures.

## Problem

Current GG20 signing flow:
1. Party 1 (coordinator) draws ephemeral nonce `k ∈ Z_n`
2. Party 1 computes `R = k·G`, extracts `r = R.x mod n`, computes `k_inv = k⁻¹ mod n`
3. Party 1 broadcasts `(r, k_inv)` to all signers
4. Each signer computes partial signature: `s_i = x_i_add · r · k_inv mod n`
5. Party 1 assembles: `s = hash · k_inv + Σ s_i mod n`

**Risk:** Party 1 alone knows `k`. A compromised Party 1 can:
- Choose biased nonces → extract private key via lattice attack (Howgrave-Graham & Smart)
- Reuse nonces across sessions → trivial key recovery
- This is the same class of vulnerability as the PlayStation 3 ECDSA break

## Options Considered

### Option 1: MtAwC (CGGMP21-style)
Each party generates k_i, uses Paillier MtA to compute shares of k without any party learning the full k.

- **Pro:** Strongest security — no party learns k
- **Pro:** Already have MtA infrastructure (Sprint 27b)
- **Con:** Requires 3 additional Paillier rounds per signing session
- **Con:** Adds ~2-5s of Paillier computation per sign (for 2048-bit keys)
- **Con:** Most complex to implement correctly

### Option 2: Commitment-Reveal Nonce (Recommended)
Each party generates k_i, commits to K_i = k_i·G (hash commitment), then reveals. R = Σ K_i. No single party knows full k.

**Protocol:**
1. Each party i generates k_i ∈ Z_n, computes K_i = k_i·G
2. Each party broadcasts commitment: `c_i = SHA-256(K_i || session_id || i)`
3. After ALL commitments received, each party reveals K_i
4. Each party verifies: `SHA-256(K_i || session_id || i) == c_i` for all peers
5. Compute R = Σ K_i (elliptic curve point addition)
6. Extract `r = R.x mod n`
7. Each party computes partial: `s_i = k_i⁻¹ · (hash + x_i_add · r) mod n`
8. Aggregate: `s = Σ s_i mod n`

- **Pro:** Simple — only 2 additional rounds (commit, reveal)
- **Pro:** No Paillier computation — pure ECC, fast (~ms)
- **Pro:** Standard technique — used by many production TSS implementations
- **Con:** Weaker than MtAwC if there's a rushing adversary (can adaptively choose k_i after seeing others' commitments, but commitment prevents this)
- **Con:** Each party learns K_j (the nonce share point) — acceptable because knowing K_j without k_j is computationally hard (ECDLP)

### Option 3: Random Coordinator Selection
Don't fix coordinator to Party 1 — rotate based on session_id hash.

- **Pro:** Simplest change — single line fix
- **Con:** Does NOT fix the core issue — whoever is coordinator still controls the nonce
- **Con:** Only makes the attack probabilistic, not impossible

## Decision

**Recommend Option 2: Commitment-Reveal Nonce**

Rationale:
1. Eliminates single-party nonce control completely
2. Only 2 additional transport rounds (vs 3+ for MtAwC)
3. No Paillier dependency — works for both GG20 and future protocols
4. Well-understood security model with hash commitments
5. Implementation effort: ~200 lines (commitment scheme + 2 rounds of broadcast/collect)

## Implementation Sketch

```
Round 1 (existing):  Share polynomial + Lagrange coefficients
Round 2 (new):       Broadcast nonce commitments  c_i = H(K_i || sid || i)
Round 3 (new):       Broadcast nonce reveals       K_i
                     Verify all commitments
                     Compute R = Σ K_i, r = R.x mod n
Round 4 (existing):  Partial signatures s_i = k_i⁻¹(hash + x_i_add·r) mod n
                     Aggregate s = Σ s_i mod n
```

**Impact on existing protocol:**
- GG20 keygen: unchanged
- GG20 signing: +2 rounds, removes coordinator role entirely
- Every party now computes full signature (not just coordinator)
- `MpcSignature` returned by every party (not just Party 1)
- Tests: remove "coordinator must be Party 1" constraint (L-009)

## Security Properties

| Property | Before (Party 1 coordinator) | After (commitment-reveal) |
|----------|------------------------------|---------------------------|
| Nonce bias | Party 1 can bias | Impossible (commitment binding) |
| Nonce reuse | Party 1 can reuse | Requires hash collision |
| Nonce knowledge | Party 1 knows full k | No party knows full k |
| Rounds | 2 | 4 (+2 for commit/reveal) |
| Computation | 1 EC scalar mul + 1 inversion | n EC point additions + SHA-256 |

## Consequences

- All existing GG20 signing tests must be updated (remove Party 1 coordinator assumption)
- Non-coordinator parties will now return real signatures (not sentinel 0xff)
- Backward incompatible — old clients cannot sign with new protocol (versioning needed)
- Performance: ~1ms additional per sign (negligible vs Paillier keygen)

## Status

- [ ] R7 review + human approval
- [ ] Implementation (Sprint 30)
- [ ] R6 security audit
- [ ] Update L-009 (coordinator limitation → resolved)
