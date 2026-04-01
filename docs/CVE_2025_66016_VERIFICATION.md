# CVE-2025-66016 Verification Report

> Auditor: R6 Security | Verification date: 2026-04-01

## CVE Summary

| Field | Value |
|-------|-------|
| **ID** | CVE-2025-66016 (GHSA-m95p-425x-x889) |
| **CVSS** | 9.3 (Critical) |
| **Affected** | CGGMP21 implementations that skip Pimod and/or Pifac verification during keygen |
| **Attack** | Single malicious signer generates a Paillier key N with known small factors, passes it to honest parties unverified. During MtA pre-signing, the attacker uses knowledge of phi(N) to decrypt Paillier ciphertexts and extract honest parties' secret shares. After ~16 signing sessions, the full private key is recovered. |
| **Impact** | Complete private key extraction by a single malicious party (threshold security violated) |

## Verification Result: NOT AFFECTED

The Vaultex MPC Wallet SDK is **not affected** by CVE-2025-66016. Both Pimod and Pifac ZK proofs are generated and verified for all peers during CGGMP21 keygen. Legacy shares without real Paillier keys are unconditionally rejected at pre-signing time.

## Evidence

### 1. Both proofs generated during keygen

File: `crates/mpc-wallet-core/src/protocol/cggmp21.rs`, lines 972-974

```rust
// Generate Pimod and Pifac ZK proofs
let pimod_proof = prove_pimod(&n_big, &p_big, &q_big);
let pifac_proof = prove_pifac(&n_big, &p_big, &q_big);
```

Proofs are generated using the real BigUint primes from `keypair_for_protocol()`, which enforces a minimum of 2048 bits (SEC-054). The proofs are broadcast alongside the Paillier public key in Round 4 (`AuxInfoBroadcast`).

### 2. Both proofs verified for ALL peers

File: `crates/mpc-wallet-core/src/protocol/cggmp21.rs`, lines 1012-1033

```rust
for aux in &all_aux {
    if aux.party_index == my_index {
        continue; // Skip self (we trust our own key)
    }
    let peer_n = aux.paillier_pk.n_biguint();

    // Verify Pimod: N is a Blum integer
    if !verify_pimod(&peer_n, &aux.pimod_proof) {
        return Err(CoreError::Protocol(format!(
            "Pimod proof verification failed for party {} -- identifiable abort",
            aux.party_index
        )));
    }

    // Verify Pifac: N has no small factors (CVE-2023-33241 prevention)
    if !verify_pifac(&peer_n, &aux.pifac_proof) {
        return Err(CoreError::Protocol(format!(
            "Pifac proof verification failed for party {} -- identifiable abort",
            aux.party_index
        )));
    }
}
```

Verification is mandatory. Failure is a hard error that triggers identifiable abort (the cheating party is named in the error). Self-skip only -- every party verifies every other party's proofs.

### 3. verify_pimod soundness

File: `crates/mpc-wallet-core/src/paillier/zk_proofs.rs`, lines 334-375

- 80 rounds of the 4th-root Blum integer proof (CGGMP21 Figure 28).
- Jacobi symbol check on w: ensures N = p * q where p, q are both 3 mod 4 (Blum integer property).
- Fiat-Shamir challenge derived from N with length-prefixed encoding (TSSHOCK-hardened).

### 4. verify_pifac soundness

File: `crates/mpc-wallet-core/src/paillier/zk_proofs.rs`, lines 646-708

- Trial division against all primes up to 2^20 -- independent of proof data (verifier's own computation).
- `p_bits + q_bits` cross-check against `N.bits()` -- detects degenerate factorizations.
- Fiat-Shamir challenge uses deterministic `pifac-challenge-v3` domain separator (SEC-060 fix removed vestigial commitment).

### 5. N_i binding: verified key used in MtA

File: `crates/mpc-wallet-core/src/protocol/cggmp21.rs`, lines 1036-1038

```rust
let all_paillier_pks: Vec<PaillierPublicKey> =
    all_aux.iter().map(|a| a.paillier_pk.clone()).collect();
```

The verified `all_paillier_pks` vector is stored in `Cggmp21ShareData` immediately after proof verification (lines 1036-1038). During pre-signing, MtA encryption uses these same stored keys (line 1362: `let peer_pk = &all_pks[peer_pk_idx]`). There is no code path that re-fetches Paillier keys from peers -- the verified keys are the only keys used.

### 6. No bypass path

File: `crates/mpc-wallet-core/src/protocol/cggmp21.rs`, lines 1225-1234, 1753-1761

The `has_real_paillier` flag is checked at the start of pre-signing:

```rust
let has_real_paillier = share_data.real_paillier_pk.is_some()
    && share_data.real_paillier_sk.is_some()
    && share_data.all_paillier_pks.is_some();
```

If `has_real_paillier` is true, all ZK proofs (Pienc, PiAffg, PiLogstar) are mandatory -- the code requires real Pedersen parameters (`has_real_aux_info()` check at line 1242).

If `has_real_paillier` is false, the else branch (line 1753) unconditionally rejects:

```rust
return Err(CoreError::Protocol(
    "CGGMP21 pre-signing requires real Paillier keys \
     -- run key refresh to upgrade legacy shares"
        .into(),
));
```

There is no simulated MtA fallback, no test-only bypass, no feature-gated exception. Legacy shares are dead code.

### 7. Paillier key size enforcement (SEC-054)

File: `crates/mpc-wallet-core/src/paillier/keygen.rs`

`keypair_for_protocol()` enforces a runtime assertion that production Paillier keys are at least 2048 bits. This prevents an attacker from attempting to use a smaller key that might be easier to factor.

## Additional Hardening

Beyond the core CVE-2025-66016 mitigations, the following defense-in-depth measures are in place:

1. **TSSHOCK-hardened Fiat-Shamir** (CVE-2022-47931): All proof challenges use `hash_update_lp()` length-prefixed encoding to prevent alpha-shuffle collisions.
2. **Session binding** (CVE-2022-47930): `session_id` and `prover_index` are bound into Pienc, PiAffg, and PiLogstar challenge hashes, preventing cross-session and cross-party proof replay.
3. **PiAffg EC binding** (SEC-056): The `commitment_bx` in PiAffg is a real EC point (`alpha * G`), included in the Fiat-Shamir hash, with the verifier checking `z1 * G == Bx + e * X`.
4. **Mandatory ZK proofs during pre-signing**: Pienc, PiAffg, and PiLogstar proofs are required from all peers during MtA. Missing proofs cause identifiable abort.

## Conclusion

The Vaultex MPC Wallet SDK correctly implements both Pimod and Pifac proof generation and verification as specified in CGGMP21. The attack described in CVE-2025-66016 is not possible against this implementation because:

1. A malicious party cannot skip proof generation (proofs are included in Round 4 broadcast).
2. All honest parties verify both proofs for all peers (hard error on failure).
3. The verified Paillier public key is the same key used in subsequent MtA operations (no re-fetch).
4. Legacy shares without real Paillier keys are unconditionally rejected (no fallback path).
5. Paillier keys are enforced to be at least 2048 bits at generation time.
