# L-014: FROST-Secp256k1-TR doesn't apply BIP-341 key tweak

- **Date:** 2026-05-07
- **Category:** Cryptographic correctness / spec gap
- **Severity:** High (blocked Bitcoin Taproot live tx)
- **Found by:** Sprint 40 audit before Bitcoin testnet send

## What happened

Plan was to ship Bitcoin Taproot (P2TR) signing with the existing `FrostSecp256k1TrProtocol`. The `bitcoin/address.rs::derive_taproot_address` function uses `Address::p2tr(secp, internal_key, None, network)` which applies the BIP-341 tweak: `output_key = internal_key + H_taptweak(internal_x_only) · G`.

The MPC protocol, however, signs with the **untweaked** group key: a Schnorr signature whose `R · G + e · P_internal` equation never references the tweak `t`. Bitcoin nodes verify against the **tweaked output key** in the previous output's `script_pubkey`, so the signature would fail validation — every live Bitcoin tx using this code path would be rejected before the bug surfaced as a "want huge fee" or "have 0" symptom.

We caught it without burning faucet funds because the Sprint 38 retro instilled the habit of checking each chain's recovery/verification path before a live tx.

## Root cause

`FrostSecp256k1TrProtocol` was written to the FROST spec (RFC 9591-style Schnorr over secp256k1) but the BIP-341 tap-tweak was never added in either keygen output or in the signing equation. Search:
- No `tap_tweak`, `taproot`, `BIP-341`, `TaggedHash`, or `tweaked` references anywhere under `crates/mpc-wallet-core/src/protocol/`.

Two viable places to apply the tweak:
1. **Keygen output**: derive a tweaked group pubkey and tweaked secret-share offsets, store both, sign with tweaked share. Cleanest but rewrites part of keygen.
2. **Per-sign**: at the start of `sign`, accept the merkle root + internal key, compute `t`, adjust `s = (k - e·(d + t)) mod n` and the signing key. Smaller change, but every Bitcoin caller has to know to pass the merkle root.

## Fix (Sprint 40, partial)

Skipped Taproot for now. **Default Bitcoin path is P2WPKH (native SegWit) signed with GG20-ECDSA**, which has no tweak issue: the script_pubkey is `OP_0 0x14 <HASH160(compressed_pubkey)>` and the signature verifies against the un-tweaked compressed pubkey directly via BIP-143.

- `BitcoinProvider::derive_address` → `derive_p2wpkh_address` (was `derive_taproot_address`)
- `BitcoinProvider::build_transaction` routes by `extra["addr_type"]` (default `p2wpkh`, fallback `taproot`)
- `BitcoinProvider::finalize_transaction` routes by sig variant (`Ecdsa` → P2WPKH, `Schnorr` → Taproot)
- `ChainRegistry::compatible_schemes(BitcoinTestnet)` reordered — `Gg20Ecdsa` first, `FrostSecp256k1Tr` last

Live Bitcoin testnet tx broadcast verified (sprint-40 commit, mempool.space confirmed).

## Takeaway

For any chain that uses key derivation with a tweak (Taproot, BIP-32 hardened paths, Stealth-style commitments), the **tweak must live inside the MPC protocol** — not as a post-hoc adjustment in the chain layer, and not invisibly inside the address-derivation library.

Audit step that would have caught this earlier: for each `MpcSignature`-producing scheme + each chain, confirm that the address derivation's pubkey is *exactly* the pubkey the signature verifies against. Mismatches mean a tweak is missing somewhere.

Future Sprint 50+ will add BIP-341 tweak support to `FrostSecp256k1TrProtocol` so Taproot signing works end-to-end.
