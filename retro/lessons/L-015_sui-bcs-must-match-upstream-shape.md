# L-015: Sui BCS struct shape must match upstream byte-for-byte, and raw_tx must carry both body + sig

- **Date:** 2026-05-10
- **Category:** Cryptographic correctness / chain-specific encoding
- **Severity:** High (silent — sig verifies locally, validator rejects)
- **Found by:** Sprint 41 — pre-Sprint audit flagged the wrong-shape struct; live testnet broadcast surfaced the second half of the bug

## What happened

Two related bugs blocked the first live Sui testnet send.

### Bug 1: hand-rolled BCS struct didn't match `TransactionData::V1` enum

The pre-existing `crates/mpc-wallet-chains/src/sui/tx.rs` defined a flat `SuiTransferPayload { sender, recipient, amount, reference }` and BCS-encoded *that* as the signing payload. The 18 unit tests passed because they only verified our internal round-trip — encode → decode → encode produces identical bytes — never against an external reference.

Sui validators actually decode signed bytes against:

```rust
enum TransactionData { V1(TransactionDataV1) }
struct TransactionDataV1 {
    kind: TransactionKind,           // enum, ProgrammableTransaction is variant 0
    sender: SuiAddress,
    gas_data: GasData,               // payment refs + price + budget
    expiration: TransactionExpiration,
}
```

…with `TransactionKind::ProgrammableTransaction` containing nested `Vec<CallArg>` + `Vec<Command>` for the actual transfer logic (SplitCoins + TransferObjects). The hand-rolled struct's first byte (`sender[0]`) was being interpreted as the V1 variant index, then `sender[1]` as the TransactionKind variant, and so on — gibberish from the first byte.

Caught by *not* trusting our own tests. Wrote `scripts/sui-ref-vector.mjs` (Node.js + `@mysten/sui` SDK) that builds the canonical `transferSui` PTB with deterministic inputs and prints the BCS hex. Hardcoded that 219-byte hex as a constant, asserted byte-for-byte equality in `bcs_matches_mysten_sdk_reference`. Replaced the struct, fixed one off-by-one (`ObjectDigest` is BCS `Vec<u8>` length-prefixed, not a fixed `[u8; 32]`), and the test went green.

### Bug 2: `raw_tx` was the signature alone, not body + signature

Sui's `sui_executeTransactionBlock` RPC takes two base64 args: `txBytes` (BCS-encoded `TransactionData`) and `[signatures]`. The `SuiProvider::broadcast` recovered them by slicing `raw_tx` at `len() - 97`:

```rust
let sig_offset = signed.raw_tx.len() - 97;
let tx_bytes = &signed.raw_tx[..sig_offset];   // BCS body
let sig_bytes = &signed.raw_tx[sig_offset..];  // 97-byte sig
```

But `finalize_sui_transaction` was writing only the 97-byte serialized signature into `raw_tx`. So `sig_offset = 0`, `tx_bytes = &[]`, and Sui returned `Deserialization error: unexpected end of input` because it tried to BCS-decode an empty buffer into `TransactionData`.

Fix: store `raw_tx = bcs_bytes ‖ [0x00 ‖ sig(64) ‖ pubkey(32)]`. Two finalize tests asserted `raw_tx.len() == 97` — updated to slice the trailing 97 bytes for the same flag/sig/pubkey checks, with an additional `len() > 97` invariant.

## Root cause

Both bugs share a root cause: **internal-only round-trip tests don't catch wire-format drift**. Our 18 Sui integration tests all looked like:

```rust
let unsigned = build_sui_transaction(...).unwrap();
let signed = finalize(&unsigned, &sig).unwrap();
assert_eq!(signed.raw_tx.len(), 97); // tests our convention, not Sui's
```

They never compared against output from a tool the validators actually trust. Once we wrote a JS script with the official SDK and asserted byte-equal output, both bugs surfaced inside an hour.

## Fix

- New module `crates/mpc-wallet-chains/src/sui/types.rs` — full `TransactionData::V1` enum tree, variants in upstream declaration order (verified), with a `transfer_sui` helper that builds the canonical SplitCoins+TransferObjects PTB.
- `tx.rs` rewritten to BCS-encode the new `TransactionData` and pack `raw_tx = bcs_bytes ‖ serialized_sig`.
- `scripts/sui-ref-vector.mjs` committed alongside `scripts/package.json` so the reference vector is reproducible — anyone can `node scripts/sui-ref-vector.mjs` to regenerate the hex if Sui upgrades the wire format.
- Two new unit tests — `bcs_matches_mysten_sdk_reference` (byte-equal) and `bcs_roundtrip_idempotent`.

## Takeaway

For any chain where we hand-roll the wire format (Bitcoin, Solana, Sui, future Cosmos/Tron/TON):

1. **Always have an upstream reference vector.** A committed script that calls the chain's official SDK and prints canonical bytes for a deterministic input. Hardcode the output as a unit test constant. If the chain upgrades, regenerate.
2. **Test at the boundary, not just internally.** Round-trip-encode tests prove our code is consistent with itself; they prove nothing about validator compatibility. The boundary is the BCS bytes the chain decodes — not the `unsigned.tx_data` we pass to ourselves.
3. **Watch for length-prefixing on byte arrays.** `[u8; N]` and `Vec<u8>` BCS-encode differently. When upstream uses a "newtype around `[u8; 32]` with custom serde that calls `serialize_bytes`", that's BCS `Vec<u8>` shape, not raw bytes. The 1-byte length prefix is the easiest variant index to miss.
4. **`raw_tx` is the validator's input, not ours.** If our broadcast path slices it (`raw_tx[..len-97]` etc.), `finalize` must produce that exact layout. Don't have one function think `raw_tx = sig` and another think `raw_tx = body ‖ sig` — pick one, document it on `SignedTransaction.raw_tx` per chain, and unit-test both sides agree.

## Verification

- `cargo test --workspace --tests` → 936 pass (929 baseline + 5 new EVM/Bitcoin tests from earlier sprints + 2 new Sui BCS tests, with 7 pre-existing Sui round-trip tests updated to use the new gas-extras helper).
- Live Sui testnet broadcast: tx `C9pp3etLRF2TUVcPv6LHCR1aQ4H8raA59JpSbNLu3ay1` (https://suiscan.xyz/testnet/tx/C9pp3etLRF2TUVcPv6LHCR1aQ4H8raA59JpSbNLu3ay1).
- Wallet recorded in `tests/e2e/funded-wallets.local.json` and project memory.
