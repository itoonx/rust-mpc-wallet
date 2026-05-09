# L-016: Aptos signing message is `prefix ‖ bcs`, not `SHA3-256(prefix ‖ bcs)` — and authenticator field order matters

- **Date:** 2026-05-10
- **Category:** Cryptographic correctness / chain-specific encoding
- **Severity:** High (silent — sig verifies locally, validator rejects)
- **Found by:** Sprint 42 — first Aptos testnet broadcast attempt returned `INVALID_SIGNATURE`

## What happened

Three sequential bugs blocked the first live Aptos testnet send. Each surfaced only because we kept iterating against the validator's actual error messages.

### Bug 1: authenticator field order + missing length prefix

The pre-existing `finalize_aptos_transaction` produced the trailing 98 bytes as
`0x00 ‖ sig(64) ‖ 0x20 ‖ pubkey(32)` — but Aptos's
`TransactionAuthenticator::Ed25519 { public_key, signature }` BCS-encodes as

```
0x00 (variant)
‖ 0x20 (Vec<u8> length=32)  ‖ pubkey(32)
‖ 0x40 (Vec<u8> length=64)  ‖ sig(64)
= 99 bytes
```

Pubkey comes **before** signature, and **both** are length-prefixed (BCS `Vec<u8>` shape because upstream's serde wraps `Ed25519PublicKey([u8; 32])` and `Ed25519Signature([u8; 64])` with `serializer.serialize_bytes(...)`). Off-by-one total length AND wrong field order. Same structural class as L-015 (Sui).

### Bug 2: SHA3-256 pre-hashing of the signing message

`build_aptos_transaction` was setting

```
sign_payload = SHA3-256(SHA3-256("APTOS::RawTransaction") ‖ BCS)
```

— a 32-byte digest. But Aptos doesn't sign that digest. Aptos signs the **raw message** `prefix ‖ bcs_bytes` (~197 bytes for a transfer). The SDK's `generateSigningMessage(bytes, "APTOS::RawTransaction")` returns the concatenation, NOT its SHA-256.

We were double-hashing: SHA3-256 on top, then Ed25519's internal SHA-512 on top of that. Local pre-broadcast `verify_aptos_signature` passed (because we verified against the same wrong digest we signed); Aptos validators recompute the canonical signing message and reject.

This is the same bug class as L-011 (GG20/CGGMP21 SHA-256 over keccak256 prehash) but in the opposite direction:

- **ECDSA (L-011)**: chain provider produces a 32-byte prehash; protocol must sign the prehash directly (skip its internal hash). Our fix: detect 32-byte input and bypass SHA-256.
- **Ed25519 (L-016)**: chain provider produces a raw message; protocol passes it to Ed25519 which does its own SHA-512 internally. Don't pre-hash the message — that adds a layer the validator doesn't undo.

### Bug 3: gas budget below per-tx minimum

Aptos rejects with `MAX_GAS_UNITS_BELOW_MIN_TRANSACTION_GAS_UNITS` (vm_error 14) when `max_gas_amount` is below the per-tx intrinsic floor. Our default of `2000` was below it. Bumped to `100_000` (unused gas is refunded by the validator).

## Root cause

For each Ed25519 chain we hand-roll:

1. The **wire format of the authenticator** must match the upstream serde wrapping byte-for-byte. Newtype-wrapped fixed-size arrays often serialize as length-prefixed `Vec<u8>` due to custom `serialize_bytes` impls. Always capture a reference vector for the full signed transaction (we'd already added `bcs_matches_aptos_sdk_reference` for the unsigned RawTransaction but not for the authenticator section).
2. **What the chain considers the "signing message"** is chain-specific. Sometimes it's a hash, sometimes a prefixed concatenation. Look at the validator's `verify` code, not just at "what the SDK puts into ed25519.sign".

## Fix

- `aptos/tx.rs::finalize_aptos_transaction`: emit `bcs ‖ 0x00 ‖ 0x20 ‖ pubkey ‖ 0x40 ‖ sig` = 99-byte authenticator.
- `aptos/tx.rs::build_aptos_transaction`: set `sign_payload = prefix ‖ bcs_bytes` (raw, not pre-hashed). Test asserts the sign payload starts with the SHA3-256("APTOS::RawTransaction") prefix.
- `send.rs::fetch_presign_extras` Aptos arm: `max_gas_amount = 100_000` default (was 2000).

## Takeaway

**Always capture a reference vector for the post-sign signed transaction**, not just the unsigned tx body. Sprint 41 (Sui) only validated unsigned BCS bytes; the authenticator wire format slipped through and we caught Sui's by reading spec docs. Sprint 42 spent a round-trip on the same class of issue. Going forward: every chain BCS test set should include a known-valid signed-tx reference vector with the authenticator/witness section spelled out.

For Ed25519 chains specifically: sign the raw signing message, not its hash — Ed25519 is "PureEdDSA" with internal SHA-512 hashing. ECDSA chains are the opposite (we sign a prehash). Making this distinction explicit per chain in the tx builder's docstring would have prevented this.

## Verification

- `cargo test --workspace --tests` → 938 pass.
- Live Aptos testnet broadcast: `0xce25a2b030770d77c993335617b1d94d71fbc83acd80c81f07ef3abf09e9902f` (https://explorer.aptoslabs.com/txn/0xce25a2b030770d77c993335617b1d94d71fbc83acd80c81f07ef3abf09e9902f?network=testnet).
- Wallet recorded in `tests/e2e/funded-wallets.local.json` and project memory.
