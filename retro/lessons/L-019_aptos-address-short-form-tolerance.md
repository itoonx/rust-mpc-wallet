# L-019: Aptos addresses have two conventions — strict and short — and framework constants use the short form

- **Date:** 2026-05-10
- **Category:** Address parsing / wire format
- **Severity:** Low (caught immediately on first FA broadcast attempt; non-silent)
- **Found by:** Sprint 47 — first live Aptos Fungible Asset broadcast

## What happened

Sprint 47's first live broadcast of a Fungible Asset transfer (APT routed
through `primary_fungible_store::transfer` with metadata `0xa`) failed
build with:

```
build_transaction: invalid input: Aptos address must be 0x + 64 hex chars
(32 bytes), got 1 hex chars
```

The strict address validator (`validate_aptos_address`) demanded exactly
64 hex characters after `0x`, but Aptos's canonical metadata for
APT-as-FA is `@0xa` — the framework's short-form convention.

## Root cause

Aptos uses two conventions for addresses simultaneously:

1. **Strict 64-char form** for *derived* addresses — wallet sender/
   recipient, account hashes, etc. These always come out as the full
   32-byte hex from key derivation.

2. **Short form** for *framework constants* — `@0x1` (the framework
   address), `@0xa` (canonical APT-as-FA metadata), `@0x4` (token
   v2 module). These are convention-pinned and conventionally written
   without leading zeros.

Aptos's own SDK (`@aptos-labs/ts-sdk`) accepts both forms transparently;
the strict-only validator on our end rejected anything not 64 chars.

The pre-existing `StructTag::parse` (Sprint 46, for Move type tags)
already had short-form-tolerant address parsing — same problem class —
but the FA metadata path used a different code path that kept the
strict validator.

## Fix

Added `parse_aptos_address_padded` in `aptos/tx.rs` — a tolerant parser
that left-pads to 32 bytes, mirroring `StructTag::parse`'s address
handling. Used only for *constants* (FA metadata, type-tag addresses)
where the short form is canonical. Sender/recipient continue to use
the strict 64-char validator since they always come out canonical
from address derivation.

The split is intentional: tolerating short forms in sender/recipient
parsing is the kind of thing that masks bugs (e.g. a user accidentally
truncates an address when copying — strict rejection catches it). For
framework constants there's no risk; the constants are canonical
short-form.

## Takeaway

**When a chain has a "framework constants" namespace separate from
derived addresses, it likely uses short-form for the former and strict
form for the latter — and you need both parsers, applied to the right
spots.**

This pattern likely repeats for upcoming chains:
- **Sui**: framework `0x1`, `0x2`, `0x3` (system addresses) appear in
  type tags but not in derived sender addresses. Already handled by
  Move type-tag parsing.
- **Solana**: program IDs are canonically 32-byte base58, but well-
  known programs (System, Token) are conventionally referenced by
  string ID — different problem class.
- **TRON**: addresses are uniformly base58check; no short form.
- **EVM**: 20-byte addresses are uniform. EIP-55 checksum is the
  separate concern.

## Verification

- 957 tests pass.
- Live Aptos FA broadcast:
  https://explorer.aptoslabs.com/txn/0xb3a41e3339db31111b8613442d895ffe2fc15615bd8624a821d52bc72b8f76f8?network=testnet
  (0.001 APT routed through `primary_fungible_store::transfer` with
  metadata=0xa — validates the FA path end-to-end).
- `tests/e2e/funded-wallets.local.json`
  `aptos-testnet.tokens.apt_via_fungible_asset` records the live tx.
