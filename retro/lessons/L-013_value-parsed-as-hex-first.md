# L-013: build_evm_transaction parsed `value` as hex before decimal

- **Date:** 2026-05-07
- **Category:** Input parsing / silent semantic conversion
- **Severity:** High (silently turned 0.001 ETH into ~1.15 ETH)
- **Found by:** Geth "want 18.4 ETH" with the user passing `--value 1000000000000000`

## What happened

```rust
let value = U256::from_str_radix(params.value.trim_start_matches("0x"), 16)
    .or_else(|_| params.value.parse::<u128>().map(U256::from)...)
```

The first parse path was **base 16, no prefix required**. The user passed `1000000000000000` (intending 1×10¹⁵ wei = 0.001 ETH). `from_str_radix("1000000000000000", 16)` happily parsed it as `0x1000000000000000` = `2⁶⁰ ≈ 1.15 ETH`. The fallback decimal parse never fired because the hex parse succeeded.

The signed transaction's `value` field thus held ~1.15 ETH worth of wei. Combined with Sepolia's actual base fee, geth's required-balance check ballooned and reported "want 18.4 ETH" — masking the true cause (wrong value, not wrong gas).

## Root cause

Two related sins:

1. **Lenient parsing of mixed alphabets.** A bare decimal string like `1000000000000000` is also a valid hex string. Without a `0x` prefix to disambiguate, parsing as hex first is always wrong by default.
2. **Fallback chain in the wrong order.** `or_else` on `from_str_radix(_, 16)` only kicks in when the first parse *fails*. For any all-digit string, the first parse always succeeds, so the fallback is dead code.

## Fix

Decimal first, hex only with explicit `0x` prefix:

```rust
let value = if let Some(hex) = params.value.strip_prefix("0x") {
    U256::from_str_radix(hex, 16)?
} else {
    U256::from_str_radix(&params.value, 10)?
};
```

## Takeaway

When a string can mean two things (hex or decimal), **make the user disambiguate**. Don't try one and fall back. Default to the form humans type by default (decimal); require an explicit prefix for the other.

This pattern shows up beyond tx values: chain IDs, gas prices, nonces, hash digests in CLI args, JSON payloads. Same rule everywhere.

A useful test: **does this parser silently succeed on user input that wasn't meant for it?** If yes, it's broken — even if every individual character is legal in both encodings.
