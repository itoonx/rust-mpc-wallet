# L-018: EVM `gas_limit` must come from `eth_estimateGas`, not from a hardcoded EOA default

- **Date:** 2026-05-10
- **Category:** RPC integration / fee estimation
- **Severity:** Medium (silent — local sig recovery passes, validator rejects with `intrinsic gas too low`)
- **Found by:** Sprint 45 — first live ERC-20 (USDC-Sepolia) MPC broadcast attempt

## What happened

Sprint 45 added ERC-20 support via the new `TokenIdentifier` schema. The
chain-level encoder, ABI calldata, and CLI plumbing all worked — local sig
recovery validated against the wallet's address. But the actual broadcast got:

```
Error: broadcast failed: eth_sendRawTransaction: intrinsic gas too low
```

The `evm/tx.rs::build_evm_transaction` path *did* set `default_gas_limit:
100_000` for ERC-20, but the auto-fetched extras from `fetch_presign_extras`
already contained `"gas_limit": 21_000` (the EOA-transfer floor we'd hardcoded
back in Sprint 38). The merging logic in build_transaction reads `extra
["gas_limit"]` first, so the 21k value silently won and the ERC-20 tx
under-bid intrinsic gas.

## Root cause

Two compounding issues:

1. **Single source of truth violated.** Both `fetch_presign_extras` and
   `build_evm_transaction` had opinions about the default gas_limit. The
   defaults were inconsistent (21k vs 100k) and the precedence wasn't
   documented. The fetch path always won because it ran first.

2. **No actual gas estimation.** `21_000` was a static "EOA floor" guess.
   It happens to be right for plain ETH transfers and wrong for *every other
   case* — contract calls, ERC-20, ERC-721, multisigs, anything that touches
   storage. We were one-shot guessing instead of asking the node.

## Fix

Two changes (Sprint 45 fix commit):

1. **Added `EvmRpcClient::estimate_gas`** wrapping `eth_estimateGas` —
   takes `(from, to, data, value)` and returns the node's estimated gas.

2. **Threaded the resolved token spec + recipient + value into
   `fetch_presign_extras`** so the EVM arm can construct the exact
   `(to, data, value)` tuple that will be signed and ask the node to
   estimate gas for *that specific call*. Result: `gas_limit = estimate *
   1.25` (25% safety margin), with a fallback of 21k for native / 100k for
   ERC-20 if the node refuses to estimate.

For the live broadcast: estimate came back at 40,707 gas (Sepolia USDC
transfer-to-self with non-zero existing balance). Margin → 50,883. Floor
→ 100,000. Final `gas_limit=100,000` (floor wins because the ERC-20
fallback is generous; for tighter packing in production we could lower
the floor to estimate * 1.25 directly).

## Takeaway

**For any chain whose native fee model includes a per-tx execution cap
(EVM gas, TRON energy, Solana compute units), the cap MUST be derived
from a live estimate against the real calldata.** Static defaults are
fine as fallbacks for when the estimate RPC is unavailable, but the
primary path should be dynamic.

Same pattern applies to the upcoming Sprints 46–49:
- **Sui**: `dryRunTransactionBlock` returns gas estimate; we currently
  hardcode `gas_budget: 10_000_000`. Should call dryRun before signing
  for tighter packing (and to catch reverting txs pre-MPC).
- **Aptos**: `simulate_transaction` returns gas_used; we hardcode
  `max_gas_amount: 100_000`. Same dryRun pattern.
- **TRON**: `triggersmartcontract` (the simulation endpoint, distinct
  from `triggerconstantcontract`) returns energy_used; for TRC-20
  Sprint 48 we'll call this and set `fee_limit = energy_used * energy_price`.
- **Solana**: compute units default to 200k per ix; for SPL we should
  prepend `ComputeBudgetProgram::SetComputeUnitLimit` based on a
  `simulateTransaction` call.

The general rule: **simulate first, sign second**. Catches reverting txs
pre-broadcast and gives tight fee packing simultaneously.

## Verification

- 951 tests pass.
- Live USDC-Sepolia transfer:
  https://sepolia.etherscan.io/tx/0x23ab51bde4db9e737f0f6039c21bf418f68147d230f9100119715643ceb090a9
  (0.1 USDC self-transfer; 40,707 gas used; sig recovers correctly).
- `tests/e2e/funded-wallets.local.json` `sepolia-test.tokens.usdc` records the live tx.
