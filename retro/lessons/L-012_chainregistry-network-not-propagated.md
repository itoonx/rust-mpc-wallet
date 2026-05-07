# L-012: ChainRegistry::default_testnet() didn't reach EvmProvider's chain_id

- **Date:** 2026-05-07
- **Category:** Configuration correctness
- **Severity:** High (every testnet EVM tx silently used mainnet chain_id)
- **Found by:** Sepolia "invalid chain ID" rejection at `eth_sendRawTransaction`

## What happened

```rust
let registry = ChainRegistry::default_testnet();           // env = Testnet
let provider = registry.provider(Chain::Ethereum)?;        // ← bug here
provider.build_transaction(params).await?;                 // chain_id = 1 !
```

`ChainRegistry::provider` constructed `EvmProvider` via `EvmProvider::new(chain)` which had a hardcoded mainnet chain-ID table. The registry's `env: NetworkEnv::Testnet` was visible to the registry but never passed into the provider constructor. Result: every Sepolia tx was built with `chain_id = 1`, which Sepolia's geth rejected with "invalid chain ID".

The displayed message `chain_id=11155111` in the CLI was the value we **fetched from `eth_chainId`** — not the value we put into the tx. Two different code paths.

## Root cause

`EvmProvider::new(chain) -> Result<Self>` was a single-network constructor that hardcoded mainnet IDs. There was no second constructor (or argument) for testnet IDs. `ChainRegistry::provider()` knew the network env but had no way to pass it.

## Fix

- Added `EvmProvider::for_network(chain, env: &NetworkEnv) -> Result<Self>` with full testnet chain-ID table (Sepolia 11155111, Amoy 80002, Base Sepolia 84532, Arb Sepolia 421614, Op Sepolia 11155420, Fuji 43113, Linea Sepolia 59141, BSC testnet 97).
- `ChainRegistry::provider()` now calls `EvmProvider::for_network(chain, &self.env)` for all EVM chains.

## Takeaway

**A registry that knows network env must propagate it to every constructor it builds.** Any "config" pulled into one layer of the stack but not threaded through to the layer that actually emits values is a future bug.

Specific anti-pattern to watch for: a registry/factory that has rich state internally but builds providers via a simpler constructor that doesn't accept that state. Either narrow the registry, or widen the constructor.

Generalized rule: **every constructor that produces a network-bound artifact must take the network as a typed argument.** No `EvmProvider::new(chain)` without `env`. Same applies to RPC clients, fee oracles, address derivation paths (BIP-44 coin types differ between mainnet/testnet for some chains), and explorer URL formatters.
