# Chain Support Roadmap

Blockchain networks to support for RPC broadcast via [Dwellir](https://www.dwellir.com/docs/getting-started/supported-chains).

> RPC Provider: **Dwellir** — single API key, HTTPS + WebSocket, archive nodes available.

---

## Current Support (v0.1.0)

| Chain | Type | Signing | Tx Building | Simulation | Broadcast |
|-------|------|---------|-------------|------------|-----------|
| Ethereum | EVM | GG20 ECDSA | EIP-1559 | Risk scoring | Planned |
| Polygon | EVM | GG20 ECDSA | EIP-1559 | Risk scoring | Planned |
| BSC | EVM | GG20 ECDSA | EIP-1559 | Risk scoring | Planned |
| Bitcoin | UTXO | FROST Schnorr | Taproot P2TR | Fee/dust check | Planned |
| Solana | SVM | FROST Ed25519 | Legacy + v0 | Program allowlist | Planned |
| Sui | Move | FROST Ed25519 | BCS intent | Gas budget check | Planned |

---

## Phase 1 — EVM L2s & Rollups (High Priority)

These chains are **EVM-compatible** — can reuse existing `EvmProvider` with minimal changes (just chain_id + RPC URL).

| Chain | Networks | Chain ID | Priority | Notes |
|-------|----------|----------|----------|-------|
| **Arbitrum** | Mainnet, Sepolia | 42161 | P0 | Top L2 by TVL |
| **Optimism** | Mainnet, Sepolia | 10 | P0 | OP Stack leader |
| **Base** | Mainnet, Sepolia | 8453 | P0 | Coinbase L2, growing fast |
| **Avalanche** | C-Chain | 43114 | P1 | Subnet architecture |
| **Linea** | Mainnet, Sepolia | 59144 | P1 | ConsenSys zkEVM |
| **zkSync Era** | Mainnet | 324 | P1 | ZK rollup |
| **Scroll** | Mainnet | 534352 | P1 | zkEVM |
| **Starknet** | Mainnet, Sepolia | — | P2 | Cairo VM (non-EVM tx format) |
| **Mantle** | Mainnet, Sepolia | 5000 | P2 | Modular L2 |
| **Blast** | Mainnet, Sepolia | 81457 | P2 | Native yield L2 |
| **Zora** | Mainnet, Sepolia | 7777777 | P2 | NFT-focused L2 |
| **Fantom / Sonic** | Mainnet | 250 | P2 | DAG-based EVM |
| **Gnosis** | Mainnet, Chiado | 100 | P2 | xDai stable payments |
| **Cronos** | Mainnet | 25 | P3 | Crypto.com chain |
| **Celo** | Mainnet, Alfajores | 42220 | P3 | Mobile-first |
| **Moonbeam** | Mainnet | 1284 | P3 | Polkadot EVM |
| **Ronin** | Mainnet, Saigon | 2020 | P3 | Gaming (Axie) |
| **opBNB** | Mainnet | 204 | P3 | BNB L2 |
| **Immutable** | Mainnet | 13371 | P3 | Gaming zkEVM |
| **Manta Pacific** | Mainnet | 169 | P3 | Privacy L2 |

**Implementation:** Add chain_id to `ChainRegistry`, configure Dwellir RPC URL. No new `ChainProvider` code needed.

---

## Phase 2 — Move Chains

| Chain | Networks | Signing | Priority | Notes |
|-------|----------|---------|----------|-------|
| **Aptos** | Mainnet | Ed25519 | P1 | Move VM, similar to Sui but different tx format |
| **Movement** | Mainnet | Ed25519 | P2 | Move-based L2 on Ethereum |

**Implementation:** New `AptosProvider` — BCS encoding (like Sui) but different tx structure, different address format (32-byte hex). Ed25519 signing reuses FROST Ed25519.

---

## Phase 3 — Substrate / Polkadot Ecosystem

| Chain | Networks | Signing | Priority | Notes |
|-------|----------|---------|----------|-------|
| **Polkadot** | Mainnet | Sr25519 / Ed25519 | P1 | Relay chain |
| **Kusama** | Mainnet | Sr25519 / Ed25519 | P1 | Canary network |
| **Astar** | Mainnet, Shibuya | Sr25519 + EVM | P2 | Multi-VM parachain |
| **Acala** | Mainnet | Sr25519 | P2 | DeFi hub |
| **Moonbeam** | Mainnet | ECDSA (EVM) | P2 | Already EVM — Phase 1 |
| **Phala** | Mainnet | Sr25519 | P3 | Privacy compute |
| **Interlay** | Mainnet | Sr25519 | P3 | BTC bridge |

**Implementation:** New `SubstrateProvider` — SCALE encoding, extrinsic format, Sr25519 signing (need new `Sr25519Protocol` or use ed25519 where supported). Significant new code.

---

## Phase 4 — Alternative L1s

| Chain | Networks | Signing | Priority | Notes |
|-------|----------|---------|----------|-------|
| **TON** | Mainnet, Testnet | Ed25519 | P1 | Telegram ecosystem, 900M+ users |
| **TRON** | Mainnet | ECDSA secp256k1 | P2 | USDT dominant chain |
| **Cosmos / IBC** | Various | secp256k1 / Ed25519 | P2 | Tendermint + IBC protocol |
| **Filecoin** | Mainnet | secp256k1 + BLS | P3 | Storage network |
| **Bittensor** | Mainnet, Testnet | Sr25519 | P3 | AI network |
| **Aleph Zero** | Mainnet, Testnet | Sr25519 | P3 | Privacy L1 |

---

## Phase 5 — Specialized & Emerging

| Chain | Networks | Type | Priority | Notes |
|-------|----------|------|----------|-------|
| **Starknet** | Mainnet | Cairo/STARK | P2 | Non-EVM tx, STARK proofs |
| **Hyperliquid** | Mainnet | EVM (custom) | P2 | Perps DEX chain |
| **Berachain** | Mainnet | EVM | P2 | Proof of Liquidity |
| **MegaETH** | Mainnet | EVM | P3 | Real-time EVM |
| **Monad** | Mainnet | EVM | P3 | Parallel EVM |

---

## Implementation Effort Matrix

| Category | Chains | New Code | Signing | Effort |
|----------|--------|----------|---------|--------|
| **EVM L2s** | ~20 chains | Chain ID + RPC only | Existing GG20 ECDSA | **Low** — days |
| **Move (Aptos)** | 2 chains | New tx builder, BCS variant | Existing FROST Ed25519 | **Medium** — 1-2 weeks |
| **Substrate** | ~15 chains | New SCALE encoding, extrinsic format | New Sr25519 or Ed25519 | **High** — 2-4 weeks |
| **TON** | 1 chain | New TL-B encoding, cell format | Existing FROST Ed25519 | **Medium** — 1-2 weeks |
| **TRON** | 1 chain | Protobuf tx, similar to EVM signing | Existing GG20 ECDSA | **Low-Medium** — 1 week |
| **Cosmos** | ~10 chains | Amino/Protobuf encoding, IBC | Existing ECDSA/Ed25519 | **Medium** — 2 weeks |
| **Starknet** | 1 chain | Cairo-specific tx, STARK sig | New STARK protocol | **Very High** — 4+ weeks |

---

## Signing Protocol Coverage

| Protocol | Curve | Chains Covered |
|----------|-------|---------------|
| **GG20 ECDSA** | secp256k1 | All EVM (~25), TRON, Cosmos (secp256k1) |
| **FROST Schnorr** | secp256k1 | Bitcoin (Taproot) |
| **FROST Ed25519** | Ed25519 | Solana, Sui, Aptos, TON, Cosmos (ed25519) |
| **Sr25519** (future) | Ristretto | Polkadot, Kusama, Substrate chains |
| **STARK** (future) | Stark curve | Starknet |
| **BLS** (future) | BLS12-381 | Filecoin, Ethereum validators |

---

## Dwellir RPC Integration Plan

### Configuration

```rust
// Future ChainRegistry with Dwellir RPC
let registry = ChainRegistry::new()
    .with_rpc_provider(DwellirConfig {
        api_key: "your-api-key",
        base_url: "https://rpc.dwellir.com",
    })
    .register_evm(Chain::Arbitrum, 42161)
    .register_evm(Chain::Optimism, 10)
    .register_evm(Chain::Base, 8453);

// Broadcast transaction
let provider = registry.provider(Chain::Arbitrum)?;
let signed_tx = provider.finalize_transaction(&unsigned, &sig)?;
provider.broadcast(signed_tx).await?;  // → Dwellir RPC
```

### Required Changes

1. **`ChainProvider` trait** — add `async fn broadcast(&self, tx: SignedTransaction) -> Result<TxHash, CoreError>`
2. **`ChainRegistry`** — accept RPC config (URL + API key) per chain
3. **HTTP client** — add `reqwest` dependency for RPC calls
4. **EVM broadcast** — `eth_sendRawTransaction` via JSON-RPC
5. **Bitcoin broadcast** — `sendrawtransaction` via JSON-RPC
6. **Solana broadcast** — `sendTransaction` via JSON-RPC
7. **Sui broadcast** — `sui_executeTransactionBlock` via JSON-RPC

---

## Summary

| Phase | Chains | Timeline | Prerequisite |
|-------|--------|----------|-------------|
| **Current** | 6 (ETH, Polygon, BSC, BTC, SOL, SUI) | Done | — |
| **Phase 1** | +20 EVM L2s | 1-2 weeks | Chain ID registry |
| **Phase 2** | +2 Move (Aptos, Movement) | 2-3 weeks | New AptosProvider |
| **Phase 3** | +15 Substrate | 3-5 weeks | New SubstrateProvider + Sr25519 |
| **Phase 4** | +6 Alt L1s (TON, TRON, Cosmos...) | 3-4 weeks | Per-chain tx format |
| **Phase 5** | +5 Specialized | 4-6 weeks | New signing protocols |
| **Total** | **~54 chains** | ~3-4 months | — |
