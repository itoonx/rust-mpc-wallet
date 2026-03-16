<div align="center">

```
          ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗███████╗██╗  ██╗
          ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██╔════╝╚██╗██╔╝
          ██║   ██║███████║██║   ██║██║     ██║   █████╗   ╚███╔╝
          ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██╔══╝   ██╔██╗
           ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ███████╗██╔╝ ██╗
            ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝
                   Your keys. Distributed. Unstoppable.
```

**Threshold MPC Wallet SDK** — No single party ever holds a complete private key.

EVM (26) | Bitcoin | Polkadot | Solana | Sui | Aptos | TON | TRON | Cosmos | Starknet | 50 chains

[![CI](https://github.com/itoonx/vaultex-mpc-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/itoonx/vaultex-mpc-rust/actions/workflows/ci.yml)

[English](README.md) | [中文](README.zh-CN.md)

</div>

---

## What is Vaultex?

Vaultex is a **Rust workspace** for building enterprise-grade **threshold multi-party computation (MPC) wallets**. The full private key is **never assembled** in memory — not during key generation, not during signing, not ever.

```
                    ┌─────────┐
                    │  Party 1 │ ← holds share s₁
                    └────┬────┘
                         │
   ┌─────────┐      ┌───┴───┐      ┌─────────┐
   │  Party 2 │──────│  NATS  │──────│  Party 3 │
   │  share s₂│      │  mTLS  │      │  share s₃│
   └─────────┘      └───┬───┘      └─────────┘
                         │
                    ┌────┴────┐
                    │ Signature│ ← valid ECDSA/Schnorr/EdDSA
                    │  (r, s)  │   full key x never computed
                    └─────────┘
```

**Why Vaultex?**

- **Zero single point of failure** — compromise 1 server, attacker gets nothing
- **Multi-chain** — 32 blockchains: EVM L1s & L2s, Bitcoin, Solana, Sui, Aptos, Litecoin, Dogecoin, Zcash, Monero
- **Enterprise controls** — RBAC, policy engine, approval workflows, audit trail
- **Proactive security** — key refresh rotates shares without changing addresses

---

## Documentation

| Document | Description |
|----------|-------------|
| **[CLI Guide](docs/CLI_GUIDE.md)** | Full command reference with examples and sample output |
| **[Architecture](docs/ARCHITECTURE.md)** | System design, trait boundaries, module map |
| **[Security](docs/SECURITY.md)** | Threat model, resolved findings, disclosure policy |
| **[Contributing](docs/CONTRIBUTING.md)** | Guide for humans and LLMs/AI agents |
| **[Changelog](CHANGELOG.md)** | Version history and release notes |
| **[Chain Roadmap](docs/CHAIN_ROADMAP.md)** | 54-chain expansion plan: EVM L2s, Move, Substrate, TON, Cosmos |
| **[Standards & References](docs/STANDARDS.md)** | All cryptographic standards, RFCs, EIPs, BIPs implemented |
| **[Security Findings](docs/SECURITY_FINDINGS.md)** | Full audit trail (0 CRITICAL/HIGH open) |

---

## Quickstart

```bash
git clone https://github.com/itoonx/vaultex-mpc-rust.git
cd vaultex-mpc-rust

cargo test --workspace     # 325 tests, ~4 seconds
./scripts/demo.sh          # interactive end-to-end demo
```

---

## Features

| Category | Highlights |
|----------|-----------|
| **MPC Protocols** | GG20 ECDSA, FROST Ed25519, FROST Schnorr, Sr25519, STARK, BLS12-381 |
| **Key Lifecycle** | Keygen, refresh, reshare (change threshold/add parties), freeze |
| **50 Chains** | EVM L1/L2s, Bitcoin, Solana, Sui, Aptos, Movement, TON, TRON, LTC, DOGE, ZEC, XMR |
| **RPC Registry** | Multi-provider (Dwellir, Alchemy, Infura, Blockstream, Mempool), failover, health tracking |
| **Broadcast** | `eth_sendRawTransaction`, REST `/tx`, `sendTransaction`, `sui_executeTransactionBlock` |
| **Transport** | NATS mTLS + per-session ECDH + SignedEnvelope replay protection |
| **Enterprise** | RBAC, ABAC, MFA, policy engine, approval workflows, audit ledger |
| **Simulation** | Pre-sign risk scoring for all chains |
| **Operations** | Multi-cloud constraints, RPC failover, chaos framework, DR |

---

## Supported Blockchains (32)

### EVM Chains (26)

| Chain | Chain ID | Type | Dwellir | Alchemy | Infura |
|-------|----------|------|:-------:|:-------:|:------:|
| Ethereum | `1` | L1 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Polygon | `137` | L1 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| BSC | `56` | L1 | :white_check_mark: | | |
| Arbitrum | `42161` | L2 (Optimistic) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Optimism | `10` | L2 (OP Stack) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Base | `8453` | L2 (OP Stack) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Avalanche | `43114` | L1 (C-Chain) | :white_check_mark: | | :white_check_mark: |
| Linea | `59144` | L2 (zkEVM) | :white_check_mark: | | :white_check_mark: |
| zkSync Era | `324` | L2 (ZK Rollup) | :white_check_mark: | | |
| Scroll | `534352` | L2 (zkEVM) | :white_check_mark: | | |
| Mantle | `5000` | L2 (Modular) | :white_check_mark: | | |
| Blast | `81457` | L2 (Yield) | :white_check_mark: | | |
| Zora | `7777777` | L2 (OP Stack) | :white_check_mark: | | |
| Fantom | `250` | L1 (DAG) | :white_check_mark: | | |
| Gnosis | `100` | L1 (xDai) | :white_check_mark: | | |
| Cronos | `25` | L1 | :white_check_mark: | | |
| Celo | `42220` | L1 (Mobile) | :white_check_mark: | | |
| Moonbeam | `1284` | Parachain (EVM) | :white_check_mark: | | |
| Ronin | `2020` | L1 (Gaming) | :white_check_mark: | | |
| opBNB | `204` | L2 (BNB) | :white_check_mark: | | |
| Immutable | `13371` | L2 (zkEVM) | :white_check_mark: | | |
| Manta Pacific | `169` | L2 (Privacy) | :white_check_mark: | | |
| Hyperliquid | `999` | L1 (Perps DEX) | :white_check_mark: | | |
| Berachain | `80094` | L1 (PoL) | :white_check_mark: | | |
| MegaETH | `6342` | L2 (Real-time) | :white_check_mark: | | |
| Monad | `143` | L1 (Parallel EVM) | :white_check_mark: | | |

> All EVM chains use **GG20 ECDSA (secp256k1)** signing protocol and **EIP-1559** transaction format.

### UTXO Chains (5)

| Chain | Address Format | Signing | Dwellir | Blockstream | Mempool |
|-------|---------------|---------|:-------:|:-----------:|:-------:|
| Bitcoin (Mainnet) | Taproot P2TR (`bc1p...`) | FROST Schnorr (BIP-340) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Bitcoin (Testnet) | Taproot P2TR (`tb1p...`) | FROST Schnorr (BIP-340) | | :white_check_mark: | :white_check_mark: |
| Litecoin | P2PKH (`L...`) / bech32 (`ltc1...`) | GG20 ECDSA | :white_check_mark: | | |
| Dogecoin | P2PKH (`D...`) | GG20 ECDSA | :white_check_mark: | | |
| Zcash | Transparent (`t1...`) | GG20 ECDSA | :white_check_mark: | | |

### Move Chains (2)

| Chain | Address Format | Signing | Dwellir |
|-------|---------------|---------|:-------:|
| Aptos | `0x` + 64 hex (SHA3-256) | FROST Ed25519 | :white_check_mark: |
| Movement | `0x` + 64 hex (SHA3-256) | FROST Ed25519 | :white_check_mark: |

### Substrate / Polkadot (6)

| Chain | Address (SS58) | Signing | Dwellir |
|-------|---------------|---------|:-------:|
| Polkadot | SS58 prefix 0 | FROST Ed25519 | :white_check_mark: |
| Kusama | SS58 prefix 2 | FROST Ed25519 | :white_check_mark: |
| Astar | SS58 prefix 5 | FROST Ed25519 | :white_check_mark: |
| Acala | SS58 prefix 10 | FROST Ed25519 | :white_check_mark: |
| Phala | SS58 prefix 30 | FROST Ed25519 | :white_check_mark: |
| Interlay | SS58 prefix 2032 | FROST Ed25519 | :white_check_mark: |

> Supports both FROST Ed25519 and **Sr25519 threshold MPC** (Schnorrkel on Ristretto255).

### Cosmos / IBC (5)

| Chain | Address (bech32) | Signing | Dwellir |
|-------|-----------------|---------|:-------:|
| Cosmos Hub | `cosmos1...` | GG20 ECDSA (secp256k1) | :white_check_mark: |
| Osmosis | `osmo1...` | GG20 ECDSA (secp256k1) | :white_check_mark: |
| Celestia | `celestia1...` | GG20 ECDSA / Ed25519 | :white_check_mark: |
| Injective | `inj1...` | GG20 ECDSA (secp256k1) | :white_check_mark: |
| Sei | `sei1...` | GG20 ECDSA (secp256k1) | :white_check_mark: |

### Alt L1s (2)

| Chain | Address Format | Signing | Dwellir |
|-------|---------------|---------|:-------:|
| TON | `0:` + 64 hex (SHA-256) | FROST Ed25519 | :white_check_mark: |
| TRON | Base58Check (`T...`, 0x41 prefix) | GG20 ECDSA (secp256k1) | :white_check_mark: |

### Specialized (1)

| Chain | Address Format | Signing | Dwellir |
|-------|---------------|---------|:-------:|
| Starknet | `0x` + 64 hex (251-bit field) | STARK curve (planned) | :white_check_mark: |

> STARK curve threshold MPC signing now available via `StarkProtocol`.

### Other Chains (3)

| Chain | Address Format | Signing | Dwellir |
|-------|---------------|---------|:-------:|
| Solana | Base58 (Ed25519) | FROST Ed25519 | :white_check_mark: |
| Sui | `0x` + 64 hex (Blake2b-256) | FROST Ed25519 | :white_check_mark: |
| Monero | Base58 (spend + view key) | FROST Ed25519 | :white_check_mark: |

> RPC Registry supports **failover** (auto-switch on unhealthy), **health tracking** per endpoint, **per-chain config** (timeout, retries), and **custom providers**.

---

## MPC Signing Protocols (6)

| Protocol | Curve | Chains | Crate |
|----------|-------|--------|-------|
| **GG20 ECDSA** | secp256k1 | EVM (26), TRON, Cosmos (5), UTXO (3) | `k256` |
| **FROST Schnorr** | secp256k1 | Bitcoin (Taproot P2TR) | `frost-secp256k1-tr` |
| **FROST Ed25519** | Ed25519 | Solana, Sui, Aptos, Movement, TON, Monero | `frost-ed25519` |
| **Sr25519 Threshold** | Ristretto255 | Polkadot, Kusama, Astar, Acala, Phala, Interlay | `schnorrkel` |
| **STARK Threshold** | Stark curve | Starknet | custom |
| **BLS12-381 Threshold** | BLS12-381 | Filecoin, Ethereum validators | `blst` |

> All protocols support threshold key generation and distributed signing — the full private key is **never** assembled.

---

## Performance

| Operation | Latency | Config |
|-----------|---------|--------|
| GG20 Keygen | **44 µs** | 2-of-3, local transport |
| GG20 Sign | **188 µs** | 2 signers |
| ChaCha20 Encrypt 1KB | **4 µs** | per-message |
| AES-256-GCM 1KB | **5 µs** | key store |
| Argon2id Derive | **72 ms** | 64MiB (intentional) |

Run benchmarks: `cargo bench -p mpc-wallet-core --bench mpc_benchmarks`

---

## Project Structure

```
crates/
  mpc-wallet-core/     ← MPC protocols, transport, key store, policy, identity
  mpc-wallet-chains/   ← Chain adapters: 50 chains (EVM, Bitcoin, Substrate, Move, Cosmos, UTXO, TON, TRON, Starknet, Monero)
  mpc-wallet-cli/      ← CLI binary
scripts/
  demo.sh              ← Interactive local demo (no external services)
docs/                  ← Architecture, security, CLI guide, sprint history
```

---

## Metrics

```
  Chains:    50          Tests:     325 pass
  Protocols: 6           CI:        fmt + clippy + test + audit
  Sprints:   20          Findings:  0 CRITICAL | 0 HIGH open
```

---

## License

MIT

---

<p align="center">
  <sub>
    Built with <a href="https://claude.com/claude-code">Claude Code</a> by a team of AI agents.
    <br/>
    No keys were harmed in the making of this SDK.
  </sub>
</p>
