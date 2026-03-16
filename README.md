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

EVM (22 chains) | Bitcoin | Solana | Sui | Aptos | Litecoin | Dogecoin | Zcash | Monero | 32 chains total

[![CI](https://github.com/itoonx/rust-mpc-wallet/actions/workflows/ci.yml/badge.svg)](https://github.com/itoonx/rust-mpc-wallet/actions/workflows/ci.yml)

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

## Quickstart

```bash
git clone https://github.com/itoonx/rust-mpc-wallet.git
cd rust-mpc-wallet

cargo test --workspace     # 272 tests, ~4 seconds
./scripts/demo.sh          # interactive end-to-end demo
```

---

## Features

| Category | Highlights |
|----------|-----------|
| **MPC Protocols** | GG20 ECDSA, FROST Ed25519, FROST Secp256k1-Taproot |
| **Key Lifecycle** | Keygen, refresh, reshare (change threshold/add parties), freeze |
| **32 Chains** | EVM L1/L2s, Bitcoin (Taproot), Solana, Sui, Aptos, Movement, LTC, DOGE, ZEC, XMR |
| **RPC Registry** | Multi-provider (Dwellir, Alchemy, Infura, Blockstream, Mempool), failover, health tracking |
| **Broadcast** | `eth_sendRawTransaction`, REST `/tx`, `sendTransaction`, `sui_executeTransactionBlock` |
| **Transport** | NATS mTLS + per-session ECDH + SignedEnvelope replay protection |
| **Enterprise** | RBAC, ABAC, MFA, policy engine, approval workflows, audit ledger |
| **Simulation** | Pre-sign risk scoring for all chains |
| **Operations** | Multi-cloud constraints, RPC failover, chaos framework, DR |

---

## Supported Blockchains (32)

| Category | Chains | Signing Protocol |
|----------|--------|-----------------|
| **EVM L1s** | Ethereum, Polygon, BSC | GG20 ECDSA (secp256k1) |
| **EVM L2s (P0)** | Arbitrum, Optimism, Base | GG20 ECDSA |
| **EVM L2s (P1)** | Avalanche, Linea, zkSync, Scroll | GG20 ECDSA |
| **EVM L2s (P2)** | Mantle, Blast, Zora, Fantom, Gnosis | GG20 ECDSA |
| **EVM L2s (P3)** | Cronos, Celo, Moonbeam, Ronin, OpBnb, Immutable, MantaPacific | GG20 ECDSA |
| **Bitcoin** | Bitcoin (Mainnet/Testnet) | FROST Schnorr (Taproot P2TR) |
| **UTXO** | Litecoin, Dogecoin, Zcash | GG20 ECDSA (secp256k1) |
| **Move** | Aptos, Movement | FROST Ed25519 |
| **Solana** | Solana | FROST Ed25519 |
| **Sui** | Sui | FROST Ed25519 |
| **CryptoNote** | Monero | FROST Ed25519 |

**RPC Providers:** Dwellir (all chains), Alchemy (ETH/Polygon/Arbitrum/Optimism/Base), Infura (ETH/Polygon/Arbitrum/Optimism/Base/Avalanche/Linea), Blockstream (Bitcoin REST), Mempool.space (Bitcoin REST), Custom

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

## Project Structure

```
crates/
  mpc-wallet-core/     ← MPC protocols, transport, key store, policy, identity
  mpc-wallet-chains/   ← Chain adapters: EVM (22), Bitcoin, Solana, Sui, Aptos, UTXO, Monero
  mpc-wallet-cli/      ← CLI binary
scripts/
  demo.sh              ← Interactive local demo (no external services)
docs/                  ← Architecture, security, CLI guide, sprint history
```

---

## Metrics

```
  Chains:    32          Tests:    272 pass
  LOC:       17,000+     CI:       fmt + clippy + test + audit
  Sprints:   17          Findings: 0 CRITICAL | 0 HIGH open
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
