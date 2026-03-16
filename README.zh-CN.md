<div align="center">

```
          ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗███████╗██╗  ██╗
          ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██╔════╝╚██╗██╔╝
          ██║   ██║███████║██║   ██║██║     ██║   █████╗   ╚███╔╝
          ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██╔══╝   ██╔██╗
           ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ███████╗██╔╝ ██╗
            ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝
                   你的密钥。分布式。不可阻挡。
```

**门限 MPC 钱包 SDK** — 没有任何一方持有完整的私钥。

EVM（22 条链）| Bitcoin | Solana | Sui | Aptos | Litecoin | Dogecoin | Zcash | Monero | 共 32 条链

[![CI](https://github.com/itoonx/vaultex-mpc-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/itoonx/vaultex-mpc-rust/actions/workflows/ci.yml)

[English](README.md) | [中文](README.zh-CN.md)

</div>

---

## Vaultex 是什么？

Vaultex 是一个用 **Rust** 构建的企业级**门限多方计算 (MPC) 钱包 SDK**。完整的私钥**永远不会**在内存中被还原 — 无论是密钥生成、签名还是任何时候。

```
                    ┌─────────┐
                    │  参与方 1 │ ← 持有份额 s₁
                    └────┬────┘
                         │
   ┌─────────┐      ┌───┴───┐      ┌─────────┐
   │  参与方 2 │──────│  NATS  │──────│  参与方 3 │
   │  份额 s₂  │      │  mTLS  │      │  份额 s₃  │
   └─────────┘      └───┬───┘      └─────────┘
                         │
                    ┌────┴────┐
                    │  签名    │ ← 有效的 ECDSA/Schnorr/EdDSA
                    │  (r, s)  │   完整密钥 x 从未被计算
                    └─────────┘
```

**为什么选择 Vaultex？**

- **零单点故障** — 攻破一台服务器，攻击者什么也得不到
- **多链支持** — 32 条区块链：EVM L1 和 L2、Bitcoin、Solana、Sui、Aptos、Litecoin、Dogecoin、Zcash、Monero
- **企业级管控** — RBAC 权限、策略引擎、审批流程、审计追踪
- **主动安全** — 密钥刷新可在不更改链上地址的情况下轮换份额

---

## 文档

| 文档 | 说明 |
|------|------|
| **[CLI 指南](docs/CLI_GUIDE.md)** | 完整命令参考，含示例和输出样例 |
| **[架构](docs/ARCHITECTURE.md)** | 系统设计、Trait 边界、模块导图 |
| **[安全](docs/SECURITY.md)** | 威胁模型、已修复漏洞、漏洞披露政策 |
| **[贡献指南](docs/CONTRIBUTING.md)** | 面向开发者和 LLM/AI Agent 的贡献指南 |
| **[更新日志](CHANGELOG.md)** | 版本历史和发布说明 |
| **[链支持路线图](docs/CHAIN_ROADMAP.md)** | 54 条链扩展计划：EVM L2、Move、Substrate、TON、Cosmos |
| **[标准与参考](docs/STANDARDS.md)** | 所有密码学标准、RFC、EIP、BIP 参考文献 |
| **[安全审计](docs/SECURITY_FINDINGS.md)** | 完整审计追踪（0 个 CRITICAL/HIGH 未解决） |

---

## 快速开始

```bash
git clone https://github.com/itoonx/vaultex-mpc-rust.git
cd vaultex-mpc-rust

cargo test --workspace     # 272 个测试，约 4 秒
./scripts/demo.sh          # 交互式端到端演示
```

---

## 功能特性

| 类别 | 亮点 |
|------|------|
| **MPC 协议** | GG20 ECDSA、FROST Ed25519、FROST Secp256k1-Taproot |
| **密钥生命周期** | 生成、刷新、重分享（修改阈值/增删参与方）、冻结 |
| **32 条链** | EVM L1/L2、Bitcoin（Taproot）、Solana、Sui、Aptos、Movement、LTC、DOGE、ZEC、XMR |
| **RPC 注册表** | 多提供商（Dwellir、Alchemy、Infura、Blockstream、Mempool）、故障切换、健康追踪 |
| **广播** | `eth_sendRawTransaction`、REST `/tx`、`sendTransaction`、`sui_executeTransactionBlock` |
| **传输层** | NATS mTLS + 会话级 ECDH + SignedEnvelope 防重放 |
| **企业功能** | RBAC、ABAC、MFA、策略引擎、审批流程、审计账本 |
| **交易模拟** | 签名前风险评分，支持所有链 |
| **运维** | 多云约束、RPC 故障切换、混沌测试框架、灾难恢复 |

---

## 支持的区块链（32 条）

### EVM 链（22 条）

| 链 | Chain ID | 类型 | Dwellir | Alchemy | Infura |
|----|----------|------|:-------:|:-------:|:------:|
| Ethereum | `1` | L1 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Polygon | `137` | L1 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| BSC | `56` | L1 | :white_check_mark: | | |
| Arbitrum | `42161` | L2（Optimistic） | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Optimism | `10` | L2（OP Stack） | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Base | `8453` | L2（OP Stack） | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Avalanche | `43114` | L1（C-Chain） | :white_check_mark: | | :white_check_mark: |
| Linea | `59144` | L2（zkEVM） | :white_check_mark: | | :white_check_mark: |
| zkSync Era | `324` | L2（ZK Rollup） | :white_check_mark: | | |
| Scroll | `534352` | L2（zkEVM） | :white_check_mark: | | |
| Mantle | `5000` | L2（模块化） | :white_check_mark: | | |
| Blast | `81457` | L2（收益） | :white_check_mark: | | |
| Zora | `7777777` | L2（OP Stack） | :white_check_mark: | | |
| Fantom | `250` | L1（DAG） | :white_check_mark: | | |
| Gnosis | `100` | L1（xDai） | :white_check_mark: | | |
| Cronos | `25` | L1 | :white_check_mark: | | |
| Celo | `42220` | L1（移动优先） | :white_check_mark: | | |
| Moonbeam | `1284` | 平行链（EVM） | :white_check_mark: | | |
| Ronin | `2020` | L1（游戏） | :white_check_mark: | | |
| opBNB | `204` | L2（BNB） | :white_check_mark: | | |
| Immutable | `13371` | L2（zkEVM） | :white_check_mark: | | |
| Manta Pacific | `169` | L2（隐私） | :white_check_mark: | | |

> 所有 EVM 链使用 **GG20 ECDSA (secp256k1)** 签名协议和 **EIP-1559** 交易格式。

### UTXO 链（5 条）

| 链 | 地址格式 | 签名协议 | Dwellir | Blockstream | Mempool |
|----|---------|---------|:-------:|:-----------:|:-------:|
| Bitcoin（主网） | Taproot P2TR (`bc1p...`) | FROST Schnorr (BIP-340) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Bitcoin（测试网） | Taproot P2TR (`tb1p...`) | FROST Schnorr (BIP-340) | | :white_check_mark: | :white_check_mark: |
| Litecoin | P2PKH (`L...`) / bech32 (`ltc1...`) | GG20 ECDSA | :white_check_mark: | | |
| Dogecoin | P2PKH (`D...`) | GG20 ECDSA | :white_check_mark: | | |
| Zcash | 透明地址 (`t1...`) | GG20 ECDSA | :white_check_mark: | | |

### Move 链（2 条）

| 链 | 地址格式 | 签名协议 | Dwellir |
|----|---------|---------|:-------:|
| Aptos | `0x` + 64 hex (SHA3-256) | FROST Ed25519 | :white_check_mark: |
| Movement | `0x` + 64 hex (SHA3-256) | FROST Ed25519 | :white_check_mark: |

### 其他链（3 条）

| 链 | 地址格式 | 签名协议 | Dwellir |
|----|---------|---------|:-------:|
| Solana | Base58 (Ed25519) | FROST Ed25519 | :white_check_mark: |
| Sui | `0x` + 64 hex (Blake2b-256) | FROST Ed25519 | :white_check_mark: |
| Monero | Base58（消费密钥 + 查看密钥） | FROST Ed25519 | :white_check_mark: |

> RPC 注册表支持**故障切换**（自动切换不健康节点）、**健康追踪**、**链级配置**（超时、重试次数）和**自定义提供商**。

---

## 性能

| 操作 | 延迟 | 配置 |
|------|------|------|
| GG20 密钥生成 | **44 µs** | 2-of-3，本地传输 |
| GG20 签名 | **188 µs** | 2 个签名方 |
| ChaCha20 加密 1KB | **4 µs** | 每条消息 |
| AES-256-GCM 1KB | **5 µs** | 密钥存储 |
| Argon2id 推导 | **72 ms** | 64MiB（设计如此） |

运行基准测试：`cargo bench -p mpc-wallet-core --bench mpc_benchmarks`

---

## 项目结构

```
crates/
  mpc-wallet-core/     ← MPC 协议、传输层、密钥存储、策略、身份认证
  mpc-wallet-chains/   ← 链适配器：EVM（22）、Bitcoin、Solana、Sui、Aptos、UTXO、Monero
  mpc-wallet-cli/      ← CLI 命令行工具
scripts/
  demo.sh              ← 交互式本地演示（无需外部服务）
docs/                  ← 架构、安全、CLI 指南、Sprint 历史
```

---

## 指标

```
  链:       32           测试:     272 通过
  代码行:   17,000+      CI:       fmt + clippy + test + audit
  Sprint:   17           漏洞:     0 CRITICAL | 0 HIGH 未解决
```

---

## 许可证

MIT

---

<p align="center">
  <sub>
    由 <a href="https://claude.com/claude-code">Claude Code</a> AI Agent 团队构建。
    <br/>
    在制作此 SDK 的过程中，没有任何密钥受到伤害。
  </sub>
</p>
