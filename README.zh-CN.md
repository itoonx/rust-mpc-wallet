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

EVM（26）| Bitcoin | Polkadot | Solana | Sui | Aptos | TON | TRON | Cosmos | Starknet | 共 50 条链

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
- **多链支持** — 50 条区块链，涵盖 8 大生态：EVM、Bitcoin、Substrate、Move、Cosmos、UTXO、TON/TRON、Starknet
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
| **[API 参考](docs/API_REFERENCE.md)** | REST API 端点、认证方式 |
| **[认证规范](specs/AUTH_SPEC.md)** | 密钥交换握手协议（28 个章节） |
| **[安全审计报告](docs/SECURITY_AUDIT_AUTH.md)** | 认证安全审计（57 项测试，所有问题已修复） |
| **[安全审计](docs/SECURITY_FINDINGS.md)** | 完整审计追踪（0 个 CRITICAL/HIGH 未解决） |

---

## 快速开始

```bash
git clone https://github.com/itoonx/vaultex-mpc-rust.git
cd vaultex-mpc-rust

cargo test --workspace     # 325 个测试，约 4 秒
./scripts/demo.sh          # 交互式端到端演示
```

---

## 功能特性

| 类别 | 亮点 |
|------|------|
| **MPC 协议** | GG20 ECDSA、FROST Ed25519、FROST Schnorr、Sr25519、STARK、BLS12-381 |
| **密钥生命周期** | 生成、刷新、重分享（修改阈值/增删参与方）、冻结 |
| **50 条链** | EVM L1/L2、Bitcoin、Solana、Sui、Aptos、Movement、TON、TRON、LTC、DOGE、ZEC、XMR |
| **RPC 注册表** | 多提供商（Dwellir、Alchemy、Infura、Blockstream、Mempool）、故障切换、健康追踪 |
| **广播** | `eth_sendRawTransaction`、REST `/tx`、`sendTransaction`、`sui_executeTransactionBlock` |
| **传输层** | NATS mTLS + 会话级 ECDH + SignedEnvelope 防重放 |
| **企业功能** | RBAC、ABAC、MFA、策略引擎、审批流程、审计账本 |
| **交易模拟** | 签名前风险评分，支持所有链 |
| **运维** | 多云约束、RPC 故障切换、混沌测试框架、灾难恢复 |

---

## 认证与 API 网关

API 网关提供多层纵深防御认证，支持三种认证方式：

```
客户端                        网关                             MPC 节点
┌──────────┐  密钥交换    ┌─────────────────┐  签名授权    ┌──────────┐
│ Ed25519 + │────────────│ X25519 ECDH     │────────────│ 独立验证  │
│ X25519   │  握手协议   │ 会话密钥         │  证明       │ 网关签名  │
│          │            │                 │            │ 再执行签名│
│ 每请求   │  会话 JWT  │ 验证 HS256      │  SignAuth  │          │
│ JWT 签名 │────────────│ 使用共享密钥     │────────────│          │
└──────────┘            └─────────────────┘            └──────────┘
```

### 三种认证方式（按优先级排列）

网关按此顺序检查：**mTLS → 会话 JWT → Bearer JWT**。如果请求头**存在**但无效，认证立即失败 — 不会降级到下一种方式。

#### 1. 会话 JWT (`X-Session-Token`) — 适用于 SDK 客户端

**适用场景：** 应用在启动时执行密钥交换握手，然后使用派生的会话密钥签名每个请求。安全性最高 — 提供双向认证、前向保密和每请求上下文绑定。

**工作原理：**

```
步骤 1：密钥交换（每个会话仅一次）
  客户端                                服务端
  ──────                                ──────
  生成临时 X25519 密钥对          ───►   验证，生成服务端临时密钥
  Ed25519 密钥 ID                       使用 Ed25519 签名会话摘要
                                 ◄───   ServerHello（挑战 + 签名）
  使用 Ed25519 签名会话摘要       ───►   验证客户端签名
  ClientAuth                            通过 ECDH + HKDF 派生共享密钥
                                 ◄───   SessionEstablished（session_id）
  双方现在拥有：
    client_write_key（32字节）← 用于签名 JWT
    server_write_key（32字节）← 用于未来的加密响应

步骤 2：每请求 JWT（每次 API 调用）
  客户端构建 JWT：
    { "sid": "session_id",
      "ip": "203.0.113.42",       ← 请求上下文（用于审计）
      "fp": "设备指纹",
      "ua": "SDK/1.0",
      "rid": "唯一请求ID",
      "iat": 1710768000,
      "exp": 1710768120 }         ← 短期有效（2分钟）
  使用 HS256(client_write_key) 签名
  发送：X-Session-Token: eyJhbG...

  服务端：
    1. 解码 JWT → 提取 session_id（此时不验证签名）
    2. 查找会话 → 获取存储的 client_write_key
    3. 使用该密钥验证 HS256 签名
       → 密钥不匹配？401。载荷被篡改？401。已过期？401。
    4. 提取请求上下文用于审计追踪
```

```bash
# 握手
POST /v1/auth/hello   # → ServerHello
POST /v1/auth/verify  # → { session_id, session_token }

# 认证请求
curl -H "X-Session-Token: eyJhbGciOiJIUzI1NiJ9.eyJzaWQiOi..." \
     https://api.example.com/v1/wallets
```

**安全性：** 前向保密（临时密钥）、双向认证（双方签名）、防重放（短期JWT + 随机数）、请求上下文绑定（IP/设备信息在签名声明中）。

---

#### 2. mTLS (双向 TLS) — 适用于服务间通信（推荐）

**适用场景：** 可管理 TLS 证书的可信基础设施中的后端服务。这是服务间认证的**最佳实践** — 身份在传输层验证，应用代码运行前即已完成。

**工作原理：**

```
服务 A                    TLS 终端（nginx/envoy）           网关
┌──────────┐  提交证书   ┌──────────────────────────┐     ┌─────────┐
│ 客户端   │────────────│ 1. 验证证书（对比 CA）     │────│ 提取    │
│ 证书 +   │  TLS 握手  │ 2. 提取 CN + 指纹         │    │ 身份    │
│ 密钥     │           │ 3. 设置 X-Client-Cert-* 头 │    │ 映射角色│
└──────────┘           └──────────────────────────┘     └─────────┘
```

**无共享密钥，请求头中无令牌。** TLS 终端处理证书验证并通过请求头传递身份：

- `X-Client-Cert-Verified: SUCCESS` — 证书已通过 CA 验证
- `X-Client-Cert-CN: trading-service.internal` — 通用名称
- `X-Client-Cert-Fingerprint: sha256:abcdef...` — 证书指纹

网关通过 `MTLS_SERVICES_FILE` 将 CN 映射到服务身份 + RBAC 角色：

```json
[
  {
    "cn": "trading-service.internal",
    "fingerprint": "sha256:abcdef1234567890",
    "role": "initiator",
    "label": "交易服务"
  }
]
```

**安全性：** 无需轮换密钥（只需更新证书）。传输层身份验证。支持证书指纹绑定。Kubernetes、Istio、Consul 原生支持。

---

#### 3. Bearer JWT (`Authorization: Bearer`) — 适用于用户端应用

**适用场景：** Web/移动应用，用户通过身份提供商（Auth0、Okta、Firebase 等）认证后获得 JWT。网关验证 JWT 签名并提取用户身份和角色。

**工作原理：**

```
身份提供商（Auth0、Okta 等）
  ↓ 颁发包含声明的 JWT：
  { "sub": "user_123", "roles": ["initiator"], "iss": "mpc-wallet",
    "aud": "mpc-wallet-api", "exp": 1710771600,
    "dept": "交易部", "risk_tier": "standard", "mfa_verified": true }
  ↓
客户端发送：Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
  ↓
服务端验证：
  1. 签名（RS256/ES256/HS256）是否与配置的密钥匹配
  2. 签发者（iss）是否与 JWT_ISSUER 配置匹配
  3. 受众（aud）是否与 JWT_AUDIENCE 配置匹配
  4. 是否未过期（exp > 当前时间）
  5. 提取角色 → 映射到 RBAC 权限
  6. 提取 ABAC 属性（部门、风险等级、MFA 状态）
```

```bash
curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOi..." \
     https://api.example.com/v1/wallets
```

**无需 HMAC 签名** — JWT 本身通过其签名提供完整性保证。

---

#### 如何选择认证方式？

| 场景 | 推荐方式 | 原因 |
|------|---------|------|
| 后端微服务 | **mTLS** | 最佳实践：无共享密钥，传输层身份验证，证书轮换 |
| Kubernetes / 服务网格 | **mTLS** | Istio、Linkerd、Consul Connect 原生支持 |
| SDK / 原生应用 | **会话 JWT** | 前向保密、双向认证、每请求上下文绑定 |
| 移动应用 | **会话 JWT** | JWT 声明中包含设备指纹用于审计 |
| 使用 IdP 的 Web 应用 | **Bearer JWT** | 用户通过 Auth0/Okta 认证，无需密钥管理 |
| 管理后台 | **Bearer JWT + MFA** | 用户身份 + 敏感操作需 MFA 二次验证 |

### 安全特性

| 特性 | 实现方式 |
|------|---------|
| **前向保密** | 每会话临时 X25519 密钥 |
| **双向认证** | Ed25519 会话摘要签名（双方） |
| **速率限制** | 握手端点每 client_key_id 10 次/秒 |
| **会话存储** | 10万上限 + 后台清理（60秒间隔） |
| **密钥清零** | 所有会话密钥 `Zeroize + ZeroizeOnDrop` |
| **动态吊销** | `POST /v1/auth/revoke-key`（管理员，无需重启） |
| **签名授权** | MPC 节点在签名前独立验证网关证明 |
| **审计追踪** | 加密请求上下文 (ChaCha20-Poly1305) + 毫秒级时间线 |
| **主网安全** | 主网强制要求 `SERVER_SIGNING_KEY` + `CLIENT_KEYS_FILE` |

> 完整 API 参考：[`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) | 协议规范：[`specs/AUTH_SPEC.md`](specs/AUTH_SPEC.md)

---

## 支持的区块链（50 条）

### EVM 链（26 条）

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
| Hyperliquid | `999` | L1（永续 DEX） | :white_check_mark: | | |
| Berachain | `80094` | L1（PoL） | :white_check_mark: | | |
| MegaETH | `6342` | L2（实时） | :white_check_mark: | | |
| Monad | `143` | L1（并行 EVM） | :white_check_mark: | | |

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

### Substrate / Polkadot（6 条）

| 链 | 地址（SS58） | 签名协议 | Dwellir |
|----|-------------|---------|:-------:|
| Polkadot | SS58 前缀 0 | FROST Ed25519 | :white_check_mark: |
| Kusama | SS58 前缀 2 | FROST Ed25519 | :white_check_mark: |
| Astar | SS58 前缀 5 | FROST Ed25519 | :white_check_mark: |
| Acala | SS58 前缀 10 | FROST Ed25519 | :white_check_mark: |
| Phala | SS58 前缀 30 | FROST Ed25519 | :white_check_mark: |
| Interlay | SS58 前缀 2032 | FROST Ed25519 | :white_check_mark: |

> 支持 FROST Ed25519 和 **Sr25519 门限 MPC**（基于 Ristretto255 的 Schnorrkel）。

### Cosmos / IBC（5 条）

| 链 | 地址（bech32） | 签名协议 | Dwellir |
|----|---------------|---------|:-------:|
| Cosmos Hub | `cosmos1...` | GG20 ECDSA (secp256k1) | :white_check_mark: |
| Osmosis | `osmo1...` | GG20 ECDSA (secp256k1) | :white_check_mark: |
| Celestia | `celestia1...` | GG20 ECDSA / Ed25519 | :white_check_mark: |
| Injective | `inj1...` | GG20 ECDSA (secp256k1) | :white_check_mark: |
| Sei | `sei1...` | GG20 ECDSA (secp256k1) | :white_check_mark: |

### 替代 L1（2 条）

| 链 | 地址格式 | 签名协议 | Dwellir |
|----|---------|---------|:-------:|
| TON | `0:` + 64 hex (SHA-256) | FROST Ed25519 | :white_check_mark: |
| TRON | Base58Check (`T...`, 0x41 前缀) | GG20 ECDSA (secp256k1) | :white_check_mark: |

### 专用链（1 条）

| 链 | 地址格式 | 签名协议 | Dwellir |
|----|---------|---------|:-------:|
| Starknet | `0x` + 64 hex（251位域） | STARK 门限 MPC | :white_check_mark: |

> STARK 曲线门限 MPC 签名正在计划中。目前使用 ECDSA 兼容占位符。

### 其他链（3 条）

| 链 | 地址格式 | 签名协议 | Dwellir |
|----|---------|---------|:-------:|
| Solana | Base58 (Ed25519) | FROST Ed25519 | :white_check_mark: |
| Sui | `0x` + 64 hex (Blake2b-256) | FROST Ed25519 | :white_check_mark: |
| Monero | Base58（消费密钥 + 查看密钥） | FROST Ed25519 | :white_check_mark: |

> RPC 注册表支持**故障切换**（自动切换不健康节点）、**健康追踪**、**链级配置**（超时、重试次数）和**自定义提供商**。

---

## MPC 签名协议（6 种）

| 协议 | 曲线 | 支持链 | 依赖库 |
|------|------|--------|--------|
| **GG20 ECDSA** | secp256k1 | EVM（26）、TRON、Cosmos（5）、UTXO（3） | `k256` |
| **FROST Schnorr** | secp256k1 | Bitcoin（Taproot P2TR） | `frost-secp256k1-tr` |
| **FROST Ed25519** | Ed25519 | Solana、Sui、Aptos、Movement、TON、Monero | `frost-ed25519` |
| **Sr25519 门限** | Ristretto255 | Polkadot、Kusama、Astar、Acala、Phala、Interlay | `schnorrkel` |
| **STARK 门限** | Stark 曲线 | Starknet | 自定义实现 |
| **BLS12-381 门限** | BLS12-381 | Filecoin、以太坊验证者 | `blst` |

> 所有协议支持门限密钥生成和分布式签名 — 完整私钥**永远不会**被组装。

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
  mpc-wallet-chains/   ← 链适配器：50 条链，涵盖 8 大生态
  mpc-wallet-cli/      ← CLI 命令行工具
services/
  api-gateway/         ← REST API 服务器、认证（密钥交换 + JWT + mTLS）、RBAC
specs/                 ← AUTH_SPEC.md、SIGN_AUTHORIZATION_SPEC.md
retro/                 ← 决策记录、经验教训、安全审计
scripts/
  demo.sh              ← 交互式本地演示（无需外部服务）
docs/                  ← 架构、安全、CLI 指南、Sprint 历史
```

---

## 指标

```
  链:       50           测试:      ~450 通过
  协议:     6            CI:        fmt + clippy + test + audit
  Sprint:   20           漏洞:      0 CRITICAL | 0 HIGH 未解决
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
