//! `mpc-wallet send` — generic end-to-end MPC keygen + sign + broadcast.
//!
//! Self-contained smoke test that works across all chains supported by the
//! `ChainProvider` trait. Runs keygen + sign in a single process via
//! `LocalTransport`, derives the chain-specific address, fetches whatever
//! pre-sign data the chain needs, builds a transaction, threshold-signs it,
//! and broadcasts via the chain's native RPC.
//!
//! ## Auto-fetched pre-sign data
//!
//! - **EVM** (Ethereum, Polygon, Base, Arbitrum, Optimism, Avalanche, Linea):
//!   nonce + EIP-1559 fees via `eth_*` JSON-RPC.
//! - **Solana**: `recent_blockhash` via `getLatestBlockhash`. Sender pubkey
//!   (`from`) is auto-filled from the derived address.
//! - **Other chains** (Bitcoin, Sui, Cosmos, Substrate, TRON, …): caller must
//!   pass chain-specific fields via `--extra '{"key":"val"}'`. The provider's
//!   `build_transaction` documents what each chain expects.

use clap::Args;
use mpc_wallet_chains::evm::rpc_client::EvmRpcClient;
use mpc_wallet_chains::provider::{Chain, TransactionParams};
use mpc_wallet_chains::registry::{ChainRegistry, NetworkEnv};
use mpc_wallet_chains::rpc::providers::infura::InfuraProvider;
use mpc_wallet_chains::rpc::RpcProvider;
use mpc_wallet_chains::solana::rpc_client::SolanaRpcClient;
use mpc_wallet_core::key_store::types::KeyGroupId;
use mpc_wallet_core::key_store::KeyStore;
use mpc_wallet_core::protocol::{KeyShare, MpcProtocol, MpcSignature};
use mpc_wallet_core::transport::local::LocalTransportNetwork;
use mpc_wallet_core::types::{CryptoScheme, PartyId, ThresholdConfig};

use crate::output::{self, CliResult, OutputFormat};

#[derive(Args)]
pub struct SendArgs {
    /// Target chain (ethereum, polygon, base, solana, bitcoin-testnet, polkadot, ...).
    #[arg(long, default_value = "ethereum")]
    pub chain: String,

    /// Network environment: mainnet | testnet (default).
    #[arg(long, default_value = "testnet")]
    pub network: String,

    /// Recipient address (chain-specific format).
    #[arg(long)]
    pub to: String,

    /// Value in chain-native base unit (wei, lamports, satoshis, ...).
    #[arg(long)]
    pub value: String,

    /// Optional hex-encoded calldata (EVM contract calls).
    #[arg(long)]
    pub data: Option<String>,

    /// Chain-specific extra params as JSON.
    /// Auto-merged with auto-fetched fields (caller wins).
    #[arg(long)]
    pub extra: Option<String>,

    /// Override RPC URL. If unset, an Infura URL is built for EVM chains and a
    /// public Solana endpoint is used for Solana. Other chains require this flag.
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Override MPC scheme. If unset, picks the first compatible scheme for the chain.
    #[arg(long)]
    pub scheme: Option<String>,

    /// Threshold (minimum signers). Default 2.
    #[arg(short = 't', long, default_value_t = 2)]
    pub threshold: u16,

    /// Total parties. Default 3.
    #[arg(short = 'n', long, default_value_t = 3)]
    pub parties: u16,

    /// EVM gas limit. Default 21000 (EOA transfer). Use 100000+ for contract recipients.
    #[arg(long)]
    pub gas_limit: Option<u64>,

    /// Dry-run: build + sign but do NOT broadcast. Prints the raw signed tx.
    #[arg(long)]
    pub dry_run: bool,

    /// Reuse an existing wallet (key_group_id from `mpc-wallet keygen`).
    /// When set, skips keygen and loads shares from the encrypted key store —
    /// the same address persists across runs so faucet funds aren't lost.
    #[arg(long)]
    pub wallet: Option<String>,

    /// Password for the encrypted key store (only with --wallet). Prompts if omitted.
    #[arg(long)]
    pub password: Option<String>,
}

pub async fn run(args: SendArgs, format: OutputFormat) -> anyhow::Result<()> {
    let chain: Chain = args
        .chain
        .parse()
        .map_err(|e: String| anyhow::anyhow!("invalid chain '{}': {e}", args.chain))?;
    let network = parse_network(&args.network)?;

    // ── 1. Resolve RPC URL ──────────────────────────────────────────────────
    let rpc_url = match args.rpc_url.clone() {
        Some(u) => u,
        None => default_rpc_url(chain, &network)?,
    };
    tracing::info!("RPC: {}", redact_key(&rpc_url));

    // ── 2. Load existing wallet, or run a fresh keygen ──────────────────────
    let (scheme, config, shares) = if let Some(ref wallet_id) = args.wallet {
        load_wallet(wallet_id, args.password.as_deref()).await?
    } else {
        let scheme = match args.scheme.as_deref() {
            Some(s) => s.parse::<CryptoScheme>().map_err(|e| anyhow::anyhow!(e))?,
            None => *ChainRegistry::compatible_schemes(chain)
                .first()
                .ok_or_else(|| anyhow::anyhow!("no MPC scheme registered for chain {chain}"))?,
        };
        let config =
            ThresholdConfig::new(args.threshold, args.parties).map_err(|e| anyhow::anyhow!(e))?;
        eprintln!(
            "→ {} keygen ({}-of-{}) on chain {} ({}) ...",
            scheme, config.threshold, config.total_parties, chain, args.network
        );
        let shares = run_keygen(scheme, config).await?;
        eprintln!("✓ Keygen complete");
        eprintln!(
            "  (ephemeral — pass `--wallet <id>` from `mpc-wallet keygen` to reuse the address across runs)"
        );
        (scheme, config, shares)
    };
    let group_pubkey = shares[0].group_public_key.clone();

    // ── 4. Derive sender address ────────────────────────────────────────────
    let registry = match network {
        NetworkEnv::Mainnet => ChainRegistry::default_mainnet(),
        _ => ChainRegistry::default_testnet(),
    };
    let provider = registry.provider(chain).map_err(|e| anyhow::anyhow!(e))?;
    let sender = provider
        .derive_address(&group_pubkey)
        .map_err(|e| anyhow::anyhow!(e))?;
    eprintln!("✓ Sender: {}", sender);

    // ── Pre-flight: chain balance check (EVM) ──────────────────────────────
    if is_evm_chain(chain) {
        let bal = EvmRpcClient::new(&rpc_url)
            .get_balance(&sender)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("✓ On-chain balance of {sender}: {} wei", bal);
        if bal == 0 {
            eprintln!("⚠️  Sender has 0 balance — fund this address first or the tx will revert.");
        }
    }

    // ── 5. Fetch chain-specific pre-sign data ───────────────────────────────
    let auto_extra = fetch_presign_extras(chain, &rpc_url, &sender).await?;
    let user_extra = match args.extra.as_deref() {
        Some(s) => Some(
            serde_json::from_str::<serde_json::Value>(s)
                .map_err(|e| anyhow::anyhow!("invalid --extra JSON: {e}"))?,
        ),
        None => None,
    };
    let mut extra = merge_extras(auto_extra, user_extra);
    if let Some(gl) = args.gas_limit {
        if let Some(serde_json::Value::Object(ref mut o)) = extra {
            o.insert("gas_limit".into(), serde_json::json!(gl));
        }
    }
    let extra = extra; // freeze

    let calldata = args
        .data
        .as_deref()
        .map(|d| hex::decode(d.strip_prefix("0x").unwrap_or(d)))
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid hex data: {e}"))?;

    let chain_id = extra
        .as_ref()
        .and_then(|e| e.get("chain_id"))
        .and_then(|v| v.as_u64());

    let params = TransactionParams {
        to: args.to.clone(),
        value: args.value.clone(),
        data: calldata,
        chain_id,
        extra: extra.clone(),
    };

    // ── 6. Build unsigned tx ────────────────────────────────────────────────
    let unsigned = provider
        .build_transaction(params)
        .await
        .map_err(|e| anyhow::anyhow!("build_transaction: {e}"))?;

    // ── 7. MPC sign the tx-specific payload ────────────────────────────────
    eprintln!(
        "→ Threshold-signing payload ({} bytes) ...",
        unsigned.sign_payload.len()
    );
    let sig = run_sign(scheme, &shares, &unsigned.sign_payload, config).await?;
    eprintln!("✓ Signed");

    // ── 8. Finalize ────────────────────────────────────────────────────────
    let signed = provider
        .finalize_transaction(&unsigned, &sig)
        .map_err(|e| anyhow::anyhow!(e))?;
    let raw_hex = format!("0x{}", hex::encode(&signed.raw_tx));

    // ── Pre-broadcast: verify the signature recovers to the derived sender ──
    if is_evm_chain(chain) {
        match mpc_wallet_chains::evm::tx::decode_eip1559_summary(&signed.raw_tx) {
            Ok(summary) => eprintln!("✓ Encoded tx: {}", summary),
            Err(e) => eprintln!("⚠️  could not decode tx for summary: {}", e),
        }
        let recovered =
            recover_evm_sender(&signed.raw_tx).map_err(|e| anyhow::anyhow!("sig recovery: {e}"))?;
        if recovered.to_lowercase() != sender.to_lowercase() {
            return Err(anyhow::anyhow!(
                "RECOVERY MISMATCH: signature recovers to {} but wallet derives to {}.\nThis means the MPC signature isn't over the right hash, OR the recovery_id is wrong. Aborting before broadcast.",
                recovered, sender
            ));
        }
        eprintln!("✓ Signature recovers to sender {} (verified)", sender);
    }

    let mut data = serde_json::json!({
        "sender": sender,
        "to": args.to,
        "value": args.value,
        "chain": args.chain,
        "scheme": scheme.to_string(),
        "tx_hash": signed.tx_hash,
        "raw_tx": raw_hex,
    });
    if let Some(cid) = chain_id {
        data["chain_id"] = serde_json::json!(cid);
    }

    if args.dry_run {
        let result = CliResult {
            status: "ok".into(),
            message: format!("dry-run: signed tx {} (not broadcast)", signed.tx_hash),
            data: Some(data),
        };
        output::print_result(&result, format);
        return Ok(());
    }

    // ── 9. Broadcast ────────────────────────────────────────────────────────
    eprintln!("→ Broadcasting via {} ...", redact_key(&rpc_url));
    let broadcast_hash = provider
        .broadcast(&signed, &rpc_url)
        .await
        .map_err(|e| anyhow::anyhow!("broadcast failed: {e}"))?;

    if let Some(url) = explorer_url(chain, &network, &broadcast_hash) {
        data["explorer"] = serde_json::Value::String(url);
    }

    let result = CliResult {
        status: "ok".into(),
        message: format!("Broadcast tx {}", broadcast_hash),
        data: Some(data),
    };
    output::print_result(&result, format);
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn is_evm_chain(chain: Chain) -> bool {
    matches!(
        chain,
        Chain::Ethereum
            | Chain::Polygon
            | Chain::Bsc
            | Chain::Arbitrum
            | Chain::Optimism
            | Chain::Base
            | Chain::Avalanche
            | Chain::Linea
    )
}

fn recover_evm_sender(raw_tx: &[u8]) -> anyhow::Result<String> {
    mpc_wallet_chains::evm::tx::recover_eip1559_sender(raw_tx).map_err(|e| anyhow::anyhow!(e))
}

/// Load shares + metadata for an existing wallet from the encrypted file store.
async fn load_wallet(
    wallet_id: &str,
    password: Option<&str>,
) -> anyhow::Result<(CryptoScheme, ThresholdConfig, Vec<KeyShare>)> {
    let group_id = KeyGroupId::from_string(wallet_id.to_string());
    let password = match password {
        Some(p) => p.to_string(),
        None => rpassword::prompt_password("Enter wallet password: ")
            .map_err(|e| anyhow::anyhow!("read password: {e}"))?,
    };
    let store = mpc_wallet_core::key_store::encrypted::EncryptedFileStore::new(
        crate::config::key_store_dir(),
        &password,
    );
    let groups = store.list().await?;
    let meta = groups
        .into_iter()
        .find(|m| m.group_id == group_id)
        .ok_or_else(|| anyhow::anyhow!("wallet '{wallet_id}' not found in key store"))?;
    eprintln!(
        "✓ Loaded wallet '{}' ({}-of-{} {})",
        meta.label, meta.config.threshold, meta.config.total_parties, meta.scheme
    );
    let mut shares = Vec::new();
    for i in 1..=meta.config.total_parties {
        shares.push(store.load(&group_id, PartyId(i)).await?);
    }
    Ok((meta.scheme, meta.config, shares))
}

fn parse_network(s: &str) -> anyhow::Result<NetworkEnv> {
    match s.to_lowercase().as_str() {
        "mainnet" => Ok(NetworkEnv::Mainnet),
        "testnet" => Ok(NetworkEnv::Testnet),
        "devnet" => Ok(NetworkEnv::Devnet),
        other => Err(anyhow::anyhow!("invalid network '{other}'")),
    }
}

/// Default RPC URL for chains that have a known public endpoint.
/// Returns an error for chains where the user must provide `--rpc-url`.
fn default_rpc_url(chain: Chain, network: &NetworkEnv) -> anyhow::Result<String> {
    // EVM via Infura (requires INFURA_API_KEY).
    let evm_chains = [
        Chain::Ethereum,
        Chain::Polygon,
        Chain::Arbitrum,
        Chain::Optimism,
        Chain::Base,
        Chain::Avalanche,
        Chain::Linea,
    ];
    if evm_chains.contains(&chain) {
        let key = std::env::var("INFURA_API_KEY").map_err(|_| {
            anyhow::anyhow!("INFURA_API_KEY env var required for EVM chains (or pass --rpc-url)")
        })?;
        return InfuraProvider::new(&key)
            .https_endpoint(chain, network)
            .ok_or_else(|| {
                anyhow::anyhow!("Infura does not support chain {chain} on {network:?}")
            });
    }
    // Solana — public endpoints (rate-limited, fine for smoke tests).
    if chain == Chain::Solana {
        return Ok(match network {
            NetworkEnv::Mainnet => "https://api.mainnet-beta.solana.com".into(),
            NetworkEnv::Devnet => "https://api.devnet.solana.com".into(),
            _ => "https://api.testnet.solana.com".into(),
        });
    }
    Err(anyhow::anyhow!(
        "no default RPC for chain {chain} — pass --rpc-url"
    ))
}

/// Fetch chain-specific pre-sign data and return it as JSON to merge into `extra`.
/// Returns `None` for chains with no auto-fetch logic.
async fn fetch_presign_extras(
    chain: Chain,
    rpc_url: &str,
    sender: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let evm_chains = [
        Chain::Ethereum,
        Chain::Polygon,
        Chain::Bsc,
        Chain::Arbitrum,
        Chain::Optimism,
        Chain::Base,
        Chain::Avalanche,
        Chain::Linea,
    ];
    if evm_chains.contains(&chain) {
        let rpc = EvmRpcClient::new(rpc_url);
        let chain_id = rpc.get_chain_id().await.map_err(|e| anyhow::anyhow!(e))?;
        let nonce = rpc
            .get_nonce(sender)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let (max_fee, max_priority) = rpc
            .suggest_eip1559_fees()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!(
            "✓ chain_id={chain_id} nonce={nonce} max_fee={} gwei priority={} gwei",
            max_fee / 1_000_000_000,
            max_priority / 1_000_000_000
        );
        return Ok(Some(serde_json::json!({
            "chain_id": chain_id,
            "nonce": nonce,
            "gas_limit": 21_000u64,
            "max_fee_per_gas": max_fee as u64,
            "max_priority_fee_per_gas": max_priority as u64,
        })));
    }
    if chain == Chain::Solana {
        let rpc = SolanaRpcClient::new(rpc_url);
        let blockhash = rpc
            .get_latest_blockhash()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("✓ recent_blockhash={blockhash}");
        return Ok(Some(serde_json::json!({
            "from": sender,
            "recent_blockhash": blockhash,
        })));
    }
    Ok(None)
}

/// Merge auto-fetched extras with user-supplied extras (user wins).
fn merge_extras(
    auto: Option<serde_json::Value>,
    user: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    match (auto, user) {
        (None, None) => None,
        (Some(v), None) | (None, Some(v)) => Some(v),
        (Some(serde_json::Value::Object(mut a)), Some(serde_json::Value::Object(u))) => {
            for (k, v) in u {
                a.insert(k, v);
            }
            Some(serde_json::Value::Object(a))
        }
        // Non-object values: user wins.
        (Some(_), Some(u)) => Some(u),
    }
}

/// Build a protocol box for the given scheme.
fn protocol_for(scheme: CryptoScheme) -> Box<dyn MpcProtocol> {
    use mpc_wallet_core::protocol::{
        bls12_381::Bls12_381Protocol, cggmp21::Cggmp21Protocol,
        frost_ed25519::FrostEd25519Protocol, frost_secp256k1::FrostSecp256k1TrProtocol,
        gg20::Gg20Protocol, sr25519::Sr25519Protocol, stark::StarkProtocol,
    };
    match scheme {
        CryptoScheme::Gg20Ecdsa => Box::new(Gg20Protocol::new()),
        CryptoScheme::Cggmp21Secp256k1 => Box::new(Cggmp21Protocol::new()),
        CryptoScheme::FrostSecp256k1Tr => Box::new(FrostSecp256k1TrProtocol::new()),
        CryptoScheme::FrostEd25519 => Box::new(FrostEd25519Protocol::new()),
        CryptoScheme::Sr25519Threshold => Box::new(Sr25519Protocol::new()),
        CryptoScheme::StarkThreshold => Box::new(StarkProtocol::new()),
        CryptoScheme::Bls12_381Threshold => Box::new(Bls12_381Protocol::new()),
    }
}

async fn run_keygen(
    scheme: CryptoScheme,
    config: ThresholdConfig,
) -> anyhow::Result<Vec<KeyShare>> {
    let transports = LocalTransportNetwork::new(config.total_parties);
    let mut handles = Vec::new();
    for i in 0..config.total_parties {
        let party_id = PartyId(i + 1);
        let transport = transports.get_transport(party_id);
        handles.push(tokio::spawn(async move {
            let p = protocol_for(scheme);
            p.keygen(config, party_id, &*transport).await
        }));
    }
    let mut shares = Vec::new();
    for h in handles {
        shares.push(h.await??);
    }
    Ok(shares)
}

async fn run_sign(
    scheme: CryptoScheme,
    shares: &[KeyShare],
    payload: &[u8],
    config: ThresholdConfig,
) -> anyhow::Result<MpcSignature> {
    let transports = LocalTransportNetwork::new(config.total_parties);
    let signers: Vec<PartyId> = (1..=config.threshold).map(PartyId).collect();
    let mut handles = Vec::new();
    for share in shares.iter().take(config.threshold as usize).cloned() {
        let transport = transports.get_transport(share.party_id);
        let signers_c = signers.clone();
        let payload_c = payload.to_vec();
        handles.push(tokio::spawn(async move {
            let p = protocol_for(scheme);
            p.sign(&share, &signers_c, &payload_c, &*transport).await
        }));
    }
    let mut sigs = Vec::new();
    for h in handles {
        sigs.push(h.await??);
    }
    Ok(sigs.remove(0))
}

fn redact_key(url: &str) -> String {
    if let Some(idx) = url.rfind('/') {
        if idx + 1 < url.len() && url[idx + 1..].len() > 8 {
            return format!("{}/<redacted>", &url[..idx]);
        }
    }
    url.to_string()
}

fn explorer_url(chain: Chain, network: &NetworkEnv, tx_hash: &str) -> Option<String> {
    let base = match (chain, network) {
        (Chain::Ethereum, NetworkEnv::Mainnet) => "https://etherscan.io/tx/",
        (Chain::Ethereum, _) => "https://sepolia.etherscan.io/tx/",
        (Chain::Polygon, NetworkEnv::Mainnet) => "https://polygonscan.com/tx/",
        (Chain::Polygon, _) => "https://amoy.polygonscan.com/tx/",
        (Chain::Bsc, _) => "https://bscscan.com/tx/",
        (Chain::Arbitrum, NetworkEnv::Mainnet) => "https://arbiscan.io/tx/",
        (Chain::Arbitrum, _) => "https://sepolia.arbiscan.io/tx/",
        (Chain::Optimism, NetworkEnv::Mainnet) => "https://optimistic.etherscan.io/tx/",
        (Chain::Optimism, _) => "https://sepolia-optimism.etherscan.io/tx/",
        (Chain::Base, NetworkEnv::Mainnet) => "https://basescan.org/tx/",
        (Chain::Base, _) => "https://sepolia.basescan.org/tx/",
        (Chain::Avalanche, _) => "https://snowtrace.io/tx/",
        (Chain::Solana, NetworkEnv::Mainnet) => "https://explorer.solana.com/tx/",
        (Chain::Solana, _) => "https://explorer.solana.com/tx/{}?cluster=devnet",
        (Chain::Sui, _) => "https://suiscan.xyz/mainnet/tx/",
        (Chain::BitcoinMainnet, _) => "https://mempool.space/tx/",
        (Chain::BitcoinTestnet, _) => "https://mempool.space/testnet/tx/",
        _ => return None,
    };
    if base.contains("{}") {
        Some(base.replace("{}", tx_hash))
    } else {
        Some(format!("{base}{tx_hash}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_extras_user_wins() {
        let auto = Some(serde_json::json!({"a": 1, "b": 2}));
        let user = Some(serde_json::json!({"b": 99, "c": 3}));
        let merged = merge_extras(auto, user).unwrap();
        assert_eq!(merged["a"], 1);
        assert_eq!(merged["b"], 99);
        assert_eq!(merged["c"], 3);
    }

    #[test]
    fn test_merge_extras_one_side_none() {
        let auto = Some(serde_json::json!({"a": 1}));
        assert_eq!(merge_extras(auto.clone(), None).unwrap()["a"], 1);
        assert_eq!(merge_extras(None, auto.clone()).unwrap()["a"], 1);
    }

    #[test]
    fn test_explorer_sepolia() {
        let url = explorer_url(Chain::Ethereum, &NetworkEnv::Testnet, "0xabc").unwrap();
        assert!(url.starts_with("https://sepolia.etherscan.io/tx/"));
    }

    #[test]
    fn test_explorer_solana_devnet() {
        let url = explorer_url(Chain::Solana, &NetworkEnv::Devnet, "abc").unwrap();
        assert!(url.contains("cluster=devnet"));
    }

    #[test]
    fn test_default_rpc_solana_devnet() {
        let url = default_rpc_url(Chain::Solana, &NetworkEnv::Devnet).unwrap();
        assert!(url.contains("devnet.solana.com"));
    }

    #[test]
    fn test_default_rpc_unsupported_chain() {
        let r = default_rpc_url(Chain::Sui, &NetworkEnv::Testnet);
        assert!(r.is_err());
    }
}
