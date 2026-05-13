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
use mpc_wallet_chains::bitcoin::rpc_client::BitcoinRpcClient;
use mpc_wallet_chains::evm::rpc_client::EvmRpcClient;
use mpc_wallet_chains::provider::{Chain, TransactionParams};
use mpc_wallet_chains::registry::{ChainRegistry, NetworkEnv};
use mpc_wallet_chains::rpc::providers::dwellir::DwellirProvider;
use mpc_wallet_chains::rpc::providers::infura::InfuraProvider;
use mpc_wallet_chains::rpc::RpcProvider;
use mpc_wallet_chains::solana::rpc_client::SolanaRpcClient;
use mpc_wallet_chains::token::TokenIdentifier;
use mpc_wallet_core::key_store::types::KeyGroupId;
use mpc_wallet_core::key_store::KeyStore;
use mpc_wallet_core::protocol::{GroupPublicKey, KeyShare, MpcProtocol, MpcSignature};
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

    /// Token to transfer instead of the chain's native token. Shorthand syntax:
    ///
    /// - `native` (default) — chain's native gas token
    /// - `erc20:0x...` — EVM ERC-20 (Sprint 45)
    /// - `spl:<mint>:<decimals>` / `spl-2022:<mint>:<decimals>` — Solana SPL (Sprint 49)
    /// - `sui-coin:<type-tag>` — Sui Coin<T> (Sprint 46)
    /// - `aptos-coin:<type-tag>` / `aptos-fa:<metadata-addr>` — Aptos (Sprints 46/47)
    /// - `trc20:T...` — TRON TRC-20 (Sprint 48)
    ///
    /// Use `--token-json '<full json>'` for the canonical wire form.
    #[arg(long)]
    pub token: Option<String>,

    /// Canonical token spec as JSON (escape hatch when shorthand isn't enough).
    /// Mutually exclusive with --token. See docs/TOKEN_TRANSFER_DESIGN.md.
    #[arg(long, conflicts_with = "token")]
    pub token_json: Option<String>,
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

    // ── Resolve token spec (shorthand → canonical JSON) ─────────────────────
    let token_json = parse_token_spec(args.token.as_deref(), args.token_json.as_deref())?;
    if let Some(ref tj) = token_json {
        eprintln!("✓ Token spec: {}", tj);
    }

    // ── Pre-flight: chain balance check ────────────────────────────────────
    if is_evm_chain(chain) {
        let rpc = EvmRpcClient::new(&rpc_url);
        // Always print native balance — needed for gas regardless of token transfer.
        let native_bal = rpc
            .get_balance(&sender)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("✓ On-chain native balance of {sender}: {} wei", native_bal);
        if native_bal == 0 {
            eprintln!("⚠️  Sender has 0 native balance — needed for gas; fund first.");
        }
        // For ERC-20 transfers, also check the token balance.
        if let Some(serde_json::Value::Object(t)) = &token_json {
            if t.get("kind").and_then(|v| v.as_str()) == Some("evm") {
                if let Some(contract) = t.get("contract").and_then(|v| v.as_str()) {
                    let token_bal = erc20_balance_of(&rpc, contract, &sender).await?;
                    eprintln!("✓ Token balance of {sender} on {contract}: {token_bal}");
                    if token_bal == "0" {
                        eprintln!(
                            "⚠️  Sender has 0 token balance — fund the token before transferring."
                        );
                    }
                }
            }
        }
    } else if chain == Chain::Solana {
        let bal = SolanaRpcClient::new(&rpc_url)
            .get_balance(&sender)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("✓ On-chain balance of {sender}: {} lamports", bal);
        if bal == 0 {
            eprintln!("⚠️  Sender has 0 lamports — fund via https://faucet.solana.com first.");
        }
    } else if matches!(chain, Chain::BitcoinTestnet | Chain::BitcoinMainnet) {
        let bal = BitcoinRpcClient::new(&rpc_url)
            .get_balance(&sender)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("✓ On-chain balance of {sender}: {} sats", bal);
        if bal == 0 {
            eprintln!("⚠️  Sender has 0 sats — fund via a testnet faucet first.");
        }
    } else if matches!(chain, Chain::Aptos | Chain::Movement) {
        let bal = mpc_wallet_chains::aptos::rpc_client::AptosRpcClient::new(&rpc_url)
            .get_balance(&sender)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("✓ On-chain balance of {sender}: {} octas", bal);
        if bal == 0 {
            eprintln!("⚠️  Sender has 0 octas — fund via https://aptos.dev/network/faucet first.");
        }
    } else if chain == Chain::Sui {
        let bal = mpc_wallet_chains::sui::rpc_client::SuiRpcClient::new(&rpc_url)
            .get_balance(&sender)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("✓ On-chain balance of {sender}: {} MIST", bal);
        if bal == 0 {
            eprintln!("⚠️  Sender has 0 MIST — fund via https://faucet.sui.io/ first.");
        }
    } else if chain == Chain::Tron {
        let bal = mpc_wallet_chains::tron::rpc_client::TronRpcClient::new(&rpc_url)
            .get_balance(&sender)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("✓ On-chain balance of {sender}: {} sun", bal);
        if bal == 0 {
            eprintln!("⚠️  Sender has 0 sun — fund via https://shasta.tronex.io or https://www.trongrid.io/shasta first.");
        }
    }

    // ── 5. Fetch chain-specific pre-sign data ───────────────────────────────
    let auto_extra = fetch_presign_extras(
        chain,
        &rpc_url,
        &sender,
        &group_pubkey,
        token_json.as_ref(),
        &args.to,
        &args.value,
    )
    .await?;
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
    // Inject the token spec into extras (where each chain provider reads it).
    if let Some(token_value) = token_json.clone() {
        match extra {
            Some(serde_json::Value::Object(ref mut o)) => {
                o.insert("token".into(), token_value);
            }
            None => {
                extra = Some(serde_json::json!({ "token": token_value }));
            }
            Some(_) => {} // shouldn't happen — extras are always objects
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

    // ── Pre-broadcast: verify the signature against the derived sender ──────
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
    } else if chain == Chain::Solana {
        match mpc_wallet_chains::solana::tx::decode_solana_summary(&signed.raw_tx) {
            Ok(summary) => eprintln!("✓ Encoded tx: {}", summary),
            Err(e) => eprintln!("⚠️  could not decode tx for summary: {}", e),
        }
        mpc_wallet_chains::solana::tx::verify_solana_signature(
            &sender,
            &sig,
            &unsigned.sign_payload,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "Ed25519 SIGNATURE INVALID: {} — the FROST sig does not verify against the wallet's pubkey ({}). Aborting before broadcast.",
                e,
                sender,
            )
        })?;
        eprintln!("✓ Ed25519 signature verifies against {}", sender);
    } else if chain == Chain::Sui {
        eprintln!(
            "✓ Encoded tx: bcs_len={} sig_len=97 (Ed25519)",
            unsigned.tx_data.len() - 32
        );
        mpc_wallet_chains::sui::tx::verify_sui_signature(
            &group_pubkey,
            &sig,
            &unsigned.sign_payload,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "Ed25519 SIGNATURE INVALID: {e} — FROST sig does not verify against {sender}. Aborting before broadcast."
            )
        })?;
        eprintln!("✓ Ed25519 signature verifies against {}", sender);
    } else if matches!(chain, Chain::Aptos | Chain::Movement) {
        eprintln!(
            "✓ Encoded tx: bcs_len={} sig_len=99 (Ed25519 authenticator)",
            unsigned.tx_data.len() - 32
        );
        mpc_wallet_chains::aptos::tx::verify_aptos_signature(
            &group_pubkey,
            &sig,
            &unsigned.sign_payload,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "Ed25519 SIGNATURE INVALID: {e} — FROST sig does not verify against {sender}. Aborting before broadcast."
            )
        })?;
        eprintln!("✓ Ed25519 signature verifies against {}", sender);
    } else if chain == Chain::Tron {
        eprintln!(
            "✓ Encoded tx: raw_len={} sig_len=65 (ECDSA r|s|v)",
            unsigned.tx_data.len()
        );
        let recovered =
            mpc_wallet_chains::tron::tx::recover_tron_sender(&unsigned.sign_payload, &sig)
                .map_err(|e| anyhow::anyhow!("TRON sig recovery: {e}"))?;
        if recovered != sender {
            return Err(anyhow::anyhow!(
                "TRON RECOVERY MISMATCH: signature recovers to {recovered} but wallet derives to {sender}.\nThe MPC signature isn't over the right hash, or the recovery_id is wrong. Aborting before broadcast."
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
    // Match by group_id (UUID) first, then fall back to label so users can
    // pass either `--wallet ea5b726e-…` or `--wallet sui-testnet`.
    let target = KeyGroupId::from_string(wallet_id.to_string());
    let meta = groups
        .iter()
        .find(|m| m.group_id == target)
        .or_else(|| groups.iter().find(|m| m.label == wallet_id))
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "wallet '{wallet_id}' not found (matched neither group_id nor label) — run `mpc-wallet list-keys` to see available wallets"
            )
        })?;
    let group_id = meta.group_id.clone();
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
    let dwellir = std::env::var("DWELLIR_API_KEY").ok();
    let infura = std::env::var("INFURA_API_KEY").ok();
    resolve_default_rpc_url(chain, network, dwellir.as_deref(), infura.as_deref())
}

/// Pure resolver — useful for unit tests that need to control which keys are
/// "set" without poking at process env.
fn resolve_default_rpc_url(
    chain: Chain,
    network: &NetworkEnv,
    dwellir_key: Option<&str>,
    infura_key: Option<&str>,
) -> anyhow::Result<String> {
    // 1. Dwellir — covers ~43 chains across EVM/Substrate/Cosmos/Move/Solana/Sui.
    if let Some(key) = dwellir_key {
        if let Some(url) = DwellirProvider::new(key).https_endpoint(chain, network) {
            return Ok(url);
        }
    }

    // 2. Infura — legacy EVM fallback.
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
        if let Some(key) = infura_key {
            if let Some(url) = InfuraProvider::new(key).https_endpoint(chain, network) {
                return Ok(url);
            }
        }
    }

    // 3. Public endpoints — Solana RPC + Bitcoin Esplora REST.
    if chain == Chain::Solana {
        return Ok(match network {
            NetworkEnv::Mainnet => "https://api.mainnet-beta.solana.com".into(),
            NetworkEnv::Devnet => "https://api.devnet.solana.com".into(),
            _ => "https://api.testnet.solana.com".into(),
        });
    }
    if chain == Chain::Sui {
        return Ok(match network {
            NetworkEnv::Mainnet => "https://fullnode.mainnet.sui.io:443".into(),
            NetworkEnv::Devnet => "https://fullnode.devnet.sui.io:443".into(),
            _ => "https://fullnode.testnet.sui.io:443".into(),
        });
    }
    if matches!(chain, Chain::Aptos | Chain::Movement) {
        // Aptos public REST endpoints.
        if chain == Chain::Aptos {
            return Ok(match network {
                NetworkEnv::Mainnet => "https://api.mainnet.aptoslabs.com".into(),
                NetworkEnv::Devnet => "https://api.devnet.aptoslabs.com".into(),
                _ => "https://api.testnet.aptoslabs.com".into(),
            });
        }
        // Movement public REST.
        return Ok(match network {
            NetworkEnv::Mainnet => "https://mainnet.movementnetwork.xyz/v1".into(),
            _ => "https://testnet.bardock.movementnetwork.xyz/v1".into(),
        });
    }
    if matches!(chain, Chain::BitcoinTestnet | Chain::BitcoinMainnet) {
        return Ok(match (chain, network) {
            (Chain::BitcoinMainnet, NetworkEnv::Mainnet) => "https://blockstream.info/api".into(),
            _ => "https://blockstream.info/testnet/api".into(),
        });
    }
    if chain == Chain::Tron {
        return Ok(match network {
            NetworkEnv::Mainnet => "https://api.trongrid.io".into(),
            _ => "https://api.shasta.trongrid.io".into(),
        });
    }

    Err(anyhow::anyhow!(
        "no default RPC for chain {chain} on {network:?} — set DWELLIR_API_KEY or pass --rpc-url"
    ))
}

/// Fetch chain-specific pre-sign data and return it as JSON to merge into `extra`.
/// Returns `None` for chains with no auto-fetch logic.
///
/// `recipient` and `value_str` are the user-supplied `--to` / `--value`. They're
/// only consumed by the EVM arm for `eth_estimateGas` against the real
/// destination (matters for ERC-20 since gas depends on whether the recipient
/// already has a non-zero token balance — first-touch storage write is ~5x
/// cheaper than overwriting).
async fn fetch_presign_extras(
    chain: Chain,
    rpc_url: &str,
    sender: &str,
    group_pubkey: &GroupPublicKey,
    token_spec: Option<&serde_json::Value>,
    recipient: &str,
    value_str: &str,
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
        // Migrated to provider.fetch_presign_extras() in Step 4 of the
        // chain-registry standardization refactor. CLI no longer owns EVM
        // RPC dance — it lives in EvmProvider.
        use mpc_wallet_chains::presign::{PresignContext, PresignExtras};
        use mpc_wallet_chains::registry::ChainRegistry;
        let registry = ChainRegistry::default_mainnet();
        let provider = registry.provider(chain).map_err(|e| anyhow::anyhow!(e))?;
        let token_typed = token_spec
            .map(|v| serde_json::from_value::<TokenIdentifier>(v.clone()))
            .transpose()
            .map_err(|e| anyhow::anyhow!("token spec deser: {e}"))?;
        let ctx = PresignContext {
            rpc_url,
            sender,
            group_pubkey,
            token: token_typed.as_ref(),
            recipient,
            value_str,
        };
        let extras = provider
            .fetch_presign_extras(ctx)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        if let PresignExtras::Evm {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } = &extras
        {
            eprintln!(
                "✓ chain_id={chain_id} nonce={nonce} fees: max_fee={max_fee_per_gas} wei priority={max_priority_fee_per_gas} wei · gas_limit={gas_limit}",
            );
        }
        return Ok(Some(extras.to_legacy_extras_json()));
    }
    if chain == Chain::Solana {
        // Migrated to provider.fetch_presign_extras() in Step 4b.
        use mpc_wallet_chains::presign::{PresignContext, PresignExtras};
        let provider = ChainRegistry::default_mainnet()
            .provider(chain)
            .map_err(|e| anyhow::anyhow!(e))?;
        let token_typed = token_spec
            .map(|v| serde_json::from_value::<TokenIdentifier>(v.clone()))
            .transpose()
            .map_err(|e| anyhow::anyhow!("token spec deser: {e}"))?;
        let ctx = PresignContext {
            rpc_url,
            sender,
            group_pubkey,
            token: token_typed.as_ref(),
            recipient,
            value_str,
        };
        let extras = provider
            .fetch_presign_extras(ctx)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        if let PresignExtras::Sol {
            recent_blockhash, ..
        } = &extras
        {
            eprintln!("✓ recent_blockhash={recent_blockhash}");
        }
        return Ok(Some(extras.to_legacy_extras_json()));
    }
    if matches!(chain, Chain::BitcoinTestnet | Chain::BitcoinMainnet) {
        let rpc = BitcoinRpcClient::new(rpc_url);
        let utxos = rpc
            .get_utxos(sender)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let total: u64 = utxos.iter().map(|u| u.value).sum();
        eprintln!("✓ {} UTXO(s) totalling {} sats", utxos.len(), total);
        let pubkey_hex = compressed_pubkey_hex(group_pubkey)?;
        // Pass UTXO list as JSON; the tx builder picks the largest one.
        let utxos_json: Vec<serde_json::Value> = utxos
            .into_iter()
            .map(|u| {
                serde_json::json!({
                    "txid": u.txid,
                    "vout": u.vout,
                    "value": u.value,
                })
            })
            .collect();
        return Ok(Some(serde_json::json!({
            "addr_type": "p2wpkh",
            "pubkey_hex": pubkey_hex,
            "utxos": utxos_json,
            "change_address": sender,
            "fee_rate_sat_per_vb": 2u64,
        })));
    }
    if chain == Chain::Sui {
        use mpc_wallet_chains::sui::rpc_client::SuiRpcClient;
        let rpc = SuiRpcClient::new(rpc_url);

        // Always fetch SUI coins for gas payment (regardless of token).
        let sui_coins = rpc
            .get_owned_coins(sender, "0x2::sui::SUI")
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        if sui_coins.is_empty() {
            return Err(anyhow::anyhow!(
                "Sui sender {sender} owns no SUI coin objects — needed for gas; fund via https://faucet.sui.io/"
            ));
        }
        let gas_coin = sui_coins
            .iter()
            .max_by_key(|c| c.balance.0)
            .expect("non-empty checked above");
        let gas_price = rpc
            .get_reference_gas_price()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        eprintln!(
            "✓ gas_coin={} version={} balance={} MIST · ref_price={} MIST/gas",
            gas_coin.object_id, gas_coin.version.0, gas_coin.balance.0, gas_price
        );

        let pubkey_hex = match group_pubkey {
            GroupPublicKey::Ed25519(b) if b.len() == 32 => hex::encode(b),
            _ => return Err(anyhow::anyhow!("Sui requires 32-byte Ed25519 group key")),
        };

        let mut presign = serde_json::json!({
            "sender": sender,
            "pubkey_hex": pubkey_hex,
            "gas_payment_object_id": gas_coin.object_id,
            "gas_payment_version": gas_coin.version.0,
            "gas_payment_digest": gas_coin.digest,
            "gas_price": gas_price,
            "gas_budget": 10_000_000u64,
        });

        // For Sui Coin<T> transfers, also fetch a source coin object of that type.
        if let Some(t) = token_spec {
            if t.get("kind").and_then(|v| v.as_str()) == Some("sui") {
                let coin_type = t
                    .get("type_tag")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Sui token spec missing type_tag"))?;
                let token_coins = rpc
                    .get_owned_coins(sender, coin_type)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;
                if token_coins.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Sui sender {sender} owns no Coin<{coin_type}> objects — fund via the relevant faucet"
                    ));
                }
                let src = token_coins
                    .iter()
                    .max_by_key(|c| c.balance.0)
                    .expect("non-empty");
                eprintln!(
                    "✓ source_coin<{coin_type}>={} version={} balance={}",
                    src.object_id, src.version.0, src.balance.0
                );
                if let serde_json::Value::Object(ref mut o) = presign {
                    o.insert(
                        "coin_payment_object_id".into(),
                        serde_json::json!(src.object_id),
                    );
                    o.insert(
                        "coin_payment_version".into(),
                        serde_json::json!(src.version.0),
                    );
                    o.insert("coin_payment_digest".into(), serde_json::json!(src.digest));
                }
            }
        }

        return Ok(Some(presign));
    }
    if matches!(chain, Chain::Aptos | Chain::Movement) {
        use mpc_wallet_chains::aptos::rpc_client::AptosRpcClient;
        let rpc = AptosRpcClient::new(rpc_url);
        let account = rpc
            .get_account(sender)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let chain_id = rpc.get_chain_id().await.map_err(|e| anyhow::anyhow!(e))?;
        let gas_unit_price = rpc
            .estimate_gas_price()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let expiration = now.saturating_add(60); // valid for 60 seconds
                                                 // Sender's Ed25519 pubkey, hex-encoded for the AptosProvider extras path.
        let pubkey_hex = match group_pubkey {
            GroupPublicKey::Ed25519(b) if b.len() == 32 => hex::encode(b),
            _ => return Err(anyhow::anyhow!("Aptos requires 32-byte Ed25519 group key")),
        };
        // Aptos validators reject txs whose `max_gas_amount * gas_unit_price`
        // is below the per-tx minimum (intrinsic gas ~1500 + signature
        // verification + script execution). 100_000 gas units is a safe
        // upper bound for a simple `aptos_account::transfer` — unused gas is
        // refunded.
        let max_gas_amount = 100_000u64;
        eprintln!(
            "✓ sequence={} chain_id={} gas_price={} octas budget={} exp=now+60s",
            account.sequence_number.0, chain_id, gas_unit_price, max_gas_amount
        );
        return Ok(Some(serde_json::json!({
            "sender": sender,
            "pubkey_hex": pubkey_hex,
            "sequence_number": account.sequence_number.0,
            "max_gas_amount": max_gas_amount,
            "gas_unit_price": gas_unit_price,
            "expiration_timestamp_secs": expiration,
            "chain_id": chain_id,
        })));
    }
    if chain == Chain::Tron {
        use mpc_wallet_chains::tron::rpc_client::TronRpcClient;
        let rpc = TronRpcClient::new(rpc_url);
        let block_ref = rpc.get_now_block().await.map_err(|e| anyhow::anyhow!(e))?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let expiration = now_ms.saturating_add(60_000);
        let owner_hex = hex::encode(
            mpc_wallet_chains::tron::tx::decode_tron_address(sender)
                .map_err(|e| anyhow::anyhow!(e))?,
        );

        // fee_limit policy — diverges by contract type:
        //   - TransferContract (native TRX): MUST omit per L-017
        //   - TriggerSmartContract (TRC-20):  MUST include (validator rejects without)
        let is_trc20 = token_spec
            .and_then(|v| v.get("kind"))
            .and_then(|v| v.as_str())
            == Some("tron");
        let mut presign = serde_json::json!({
            "owner_address": owner_hex,
            "ref_block_bytes": hex::encode(block_ref.ref_block_bytes),
            "ref_block_hash": hex::encode(block_ref.ref_block_hash),
            "timestamp": now_ms,
            "expiration": expiration,
        });
        if is_trc20 {
            // Default 100 TRX cap; refunded for unused energy.
            if let serde_json::Value::Object(ref mut o) = presign {
                o.insert("fee_limit".into(), serde_json::json!(100_000_000i64));
            }
            eprintln!(
                "✓ block=ref_block_bytes:0x{} hash:0x{} exp=now+60s fee_limit=100_000_000 sun (TRC-20)",
                hex::encode(block_ref.ref_block_bytes),
                hex::encode(block_ref.ref_block_hash),
            );
        } else {
            eprintln!(
                "✓ block=ref_block_bytes:0x{} hash:0x{} exp=now+60s (fee_limit omitted — native TransferContract)",
                hex::encode(block_ref.ref_block_bytes),
                hex::encode(block_ref.ref_block_hash),
            );
        }
        return Ok(Some(presign));
    }
    Ok(None)
}

/// Render a `GroupPublicKey` as a 33-byte compressed hex string for chains
/// (like Bitcoin P2WPKH) that need it in `extras`.
fn compressed_pubkey_hex(group_pubkey: &GroupPublicKey) -> anyhow::Result<String> {
    match group_pubkey {
        GroupPublicKey::Secp256k1(bytes) if bytes.len() == 33 => Ok(hex::encode(bytes)),
        GroupPublicKey::Secp256k1Uncompressed(bytes) if bytes.len() == 65 => {
            let parity = if bytes[64] & 1 == 0 { 0x02 } else { 0x03 };
            let mut out = Vec::with_capacity(33);
            out.push(parity);
            out.extend_from_slice(&bytes[1..33]);
            Ok(hex::encode(out))
        }
        other => Err(anyhow::anyhow!(
            "compressed_pubkey_hex: expected secp256k1 key, got {:?}",
            std::mem::discriminant(other)
        )),
    }
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

/// Translate `--token <shorthand>` (or `--token-json <json>`) into the canonical
/// JSON `TokenIdentifier` shape that chain providers parse. Returns `None` for
/// the implicit native case (no flag set, or shorthand "native").
fn parse_token_spec(
    shorthand: Option<&str>,
    json: Option<&str>,
) -> anyhow::Result<Option<serde_json::Value>> {
    if let Some(j) = json {
        let v: serde_json::Value =
            serde_json::from_str(j).map_err(|e| anyhow::anyhow!("invalid --token-json: {e}"))?;
        return Ok(Some(v));
    }
    let Some(s) = shorthand else {
        return Ok(None);
    };
    if s == "native" {
        return Ok(None);
    }
    let (prefix, rest) = s.split_once(':').ok_or_else(|| {
        anyhow::anyhow!("--token shorthand must be 'native' or '<kind>:<args>', got '{s}'")
    })?;
    let v = match prefix {
        "erc20" => serde_json::json!({
            "kind": "evm", "contract": rest, "standard": "erc20",
        }),
        "erc721" | "erc1155" => {
            return Err(anyhow::anyhow!(
                "--token {prefix}: NFT support deferred; see docs/TOKEN_TRANSFER_DESIGN.md §7"
            ));
        }
        "spl" | "spl-2022" => {
            let parts: Vec<&str> = rest.split(':').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!(
                    "--token spl shorthand: '{prefix}:<mint>:<decimals>'"
                ));
            }
            let decimals: u8 = parts[1]
                .parse()
                .map_err(|e| anyhow::anyhow!("--token spl decimals must be u8: {e}"))?;
            let program = if prefix == "spl-2022" {
                "token2022"
            } else {
                "spl_token"
            };
            serde_json::json!({
                "kind": "spl", "mint": parts[0], "program": program, "decimals": decimals,
            })
        }
        "sui-coin" => serde_json::json!({ "kind": "sui", "type_tag": rest }),
        "aptos-coin" => serde_json::json!({
            "kind": "aptos", "flavor": { "type": "coin", "type_tag": rest },
        }),
        "aptos-fa" => serde_json::json!({
            "kind": "aptos", "flavor": { "type": "fungible_asset", "metadata": rest },
        }),
        "trc20" => serde_json::json!({ "kind": "tron", "contract": rest }),
        other => {
            return Err(anyhow::anyhow!(
                "--token: unknown shorthand prefix '{other}'"
            ))
        }
    };
    Ok(Some(v))
}

/// Query an ERC-20 contract's `balanceOf(holder)` via `eth_call`. Returns the
/// balance as a decimal string (uint256 — could exceed u64).
async fn erc20_balance_of(
    rpc: &EvmRpcClient,
    contract: &str,
    holder: &str,
) -> anyhow::Result<String> {
    use mpc_wallet_chains::evm::erc20;
    let calldata = erc20::encode_balance_of(holder).map_err(|e| anyhow::anyhow!(e))?;
    let result_hex = rpc
        .eth_call(contract, &format!("0x{}", hex::encode(calldata)))
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let bytes = hex::decode(result_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("balanceOf returned non-hex: {e}"))?;
    erc20::decode_uint256_decimal(&bytes).map_err(|e| anyhow::anyhow!(e))
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
        (Chain::Sui, NetworkEnv::Mainnet) => "https://suiscan.xyz/mainnet/tx/",
        (Chain::Sui, _) => "https://suiscan.xyz/testnet/tx/",
        (Chain::Aptos, NetworkEnv::Mainnet) => "https://aptoscan.com/transaction/",
        (Chain::Aptos, NetworkEnv::Devnet) => "https://aptoscan.com/transaction/{}?network=devnet",
        (Chain::Aptos, _) => "https://aptoscan.com/transaction/{}?network=testnet",
        (Chain::Movement, _) => "https://explorer.movementnetwork.xyz/txn/{}?network=testnet",
        (Chain::BitcoinMainnet, _) => "https://mempool.space/tx/",
        (Chain::BitcoinTestnet, _) => "https://mempool.space/testnet/tx/",
        (Chain::Tron, NetworkEnv::Mainnet) => "https://tronscan.org/#/transaction/",
        (Chain::Tron, _) => "https://shasta.tronscan.org/#/transaction/",
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
    fn test_default_rpc_solana_devnet_no_dwellir() {
        // Without Dwellir key → falls back to public Solana endpoint.
        let url = resolve_default_rpc_url(Chain::Solana, &NetworkEnv::Devnet, None, None).unwrap();
        assert!(url.contains("devnet.solana.com"));
    }

    #[test]
    fn test_default_rpc_solana_devnet_with_dwellir() {
        // With Dwellir key → Dwellir URL preferred over public.
        let url =
            resolve_default_rpc_url(Chain::Solana, &NetworkEnv::Devnet, Some("KEY"), None).unwrap();
        assert!(url.contains("dwellir.com"));
        assert!(url.contains("/KEY"));
    }

    #[test]
    fn test_default_rpc_evm_dwellir_first() {
        // Both keys present → Dwellir wins for EVM.
        let url = resolve_default_rpc_url(
            Chain::Ethereum,
            &NetworkEnv::Testnet,
            Some("DK"),
            Some("IK"),
        )
        .unwrap();
        assert!(url.contains("dwellir.com"), "got {url}");
        assert!(url.contains("ethereum-sepolia"));
    }

    #[test]
    fn test_default_rpc_evm_falls_back_to_infura() {
        // Only Infura set → Infura URL.
        let url =
            resolve_default_rpc_url(Chain::Ethereum, &NetworkEnv::Testnet, None, Some("PROJ"))
                .unwrap();
        assert!(url.contains("infura.io"), "got {url}");
        assert!(url.contains("sepolia"));
    }

    #[test]
    fn test_default_rpc_evm_no_keys_errors() {
        let r = resolve_default_rpc_url(Chain::Ethereum, &NetworkEnv::Testnet, None, None);
        assert!(r.is_err());
    }

    #[test]
    fn test_default_rpc_bitcoin_unchanged() {
        // Bitcoin always uses Blockstream Esplora regardless of keys.
        let url =
            resolve_default_rpc_url(Chain::BitcoinTestnet, &NetworkEnv::Testnet, Some("X"), None)
                .unwrap();
        assert!(url.contains("blockstream.info/testnet/api"));
    }

    #[test]
    fn test_default_rpc_unsupported_chain_no_dwellir() {
        // Monero — no provider, no public fallback.
        let r = resolve_default_rpc_url(Chain::Monero, &NetworkEnv::Mainnet, None, None);
        assert!(r.is_err());
    }
}
