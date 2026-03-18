//! Chain listing and address derivation endpoints.

use axum::{
    extract::{Path, State},
    Json,
};

use mpc_wallet_chains::provider::Chain;
use mpc_wallet_chains::registry::ChainRegistry;

use crate::errors::{ApiError, ErrorCode};
use crate::models::response::{ApiResponse, ChainInfo, ChainsListResponse};
use crate::state::AppState;

/// Categorize a chain for display purposes.
fn chain_category(chain: Chain) -> &'static str {
    match chain {
        Chain::Ethereum
        | Chain::Polygon
        | Chain::Bsc
        | Chain::Arbitrum
        | Chain::Optimism
        | Chain::Base
        | Chain::Avalanche
        | Chain::Linea
        | Chain::ZkSync
        | Chain::Scroll
        | Chain::Mantle
        | Chain::Blast
        | Chain::Zora
        | Chain::Fantom
        | Chain::Gnosis
        | Chain::Cronos
        | Chain::Celo
        | Chain::Moonbeam
        | Chain::Ronin
        | Chain::OpBnb
        | Chain::Immutable
        | Chain::MantaPacific
        | Chain::Hyperliquid
        | Chain::Berachain
        | Chain::MegaEth
        | Chain::Monad => "evm",
        Chain::BitcoinMainnet
        | Chain::BitcoinTestnet
        | Chain::Litecoin
        | Chain::Dogecoin
        | Chain::Zcash => "utxo",
        Chain::Solana => "solana",
        Chain::Sui => "sui",
        Chain::Aptos | Chain::Movement => "move",
        Chain::Polkadot
        | Chain::Kusama
        | Chain::Astar
        | Chain::Acala
        | Chain::Phala
        | Chain::Interlay => "substrate",
        Chain::CosmosHub | Chain::Osmosis | Chain::Celestia | Chain::Injective | Chain::Sei => {
            "cosmos"
        }
        Chain::Starknet => "starknet",
        Chain::Monero => "cryptonote",
        Chain::Ton => "ton",
        Chain::Tron => "tron",
    }
}

/// Display name for a chain.
fn chain_display_name(chain: Chain) -> &'static str {
    match chain {
        Chain::Ethereum => "Ethereum",
        Chain::Polygon => "Polygon",
        Chain::Bsc => "BNB Smart Chain",
        Chain::Arbitrum => "Arbitrum One",
        Chain::Optimism => "Optimism",
        Chain::Base => "Base",
        Chain::Avalanche => "Avalanche C-Chain",
        Chain::Linea => "Linea",
        Chain::ZkSync => "zkSync Era",
        Chain::Scroll => "Scroll",
        Chain::Mantle => "Mantle",
        Chain::Blast => "Blast",
        Chain::Zora => "Zora",
        Chain::Fantom => "Fantom",
        Chain::Gnosis => "Gnosis",
        Chain::Cronos => "Cronos",
        Chain::Celo => "Celo",
        Chain::Moonbeam => "Moonbeam",
        Chain::Ronin => "Ronin",
        Chain::OpBnb => "opBNB",
        Chain::Immutable => "Immutable X",
        Chain::MantaPacific => "Manta Pacific",
        Chain::Hyperliquid => "Hyperliquid",
        Chain::Berachain => "Berachain",
        Chain::MegaEth => "MegaETH",
        Chain::Monad => "Monad",
        Chain::BitcoinMainnet => "Bitcoin",
        Chain::BitcoinTestnet => "Bitcoin Testnet",
        Chain::Litecoin => "Litecoin",
        Chain::Dogecoin => "Dogecoin",
        Chain::Zcash => "Zcash",
        Chain::Solana => "Solana",
        Chain::Sui => "Sui",
        Chain::Aptos => "Aptos",
        Chain::Movement => "Movement",
        Chain::Polkadot => "Polkadot",
        Chain::Kusama => "Kusama",
        Chain::Astar => "Astar",
        Chain::Acala => "Acala",
        Chain::Phala => "Phala",
        Chain::Interlay => "Interlay",
        Chain::CosmosHub => "Cosmos Hub",
        Chain::Osmosis => "Osmosis",
        Chain::Celestia => "Celestia",
        Chain::Injective => "Injective",
        Chain::Sei => "Sei",
        Chain::Starknet => "StarkNet",
        Chain::Monero => "Monero",
        Chain::Ton => "TON",
        Chain::Tron => "TRON",
    }
}

/// `GET /v1/chains` — list all supported chains.
pub async fn list_chains() -> Json<ApiResponse<ChainsListResponse>> {
    let chains: Vec<ChainInfo> = ChainRegistry::supported_chains()
        .into_iter()
        .map(|c| ChainInfo {
            name: c.to_string(),
            display_name: chain_display_name(c).into(),
            category: chain_category(c).into(),
        })
        .collect();
    let total = chains.len();
    Json(ApiResponse::ok(ChainsListResponse { chains, total }))
}

/// `GET /v1/chains/:chain/address/:id` — derive address for a chain.
///
/// NOTE: In a production system this would load the wallet's group public key
/// from the key store and derive the chain-specific address. This stub returns
/// a placeholder demonstrating the routing.
pub async fn derive_address(
    State(state): State<AppState>,
    Path((chain_name, wallet_id)): Path<(String, String)>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let chain: Chain = chain_name
        .parse()
        .map_err(|e: String| ApiError::bad_request(ErrorCode::InvalidInput, e))?;

    // Verify the chain is supported by the registry.
    state
        .chain_registry
        .provider(chain)
        .map_err(ApiError::from)?;

    // In production: load group_pubkey from key store by wallet_id, then call
    // provider.derive_address(&group_pubkey). For now, return a stub.
    Ok(Json(ApiResponse::ok(serde_json::json!({
        "wallet_id": wallet_id,
        "chain": chain.to_string(),
        "address": format!("derive-from-keystore-for-{wallet_id}"),
        "note": "requires key store integration to return real addresses"
    }))))
}
