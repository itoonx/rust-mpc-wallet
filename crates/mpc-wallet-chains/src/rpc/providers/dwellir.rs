//! Dwellir RPC provider preset.
//!
//! Dwellir uses a single API key for all supported chains.
//! HTTPS: `https://api-{slug}.n.dwellir.com/{api_key}`
//! WSS:   `wss://api-{slug}.n.dwellir.com/{api_key}`
//!
//! Slug convention (verified against Dwellir's live endpoints, May 2026):
//! - EVM: `{chain}-{network}` — e.g. `ethereum-mainnet`, `ethereum-sepolia`,
//!   `polygon-amoy`, `arbitrum-sepolia`.
//! - Substrate / cosmos / specialized: bare chain name (no `-mainnet` suffix) —
//!   e.g. `polkadot`, `kusama`.
//! - Aptos / Movement / Solana / Sui: `{chain}-mainnet` for mainnet, `-testnet`
//!   / `-devnet` for non-mainnet.
//!
//! Per-account chain availability varies — a missing endpoint surfaces as a
//! DNS resolution failure when the URL is requested.

use crate::provider::Chain;
use crate::registry::NetworkEnv;
use crate::rpc::RpcProvider;

/// Dwellir RPC provider — single API key, multiple chains.
pub struct DwellirProvider {
    api_key: String,
}

impl DwellirProvider {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
        }
    }

    /// Map Chain to Dwellir's subdomain slug.
    fn chain_slug(chain: Chain, network: &NetworkEnv) -> Option<&'static str> {
        match (chain, network) {
            // EVM L1s
            (Chain::Ethereum, NetworkEnv::Testnet) => Some("ethereum-sepolia"),
            (Chain::Ethereum, _) => Some("ethereum-mainnet"),
            (Chain::Polygon, NetworkEnv::Testnet) => Some("polygon-amoy"),
            (Chain::Polygon, _) => Some("polygon-mainnet"),
            (Chain::Bsc, NetworkEnv::Testnet) => Some("bsc-testnet"),
            (Chain::Bsc, _) => Some("bsc-mainnet"),
            // EVM L2s — P0
            (Chain::Arbitrum, NetworkEnv::Testnet) => Some("arbitrum-sepolia"),
            (Chain::Arbitrum, _) => Some("arbitrum-mainnet"),
            (Chain::Optimism, NetworkEnv::Testnet) => Some("optimism-sepolia"),
            (Chain::Optimism, _) => Some("optimism-mainnet"),
            (Chain::Base, NetworkEnv::Testnet) => Some("base-sepolia"),
            (Chain::Base, _) => Some("base-mainnet"),
            // EVM L2s — P1
            (Chain::Avalanche, NetworkEnv::Testnet) => Some("avalanche-fuji"),
            (Chain::Avalanche, _) => Some("avalanche-mainnet"),
            (Chain::Linea, NetworkEnv::Testnet) => Some("linea-sepolia"),
            (Chain::Linea, _) => Some("linea-mainnet"),
            (Chain::ZkSync, _) => Some("zksync-mainnet"),
            (Chain::Scroll, _) => Some("scroll-mainnet"),
            // EVM L2s — P2
            (Chain::Mantle, _) => Some("mantle-mainnet"),
            (Chain::Blast, _) => Some("blast-mainnet"),
            (Chain::Zora, _) => Some("zora-mainnet"),
            (Chain::Fantom, _) => Some("fantom-mainnet"),
            (Chain::Gnosis, _) => Some("gnosis-mainnet"),
            // EVM L2s — P3
            (Chain::Cronos, _) => Some("cronos-mainnet"),
            (Chain::Celo, _) => Some("celo-mainnet"),
            (Chain::Moonbeam, _) => Some("moonbeam"),
            (Chain::Ronin, _) => Some("ronin-mainnet"),
            (Chain::OpBnb, _) => Some("opbnb-mainnet"),
            (Chain::Immutable, _) => Some("immutable-mainnet"),
            (Chain::MantaPacific, _) => Some("manta-pacific-mainnet"),
            // EVM — Phase 5
            (Chain::Hyperliquid, _) => Some("hyperliquid-mainnet"),
            (Chain::Berachain, _) => Some("berachain-mainnet"),
            (Chain::MegaEth, _) => Some("megaeth-mainnet"),
            (Chain::Monad, _) => Some("monad-mainnet"),
            // Move chains
            (Chain::Aptos, NetworkEnv::Testnet) => Some("aptos-testnet"),
            (Chain::Aptos, _) => Some("aptos-mainnet"),
            (Chain::Movement, NetworkEnv::Testnet) => Some("movement-testnet"),
            (Chain::Movement, _) => Some("movement-mainnet"),
            // Substrate / Polkadot — bare chain name (no -mainnet suffix)
            (Chain::Polkadot, _) => Some("polkadot"),
            (Chain::Kusama, _) => Some("kusama"),
            (Chain::Astar, _) => Some("astar"),
            (Chain::Acala, _) => Some("acala"),
            (Chain::Phala, _) => Some("phala"),
            (Chain::Interlay, _) => Some("interlay"),
            // Specialized
            (Chain::Starknet, _) => Some("starknet-mainnet"),
            // Cosmos / IBC
            (Chain::CosmosHub, _) => Some("cosmoshub"),
            (Chain::Osmosis, _) => Some("osmosis"),
            (Chain::Celestia, _) => Some("celestia-mainnet"),
            (Chain::Injective, _) => Some("injective"),
            (Chain::Sei, _) => Some("sei-mainnet"),
            // Alt L1s
            (Chain::Ton, NetworkEnv::Testnet) => Some("ton-testnet"),
            (Chain::Ton, _) => Some("ton-mainnet"),
            (Chain::Tron, _) => Some("tron-mainnet"),
            // Non-EVM
            (Chain::BitcoinMainnet, _) => Some("bitcoin-mainnet"),
            (Chain::Solana, NetworkEnv::Devnet) => Some("solana-devnet"),
            (Chain::Solana, NetworkEnv::Testnet) => Some("solana-testnet"),
            (Chain::Solana, _) => Some("solana-mainnet"),
            (Chain::Sui, NetworkEnv::Testnet) => Some("sui-testnet"),
            (Chain::Sui, _) => Some("sui-mainnet"),
            _ => None,
        }
    }
}

impl RpcProvider for DwellirProvider {
    fn name(&self) -> &str {
        "dwellir"
    }

    fn supported_chains(&self) -> Vec<Chain> {
        vec![
            Chain::Ethereum,
            Chain::Polygon,
            Chain::Bsc,
            Chain::Arbitrum,
            Chain::Optimism,
            Chain::Base,
            Chain::Avalanche,
            Chain::Linea,
            Chain::ZkSync,
            Chain::Scroll,
            Chain::Mantle,
            Chain::Blast,
            Chain::Zora,
            Chain::Fantom,
            Chain::Gnosis,
            Chain::Cronos,
            Chain::Celo,
            Chain::Moonbeam,
            Chain::Ronin,
            Chain::OpBnb,
            Chain::Immutable,
            Chain::MantaPacific,
            Chain::Hyperliquid,
            Chain::Berachain,
            Chain::MegaEth,
            Chain::Monad,
            Chain::Aptos,
            Chain::Movement,
            Chain::Polkadot,
            Chain::Kusama,
            Chain::Astar,
            Chain::Acala,
            Chain::Phala,
            Chain::Interlay,
            Chain::Starknet,
            Chain::CosmosHub,
            Chain::Osmosis,
            Chain::Celestia,
            Chain::Injective,
            Chain::Sei,
            Chain::Ton,
            Chain::Tron,
            Chain::BitcoinMainnet,
            Chain::Solana,
            Chain::Sui,
        ]
    }

    fn https_endpoint(&self, chain: Chain, network: &NetworkEnv) -> Option<String> {
        let slug = Self::chain_slug(chain, network)?;
        Some(format!("https://api-{slug}.n.dwellir.com/{}", self.api_key))
    }

    fn wss_endpoint(&self, chain: Chain, network: &NetworkEnv) -> Option<String> {
        let slug = Self::chain_slug(chain, network)?;
        Some(format!("wss://api-{slug}.n.dwellir.com/{}", self.api_key))
    }

    fn api_key_header(&self) -> Option<(&str, &str)> {
        None // Dwellir uses path-based auth
    }
}
