//! Dwellir RPC provider preset.
//!
//! Dwellir uses a single API key for all supported chains.
//! HTTPS: `https://{chain}-rpc.dwellir.com/{api_key}`
//! WSS:   `wss://{chain}-rpc.dwellir.com/{api_key}`

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

    /// Map Chain to Dwellir's subdomain prefix.
    fn chain_slug(chain: Chain, network: &NetworkEnv) -> Option<&'static str> {
        match (chain, network) {
            // EVM L1s
            (Chain::Ethereum, NetworkEnv::Testnet) => Some("ethereum-sepolia"),
            (Chain::Ethereum, _) => Some("ethereum"),
            (Chain::Polygon, NetworkEnv::Testnet) => Some("polygon-amoy"),
            (Chain::Polygon, _) => Some("polygon"),
            (Chain::Bsc, NetworkEnv::Testnet) => Some("bsc-testnet"),
            (Chain::Bsc, _) => Some("bsc"),
            // EVM L2s — P0
            (Chain::Arbitrum, NetworkEnv::Testnet) => Some("arbitrum-sepolia"),
            (Chain::Arbitrum, _) => Some("arbitrum"),
            (Chain::Optimism, NetworkEnv::Testnet) => Some("optimism-sepolia"),
            (Chain::Optimism, _) => Some("optimism"),
            (Chain::Base, NetworkEnv::Testnet) => Some("base-sepolia"),
            (Chain::Base, _) => Some("base"),
            // EVM L2s — P1
            (Chain::Avalanche, NetworkEnv::Testnet) => Some("avalanche-fuji"),
            (Chain::Avalanche, _) => Some("avalanche"),
            (Chain::Linea, NetworkEnv::Testnet) => Some("linea-sepolia"),
            (Chain::Linea, _) => Some("linea"),
            (Chain::ZkSync, _) => Some("zksync"),
            (Chain::Scroll, _) => Some("scroll"),
            // EVM L2s — P2
            (Chain::Mantle, _) => Some("mantle"),
            (Chain::Blast, _) => Some("blast"),
            (Chain::Zora, _) => Some("zora"),
            (Chain::Fantom, _) => Some("fantom"),
            (Chain::Gnosis, _) => Some("gnosis"),
            // EVM L2s — P3
            (Chain::Cronos, _) => Some("cronos"),
            (Chain::Celo, _) => Some("celo"),
            (Chain::Moonbeam, _) => Some("moonbeam"),
            (Chain::Ronin, _) => Some("ronin"),
            (Chain::OpBnb, _) => Some("opbnb"),
            (Chain::Immutable, _) => Some("immutable"),
            (Chain::MantaPacific, _) => Some("manta-pacific"),
            // Non-EVM
            (Chain::BitcoinMainnet, _) => Some("bitcoin"),
            (Chain::Solana, _) => Some("solana"),
            (Chain::Sui, _) => Some("sui"),
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
            Chain::BitcoinMainnet,
            Chain::Solana,
            Chain::Sui,
        ]
    }

    fn https_endpoint(&self, chain: Chain, network: &NetworkEnv) -> Option<String> {
        let slug = Self::chain_slug(chain, network)?;
        Some(format!("https://{slug}-rpc.dwellir.com/{}", self.api_key))
    }

    fn wss_endpoint(&self, chain: Chain, network: &NetworkEnv) -> Option<String> {
        let slug = Self::chain_slug(chain, network)?;
        Some(format!("wss://{slug}-rpc.dwellir.com/{}", self.api_key))
    }

    fn api_key_header(&self) -> Option<(&str, &str)> {
        None // Dwellir uses path-based auth
    }
}
