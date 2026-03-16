//! Infura RPC provider preset.
//!
//! HTTPS: `https://{chain}.infura.io/v3/{project_id}`
//! WSS:   `wss://{chain}.infura.io/ws/v3/{project_id}`

use crate::provider::Chain;
use crate::registry::NetworkEnv;
use crate::rpc::RpcProvider;

/// Infura RPC provider.
pub struct InfuraProvider {
    project_id: String,
}

impl InfuraProvider {
    pub fn new(project_id: &str) -> Self {
        Self {
            project_id: project_id.to_string(),
        }
    }

    /// Map Chain to Infura's subdomain prefix.
    fn chain_slug(chain: Chain, network: &NetworkEnv) -> Option<&'static str> {
        match (chain, network) {
            (Chain::Ethereum, NetworkEnv::Mainnet) => Some("mainnet"),
            (Chain::Ethereum, NetworkEnv::Testnet) => Some("sepolia"),
            (Chain::Polygon, NetworkEnv::Mainnet) => Some("polygon-mainnet"),
            (Chain::Polygon, NetworkEnv::Testnet) => Some("polygon-amoy"),
            (Chain::Arbitrum, NetworkEnv::Mainnet) => Some("arbitrum-mainnet"),
            (Chain::Arbitrum, NetworkEnv::Testnet) => Some("arbitrum-sepolia"),
            (Chain::Optimism, NetworkEnv::Mainnet) => Some("optimism-mainnet"),
            (Chain::Optimism, NetworkEnv::Testnet) => Some("optimism-sepolia"),
            (Chain::Base, NetworkEnv::Mainnet) => Some("base-mainnet"),
            (Chain::Base, NetworkEnv::Testnet) => Some("base-sepolia"),
            (Chain::Avalanche, NetworkEnv::Mainnet) => Some("avalanche-mainnet"),
            (Chain::Avalanche, NetworkEnv::Testnet) => Some("avalanche-fuji"),
            (Chain::Linea, NetworkEnv::Mainnet) => Some("linea-mainnet"),
            (Chain::Linea, NetworkEnv::Testnet) => Some("linea-sepolia"),
            _ => None,
        }
    }
}

impl RpcProvider for InfuraProvider {
    fn name(&self) -> &str {
        "infura"
    }

    fn supported_chains(&self) -> Vec<Chain> {
        vec![
            Chain::Ethereum,
            Chain::Polygon,
            Chain::Arbitrum,
            Chain::Optimism,
            Chain::Base,
            Chain::Avalanche,
            Chain::Linea,
        ]
    }

    fn https_endpoint(&self, chain: Chain, network: &NetworkEnv) -> Option<String> {
        let slug = Self::chain_slug(chain, network)?;
        Some(format!("https://{slug}.infura.io/v3/{}", self.project_id))
    }

    fn wss_endpoint(&self, chain: Chain, network: &NetworkEnv) -> Option<String> {
        let slug = Self::chain_slug(chain, network)?;
        Some(format!("wss://{slug}.infura.io/ws/v3/{}", self.project_id))
    }

    fn api_key_header(&self) -> Option<(&str, &str)> {
        None // Infura uses path-based auth
    }
}
