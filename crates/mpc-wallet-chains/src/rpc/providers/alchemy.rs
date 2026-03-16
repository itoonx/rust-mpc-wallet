//! Alchemy RPC provider preset.
//!
//! HTTPS: `https://{chain}-mainnet.g.alchemy.com/v2/{api_key}`
//! WSS:   `wss://{chain}-mainnet.g.alchemy.com/v2/{api_key}`

use crate::provider::Chain;
use crate::registry::NetworkEnv;
use crate::rpc::RpcProvider;

/// Alchemy RPC provider.
pub struct AlchemyProvider {
    api_key: String,
}

impl AlchemyProvider {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
        }
    }

    /// Map Chain to Alchemy's subdomain prefix.
    fn chain_slug(chain: Chain, network: &NetworkEnv) -> Option<&'static str> {
        match (chain, network) {
            (Chain::Ethereum, NetworkEnv::Mainnet) => Some("eth-mainnet"),
            (Chain::Ethereum, NetworkEnv::Testnet) => Some("eth-sepolia"),
            (Chain::Polygon, NetworkEnv::Mainnet) => Some("polygon-mainnet"),
            (Chain::Polygon, NetworkEnv::Testnet) => Some("polygon-amoy"),
            (Chain::Arbitrum, NetworkEnv::Mainnet) => Some("arb-mainnet"),
            (Chain::Arbitrum, NetworkEnv::Testnet) => Some("arb-sepolia"),
            (Chain::Optimism, NetworkEnv::Mainnet) => Some("opt-mainnet"),
            (Chain::Optimism, NetworkEnv::Testnet) => Some("opt-sepolia"),
            (Chain::Base, NetworkEnv::Mainnet) => Some("base-mainnet"),
            (Chain::Base, NetworkEnv::Testnet) => Some("base-sepolia"),
            _ => None,
        }
    }
}

impl RpcProvider for AlchemyProvider {
    fn name(&self) -> &str {
        "alchemy"
    }

    fn supported_chains(&self) -> Vec<Chain> {
        vec![
            Chain::Ethereum,
            Chain::Polygon,
            Chain::Arbitrum,
            Chain::Optimism,
            Chain::Base,
        ]
    }

    fn https_endpoint(&self, chain: Chain, network: &NetworkEnv) -> Option<String> {
        let slug = Self::chain_slug(chain, network)?;
        Some(format!("https://{slug}.g.alchemy.com/v2/{}", self.api_key))
    }

    fn wss_endpoint(&self, chain: Chain, network: &NetworkEnv) -> Option<String> {
        let slug = Self::chain_slug(chain, network)?;
        Some(format!("wss://{slug}.g.alchemy.com/v2/{}", self.api_key))
    }

    fn api_key_header(&self) -> Option<(&str, &str)> {
        None // Alchemy uses path-based auth
    }
}
