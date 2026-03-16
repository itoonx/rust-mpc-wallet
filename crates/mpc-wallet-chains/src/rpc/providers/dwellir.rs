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
    fn chain_slug(chain: Chain) -> Option<&'static str> {
        match chain {
            Chain::Ethereum => Some("ethereum"),
            Chain::Polygon => Some("polygon"),
            Chain::Bsc => Some("bsc"),
            Chain::BitcoinMainnet => Some("bitcoin"),
            Chain::Solana => Some("solana"),
            Chain::Sui => Some("sui"),
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
            Chain::BitcoinMainnet,
            Chain::Solana,
            Chain::Sui,
        ]
    }

    fn https_endpoint(&self, chain: Chain, _network: &NetworkEnv) -> Option<String> {
        let slug = Self::chain_slug(chain)?;
        Some(format!("https://{slug}-rpc.dwellir.com/{}", self.api_key))
    }

    fn wss_endpoint(&self, chain: Chain, _network: &NetworkEnv) -> Option<String> {
        let slug = Self::chain_slug(chain)?;
        Some(format!("wss://{slug}-rpc.dwellir.com/{}", self.api_key))
    }

    fn api_key_header(&self) -> Option<(&str, &str)> {
        None // Dwellir uses path-based auth
    }
}
