//! Blockstream Esplora REST API provider.
//!
//! Mainnet: `https://blockstream.info/api`
//! Testnet: `https://blockstream.info/testnet/api`

use crate::provider::Chain;
use crate::registry::NetworkEnv;
use crate::rpc::{RpcProtocol, RpcProvider};

/// Blockstream Esplora REST API provider for Bitcoin.
pub struct BlockstreamProvider;

impl BlockstreamProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BlockstreamProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl RpcProvider for BlockstreamProvider {
    fn name(&self) -> &str {
        "blockstream"
    }

    fn supported_chains(&self) -> Vec<Chain> {
        vec![Chain::BitcoinMainnet, Chain::BitcoinTestnet]
    }

    fn https_endpoint(&self, chain: Chain, _network: &NetworkEnv) -> Option<String> {
        match chain {
            Chain::BitcoinMainnet => Some("https://blockstream.info/api".into()),
            Chain::BitcoinTestnet => Some("https://blockstream.info/testnet/api".into()),
            _ => None,
        }
    }

    fn wss_endpoint(&self, _chain: Chain, _network: &NetworkEnv) -> Option<String> {
        None // Blockstream Esplora doesn't offer WebSocket
    }

    fn api_key_header(&self) -> Option<(&str, &str)> {
        None // No API key required
    }

    fn protocol(&self) -> RpcProtocol {
        RpcProtocol::Rest
    }
}
