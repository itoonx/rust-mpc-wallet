//! Mempool.space REST API provider.
//!
//! Mainnet: `https://mempool.space/api`
//! Testnet: `https://mempool.space/testnet/api`

use crate::provider::Chain;
use crate::registry::NetworkEnv;
use crate::rpc::{RpcProtocol, RpcProvider};

/// Mempool.space REST API provider for Bitcoin.
pub struct MempoolProvider;

impl MempoolProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MempoolProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl RpcProvider for MempoolProvider {
    fn name(&self) -> &str {
        "mempool"
    }

    fn supported_chains(&self) -> Vec<Chain> {
        vec![Chain::BitcoinMainnet, Chain::BitcoinTestnet]
    }

    fn https_endpoint(&self, chain: Chain, _network: &NetworkEnv) -> Option<String> {
        match chain {
            Chain::BitcoinMainnet => Some("https://mempool.space/api".into()),
            Chain::BitcoinTestnet => Some("https://mempool.space/testnet/api".into()),
            _ => None,
        }
    }

    fn wss_endpoint(&self, _chain: Chain, _network: &NetworkEnv) -> Option<String> {
        None // Mempool.space REST API doesn't offer WebSocket
    }

    fn api_key_header(&self) -> Option<(&str, &str)> {
        None
    }

    fn protocol(&self) -> RpcProtocol {
        RpcProtocol::Rest
    }
}
