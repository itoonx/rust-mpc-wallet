//! Custom RPC provider — user-defined endpoints per chain.

use std::collections::HashMap;

use crate::provider::Chain;
use crate::registry::NetworkEnv;
use crate::rpc::RpcProvider;

/// User-defined custom RPC provider with explicit per-chain endpoints.
pub struct CustomProvider {
    provider_name: String,
    https_endpoints: HashMap<Chain, String>,
    wss_endpoints: HashMap<Chain, String>,
}

impl CustomProvider {
    pub fn new(
        name: &str,
        https_endpoints: HashMap<Chain, String>,
        wss_endpoints: HashMap<Chain, String>,
    ) -> Self {
        Self {
            provider_name: name.to_string(),
            https_endpoints,
            wss_endpoints,
        }
    }
}

impl RpcProvider for CustomProvider {
    fn name(&self) -> &str {
        &self.provider_name
    }

    fn supported_chains(&self) -> Vec<Chain> {
        let mut chains: Vec<Chain> = self
            .https_endpoints
            .keys()
            .chain(self.wss_endpoints.keys())
            .copied()
            .collect();
        chains.sort_by_key(|c| format!("{c:?}"));
        chains.dedup();
        chains
    }

    fn https_endpoint(&self, chain: Chain, _network: &NetworkEnv) -> Option<String> {
        self.https_endpoints.get(&chain).cloned()
    }

    fn wss_endpoint(&self, chain: Chain, _network: &NetworkEnv) -> Option<String> {
        self.wss_endpoints.get(&chain).cloned()
    }

    fn api_key_header(&self) -> Option<(&str, &str)> {
        None
    }
}
