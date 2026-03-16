//! RPC Registry — multi-provider standardized interface.
//!
//! Provides a unified registry for RPC providers (Dwellir, Alchemy, Infura, etc.)
//! with failover, health tracking, and per-chain configuration.

pub mod providers;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::provider::Chain;
use crate::registry::NetworkEnv;
use mpc_wallet_core::error::CoreError;

/// The API protocol used by an RPC provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcProtocol {
    /// JSON-RPC 2.0 (EVM, Solana, Sui, Bitcoin Core).
    JsonRpc,
    /// REST/HTTP API (Blockstream Esplora, Mempool.space).
    Rest,
}

/// Trait that every RPC provider must implement.
pub trait RpcProvider: Send + Sync {
    /// Human-readable provider name (e.g. "dwellir", "alchemy").
    fn name(&self) -> &str;

    /// Chains this provider supports.
    fn supported_chains(&self) -> Vec<Chain>;

    /// HTTPS endpoint for the given chain/network.
    fn https_endpoint(&self, chain: Chain, network: &NetworkEnv) -> Option<String>;

    /// WebSocket endpoint for subscriptions/real-time events.
    fn wss_endpoint(&self, chain: Chain, network: &NetworkEnv) -> Option<String>;

    /// Optional API key header: `(header_name, key_value)`.
    fn api_key_header(&self) -> Option<(&str, &str)>;

    /// The API protocol this provider uses. Defaults to JSON-RPC.
    fn protocol(&self) -> RpcProtocol {
        RpcProtocol::JsonRpc
    }
}

/// Transport protocol for an RPC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcTransport {
    /// JSON-RPC over HTTPS.
    Https,
    /// JSON-RPC over WebSocket (subscriptions, real-time).
    Wss,
    /// REST API over HTTPS.
    Rest,
}

/// Single RPC endpoint configuration.
#[derive(Debug, Clone)]
pub struct RpcEndpointConfig {
    pub url: String,
    pub provider_name: String,
    pub transport: RpcTransport,
    pub protocol: RpcProtocol,
    pub priority: u8,
    pub weight: u8,
    pub is_archive: bool,
}

/// Per-chain RPC configuration.
#[derive(Debug, Clone)]
pub struct ChainRpcConfig {
    pub chain: Chain,
    pub endpoints: Vec<RpcEndpointConfig>,
    pub timeout_ms: u64,
    pub max_retries: u8,
}

impl ChainRpcConfig {
    pub fn new(chain: Chain) -> Self {
        Self {
            chain,
            endpoints: Vec::new(),
            timeout_ms: 30_000,
            max_retries: 3,
        }
    }
}

/// Health status of an endpoint.
#[derive(Debug, Clone)]
struct EndpointHealth {
    healthy: bool,
}

/// Central registry for managing RPC providers with failover and health tracking.
pub struct RpcRegistry {
    providers: Vec<Box<dyn RpcProvider>>,
    chain_config: HashMap<Chain, ChainRpcConfig>,
    default_provider: Option<String>,
    network: NetworkEnv,
    /// Tracks health per endpoint URL.
    health: Arc<RwLock<HashMap<String, EndpointHealth>>>,
}

impl RpcRegistry {
    /// Start building a new registry.
    pub fn builder() -> RpcRegistryBuilder {
        RpcRegistryBuilder {
            providers: Vec::new(),
            chain_config: HashMap::new(),
            default_provider: None,
            network: NetworkEnv::Mainnet,
        }
    }

    /// Get the HTTPS endpoint for a chain from the default provider.
    pub fn endpoint(&self, chain: Chain) -> Result<String, CoreError> {
        if let Some(ref default) = self.default_provider {
            return self.endpoint_from(default, chain);
        }
        // Try each provider in order.
        for provider in &self.providers {
            if let Some(url) = provider.https_endpoint(chain, &self.network) {
                return Ok(url);
            }
        }
        Err(CoreError::Other(format!(
            "no RPC endpoint for chain {chain}"
        )))
    }

    /// Get the HTTPS endpoint from a specific named provider.
    pub fn endpoint_from(&self, provider_name: &str, chain: Chain) -> Result<String, CoreError> {
        for provider in &self.providers {
            if provider.name() == provider_name {
                return provider
                    .https_endpoint(chain, &self.network)
                    .ok_or_else(|| {
                        CoreError::Other(format!(
                            "provider '{provider_name}' does not support chain {chain}"
                        ))
                    });
            }
        }
        Err(CoreError::Other(format!(
            "unknown provider: {provider_name}"
        )))
    }

    /// Get the WebSocket endpoint for a chain from the default provider.
    pub fn ws_endpoint(&self, chain: Chain) -> Result<String, CoreError> {
        if let Some(ref default) = self.default_provider {
            return self.ws_endpoint_from(default, chain);
        }
        for provider in &self.providers {
            if let Some(url) = provider.wss_endpoint(chain, &self.network) {
                return Ok(url);
            }
        }
        Err(CoreError::Other(format!(
            "no WebSocket endpoint for chain {chain}"
        )))
    }

    /// Get the WebSocket endpoint from a specific named provider.
    pub fn ws_endpoint_from(&self, provider_name: &str, chain: Chain) -> Result<String, CoreError> {
        for provider in &self.providers {
            if provider.name() == provider_name {
                return provider
                    .wss_endpoint(chain, &self.network)
                    .ok_or_else(|| {
                        CoreError::Other(format!(
                            "provider '{provider_name}' does not support chain {chain} (wss)"
                        ))
                    });
            }
        }
        Err(CoreError::Other(format!(
            "unknown provider: {provider_name}"
        )))
    }

    /// Mark an endpoint URL as unhealthy.
    pub fn mark_unhealthy(&self, url: &str) {
        let mut health = self.health.write().expect("health lock poisoned");
        health.insert(
            url.to_string(),
            EndpointHealth { healthy: false },
        );
    }

    /// Mark an endpoint URL as healthy.
    pub fn mark_healthy(&self, url: &str) {
        let mut health = self.health.write().expect("health lock poisoned");
        health.insert(
            url.to_string(),
            EndpointHealth { healthy: true },
        );
    }

    fn is_healthy(&self, url: &str) -> bool {
        let health = self.health.read().expect("health lock poisoned");
        health
            .get(url)
            .map(|h| h.healthy)
            .unwrap_or(true) // unknown = healthy
    }

    /// Get the next healthy HTTPS endpoint for a chain, trying all providers in order.
    pub fn next_healthy_endpoint(&self, chain: Chain) -> Result<String, CoreError> {
        for provider in &self.providers {
            if let Some(url) = provider.https_endpoint(chain, &self.network) {
                if self.is_healthy(&url) {
                    return Ok(url);
                }
            }
        }
        Err(CoreError::Other(format!(
            "no healthy RPC endpoint for chain {chain}"
        )))
    }

    /// Get a REST API endpoint for a chain (e.g. Bitcoin via Blockstream).
    /// Only returns endpoints from providers whose protocol is `RpcProtocol::Rest`.
    pub fn rest_endpoint(&self, chain: Chain) -> Result<String, CoreError> {
        for provider in &self.providers {
            if provider.protocol() == RpcProtocol::Rest {
                if let Some(url) = provider.https_endpoint(chain, &self.network) {
                    return Ok(url);
                }
            }
        }
        Err(CoreError::Other(format!(
            "no REST endpoint for chain {chain}"
        )))
    }

    /// Get a REST API endpoint from a specific named provider.
    pub fn rest_endpoint_from(
        &self,
        provider_name: &str,
        chain: Chain,
    ) -> Result<String, CoreError> {
        for provider in &self.providers {
            if provider.name() == provider_name && provider.protocol() == RpcProtocol::Rest {
                return provider
                    .https_endpoint(chain, &self.network)
                    .ok_or_else(|| {
                        CoreError::Other(format!(
                            "REST provider '{provider_name}' does not support chain {chain}"
                        ))
                    });
            }
        }
        Err(CoreError::Other(format!(
            "unknown REST provider: {provider_name}"
        )))
    }

    /// Get the next healthy endpoint for a chain, filtered by protocol.
    pub fn next_healthy_endpoint_with_protocol(
        &self,
        chain: Chain,
        protocol: RpcProtocol,
    ) -> Result<String, CoreError> {
        for provider in &self.providers {
            if provider.protocol() == protocol {
                if let Some(url) = provider.https_endpoint(chain, &self.network) {
                    if self.is_healthy(&url) {
                        return Ok(url);
                    }
                }
            }
        }
        Err(CoreError::Other(format!(
            "no healthy {protocol:?} endpoint for chain {chain}"
        )))
    }

    /// Get per-chain RPC config (timeout, retries).
    pub fn chain_config(&self, chain: Chain) -> Option<&ChainRpcConfig> {
        self.chain_config.get(&chain)
    }

    /// List all registered provider names.
    pub fn provider_names(&self) -> Vec<&str> {
        self.providers.iter().map(|p| p.name()).collect()
    }
}

/// Builder for constructing an `RpcRegistry`.
pub struct RpcRegistryBuilder {
    providers: Vec<Box<dyn RpcProvider>>,
    chain_config: HashMap<Chain, ChainRpcConfig>,
    default_provider: Option<String>,
    network: NetworkEnv,
}

impl RpcRegistryBuilder {
    /// Add a provider to the registry.
    pub fn add_provider(mut self, provider: impl RpcProvider + 'static) -> Self {
        self.providers.push(Box::new(provider));
        self
    }

    /// Set the default provider name.
    pub fn set_default(mut self, name: &str) -> Self {
        self.default_provider = Some(name.to_string());
        self
    }

    /// Set the network environment.
    pub fn network(mut self, env: NetworkEnv) -> Self {
        self.network = env;
        self
    }

    /// Set per-chain RPC config.
    pub fn chain_rpc_config(mut self, config: ChainRpcConfig) -> Self {
        self.chain_config.insert(config.chain, config);
        self
    }

    /// Build the registry.
    pub fn build(self) -> RpcRegistry {
        RpcRegistry {
            providers: self.providers,
            chain_config: self.chain_config,
            default_provider: self.default_provider,
            network: self.network,
            health: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::providers::{
        alchemy::AlchemyProvider, blockstream::BlockstreamProvider, custom::CustomProvider,
        dwellir::DwellirProvider, infura::InfuraProvider, mempool::MempoolProvider,
    };

    #[test]
    fn test_registry_add_multiple_providers() {
        let rpc = RpcRegistry::builder()
            .add_provider(DwellirProvider::new("dw-key"))
            .add_provider(AlchemyProvider::new("al-key"))
            .build();
        assert_eq!(rpc.provider_names().len(), 2);
        assert!(rpc.provider_names().contains(&"dwellir"));
        assert!(rpc.provider_names().contains(&"alchemy"));
    }

    #[test]
    fn test_registry_default_provider() {
        let rpc = RpcRegistry::builder()
            .add_provider(DwellirProvider::new("dw-key"))
            .add_provider(AlchemyProvider::new("al-key"))
            .set_default("alchemy")
            .build();
        let url = rpc.endpoint(Chain::Ethereum).unwrap();
        assert!(url.contains("alchemy"));
    }

    #[test]
    fn test_registry_specific_provider() {
        let rpc = RpcRegistry::builder()
            .add_provider(DwellirProvider::new("dw-key"))
            .add_provider(AlchemyProvider::new("al-key"))
            .set_default("dwellir")
            .build();
        let url = rpc.endpoint_from("alchemy", Chain::Ethereum).unwrap();
        assert!(url.contains("alchemy"));
    }

    #[test]
    fn test_registry_unsupported_chain() {
        let rpc = RpcRegistry::builder()
            .add_provider(AlchemyProvider::new("al-key"))
            .build();
        // Alchemy doesn't support Sui
        let result = rpc.endpoint(Chain::Sui);
        assert!(result.is_err());
    }

    #[test]
    fn test_dwellir_endpoint_format() {
        let provider = DwellirProvider::new("test-key");
        let url = provider
            .https_endpoint(Chain::Ethereum, &NetworkEnv::Mainnet)
            .unwrap();
        assert!(url.starts_with("https://"));
        assert!(url.contains("dwellir.com"));
        assert!(url.contains("test-key"));
    }

    #[test]
    fn test_alchemy_endpoint_format() {
        let provider = AlchemyProvider::new("test-key");
        let url = provider
            .https_endpoint(Chain::Ethereum, &NetworkEnv::Mainnet)
            .unwrap();
        assert!(url.starts_with("https://"));
        assert!(url.contains("alchemy.com"));
        assert!(url.contains("test-key"));
    }

    #[test]
    fn test_infura_endpoint_format() {
        let provider = InfuraProvider::new("test-project-id");
        let url = provider
            .https_endpoint(Chain::Ethereum, &NetworkEnv::Mainnet)
            .unwrap();
        assert!(url.starts_with("https://"));
        assert!(url.contains("infura.io"));
        assert!(url.contains("test-project-id"));
    }

    #[test]
    fn test_custom_provider() {
        let mut https = HashMap::new();
        https.insert(Chain::Ethereum, "https://my-node.example.com/rpc".to_string());
        let provider = CustomProvider::new("my-node", https, HashMap::new());
        let url = provider
            .https_endpoint(Chain::Ethereum, &NetworkEnv::Mainnet)
            .unwrap();
        assert_eq!(url, "https://my-node.example.com/rpc");
    }

    #[test]
    fn test_failover_on_unhealthy() {
        let rpc = RpcRegistry::builder()
            .add_provider(DwellirProvider::new("dw-key"))
            .add_provider(AlchemyProvider::new("al-key"))
            .build();

        // Get dwellir URL and mark it unhealthy.
        let dw_url = rpc.endpoint_from("dwellir", Chain::Ethereum).unwrap();
        rpc.mark_unhealthy(&dw_url);

        // next_healthy_endpoint should skip dwellir and return alchemy.
        let healthy_url = rpc.next_healthy_endpoint(Chain::Ethereum).unwrap();
        assert!(healthy_url.contains("alchemy"));
    }

    #[test]
    fn test_chain_rpc_config_timeout() {
        let config = ChainRpcConfig {
            chain: Chain::Ethereum,
            endpoints: Vec::new(),
            timeout_ms: 5_000,
            max_retries: 5,
        };
        let rpc = RpcRegistry::builder()
            .chain_rpc_config(config)
            .build();
        let cfg = rpc.chain_config(Chain::Ethereum).unwrap();
        assert_eq!(cfg.timeout_ms, 5_000);
        assert_eq!(cfg.max_retries, 5);
    }

    #[test]
    fn test_https_endpoint_format() {
        let providers: Vec<Box<dyn RpcProvider>> = vec![
            Box::new(DwellirProvider::new("k")),
            Box::new(AlchemyProvider::new("k")),
            Box::new(InfuraProvider::new("k")),
        ];
        for provider in &providers {
            for chain in provider.supported_chains() {
                if let Some(url) = provider.https_endpoint(chain, &NetworkEnv::Mainnet) {
                    assert!(
                        url.starts_with("https://"),
                        "{} https for {chain} should start with https://: {url}",
                        provider.name()
                    );
                }
            }
        }
    }

    #[test]
    fn test_wss_endpoint_format() {
        let providers: Vec<Box<dyn RpcProvider>> = vec![
            Box::new(DwellirProvider::new("k")),
            Box::new(AlchemyProvider::new("k")),
            Box::new(InfuraProvider::new("k")),
        ];
        for provider in &providers {
            for chain in provider.supported_chains() {
                if let Some(url) = provider.wss_endpoint(chain, &NetworkEnv::Mainnet) {
                    assert!(
                        url.starts_with("wss://"),
                        "{} wss for {chain} should start with wss://: {url}",
                        provider.name()
                    );
                }
            }
        }
    }

    #[test]
    fn test_blockstream_rest_endpoint() {
        let provider = BlockstreamProvider::new();
        assert_eq!(provider.protocol(), RpcProtocol::Rest);
        let url = provider
            .https_endpoint(Chain::BitcoinMainnet, &NetworkEnv::Mainnet)
            .unwrap();
        assert_eq!(url, "https://blockstream.info/api");
        let url = provider
            .https_endpoint(Chain::BitcoinTestnet, &NetworkEnv::Testnet)
            .unwrap();
        assert_eq!(url, "https://blockstream.info/testnet/api");
        // Not supported for EVM
        assert!(provider
            .https_endpoint(Chain::Ethereum, &NetworkEnv::Mainnet)
            .is_none());
        // No WSS
        assert!(provider
            .wss_endpoint(Chain::BitcoinMainnet, &NetworkEnv::Mainnet)
            .is_none());
    }

    #[test]
    fn test_mempool_rest_endpoint() {
        let provider = MempoolProvider::new();
        assert_eq!(provider.protocol(), RpcProtocol::Rest);
        let url = provider
            .https_endpoint(Chain::BitcoinMainnet, &NetworkEnv::Mainnet)
            .unwrap();
        assert_eq!(url, "https://mempool.space/api");
        let url = provider
            .https_endpoint(Chain::BitcoinTestnet, &NetworkEnv::Testnet)
            .unwrap();
        assert_eq!(url, "https://mempool.space/testnet/api");
    }

    #[test]
    fn test_existing_providers_default_to_jsonrpc() {
        let dw = DwellirProvider::new("k");
        assert_eq!(dw.protocol(), RpcProtocol::JsonRpc);
        let al = AlchemyProvider::new("k");
        assert_eq!(al.protocol(), RpcProtocol::JsonRpc);
        let inf = InfuraProvider::new("k");
        assert_eq!(inf.protocol(), RpcProtocol::JsonRpc);
    }

    #[test]
    fn test_registry_rest_endpoint() {
        let rpc = RpcRegistry::builder()
            .add_provider(DwellirProvider::new("k"))
            .add_provider(BlockstreamProvider::new())
            .build();
        // rest_endpoint should return Blockstream, not Dwellir
        let url = rpc.rest_endpoint(Chain::BitcoinMainnet).unwrap();
        assert!(url.contains("blockstream.info"));
        // rest_endpoint for Ethereum should fail (no REST provider for EVM)
        assert!(rpc.rest_endpoint(Chain::Ethereum).is_err());
    }

    #[test]
    fn test_registry_failover_rest_providers() {
        let rpc = RpcRegistry::builder()
            .add_provider(BlockstreamProvider::new())
            .add_provider(MempoolProvider::new())
            .build();
        let url = rpc
            .next_healthy_endpoint_with_protocol(Chain::BitcoinMainnet, RpcProtocol::Rest)
            .unwrap();
        assert!(url.contains("blockstream"));
        // Mark blockstream unhealthy, should failover to mempool
        rpc.mark_unhealthy(&url);
        let url2 = rpc
            .next_healthy_endpoint_with_protocol(Chain::BitcoinMainnet, RpcProtocol::Rest)
            .unwrap();
        assert!(url2.contains("mempool"));
    }

    #[test]
    fn test_mixed_protocol_registry() {
        let rpc = RpcRegistry::builder()
            .add_provider(DwellirProvider::new("k"))
            .add_provider(BlockstreamProvider::new())
            .build();
        // endpoint() returns first match (Dwellir, JSON-RPC)
        let jsonrpc_url = rpc.endpoint(Chain::BitcoinMainnet).unwrap();
        assert!(jsonrpc_url.contains("dwellir"));
        // rest_endpoint() returns only REST match (Blockstream)
        let rest_url = rpc.rest_endpoint(Chain::BitcoinMainnet).unwrap();
        assert!(rest_url.contains("blockstream"));
    }

    #[test]
    fn test_custom_provider_both_transports() {
        let mut https = HashMap::new();
        let mut wss = HashMap::new();
        https.insert(Chain::Solana, "https://solana.example.com".to_string());
        wss.insert(Chain::Solana, "wss://solana.example.com/ws".to_string());
        let provider = CustomProvider::new("custom-sol", https, wss);

        let h = provider
            .https_endpoint(Chain::Solana, &NetworkEnv::Mainnet)
            .unwrap();
        let w = provider
            .wss_endpoint(Chain::Solana, &NetworkEnv::Mainnet)
            .unwrap();
        assert!(h.starts_with("https://"));
        assert!(w.starts_with("wss://"));
    }
}
