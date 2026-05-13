pub mod address;
pub mod erc20;
pub mod rpc_client;
pub mod signer;
pub mod tx;

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// Configuration for EVM transaction simulation.
#[derive(Debug, Clone)]
pub struct EvmSimulationConfig {
    /// Maximum transaction value before flagging as high-value (in wei).
    pub high_value_threshold: u64,
    /// Known proxy contract addresses (for risk flagging).
    pub known_proxies: Vec<String>,
    /// Default gas estimate when simulation is not connected to RPC.
    pub default_gas_estimate: u64,
}

impl Default for EvmSimulationConfig {
    fn default() -> Self {
        Self {
            high_value_threshold: 10_000_000_000_000_000_000, // 10 ETH in wei
            known_proxies: Vec::new(),
            default_gas_estimate: 21_000,
        }
    }
}

pub struct EvmProvider {
    pub chain: Chain,
    pub chain_id: u64,
    pub simulation_config: Option<EvmSimulationConfig>,
}

impl EvmProvider {
    /// Create an `EvmProvider` for the given chain. The chain_id is derived
    /// automatically from the chain variant. Returns `CoreError::InvalidInput`
    /// for non-EVM chains (Bitcoin, Solana, Sui).
    pub fn new(chain: Chain) -> Result<Self, CoreError> {
        let chain_id = mainnet_chain_id(chain)?;
        Ok(Self {
            chain,
            chain_id,
            simulation_config: None,
        })
    }

    /// Network-aware constructor. Selects testnet chain_id when env is Testnet/Devnet.
    pub fn for_network(chain: Chain, env: &crate::registry::NetworkEnv) -> Result<Self, CoreError> {
        use crate::registry::NetworkEnv;
        let chain_id = match env {
            NetworkEnv::Mainnet => mainnet_chain_id(chain)?,
            NetworkEnv::Testnet | NetworkEnv::Devnet => testnet_chain_id(chain)?,
            NetworkEnv::Custom(_) => mainnet_chain_id(chain)?,
        };
        Ok(Self {
            chain,
            chain_id,
            simulation_config: None,
        })
    }

    pub fn ethereum() -> Self {
        Self {
            chain: Chain::Ethereum,
            chain_id: 1,
            simulation_config: None,
        }
    }

    pub fn polygon() -> Self {
        Self {
            chain: Chain::Polygon,
            chain_id: 137,
            simulation_config: None,
        }
    }

    pub fn bsc() -> Self {
        Self {
            chain: Chain::Bsc,
            chain_id: 56,
            simulation_config: None,
        }
    }

    /// Attach a simulation configuration, enabling `simulate_transaction`.
    pub fn with_simulation(mut self, config: EvmSimulationConfig) -> Self {
        self.simulation_config = Some(config);
        self
    }
}

/// Mainnet chain IDs for all supported EVM chains.
fn mainnet_chain_id(chain: Chain) -> Result<u64, CoreError> {
    Ok(match chain {
        Chain::Ethereum => 1,
        Chain::Polygon => 137,
        Chain::Bsc => 56,
        Chain::Arbitrum => 42161,
        Chain::Optimism => 10,
        Chain::Base => 8453,
        Chain::Avalanche => 43114,
        Chain::Linea => 59144,
        Chain::ZkSync => 324,
        Chain::Scroll => 534352,
        Chain::Mantle => 5000,
        Chain::Blast => 81457,
        Chain::Zora => 7777777,
        Chain::Fantom => 250,
        Chain::Gnosis => 100,
        Chain::Cronos => 25,
        Chain::Celo => 42220,
        Chain::Moonbeam => 1284,
        Chain::Ronin => 2020,
        Chain::OpBnb => 204,
        Chain::Immutable => 13371,
        Chain::MantaPacific => 169,
        Chain::Hyperliquid => 999,
        Chain::Berachain => 80094,
        Chain::MegaEth => 6342,
        Chain::Monad => 143,
        other => {
            return Err(CoreError::InvalidInput(format!(
                "chain '{other}' is not an EVM chain"
            )))
        }
    })
}

/// Testnet chain IDs. Falls back to mainnet for chains without an established testnet mapping.
fn testnet_chain_id(chain: Chain) -> Result<u64, CoreError> {
    Ok(match chain {
        Chain::Ethereum => 11155111, // Sepolia
        Chain::Polygon => 80002,     // Amoy
        Chain::Bsc => 97,            // BSC testnet
        Chain::Arbitrum => 421614,   // Arbitrum Sepolia
        Chain::Optimism => 11155420, // Optimism Sepolia
        Chain::Base => 84532,        // Base Sepolia
        Chain::Avalanche => 43113,   // Fuji
        Chain::Linea => 59141,       // Linea Sepolia
        _ => return mainnet_chain_id(chain),
    })
}

#[async_trait]
impl ChainProvider for EvmProvider {
    fn chain(&self) -> Chain {
        self.chain
    }

    fn metadata(&self) -> &'static crate::metadata::ChainMetadata {
        crate::metadata::metadata_for(self.chain).unwrap_or_else(|| {
            panic!(
                "CHAIN_METADATA has no entry for {:?} — only Ethereum is wired in Step 3",
                self.chain
            )
        })
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_evm_address(group_pubkey)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        tx::build_evm_transaction(self.chain, self.chain_id, params).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_evm_transaction(unsigned, sig)
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        let raw_hex = format!("0x{}", hex::encode(&signed.raw_tx));
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendRawTransaction",
            "params": [raw_hex]
        });
        let client = reqwest::Client::new();
        let resp = client
            .post(rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast request failed: {e}")))?;
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast response parse failed: {e}")))?;
        if let Some(err) = json.get("error") {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown RPC error");
            return Err(CoreError::Other(format!("eth_sendRawTransaction: {msg}")));
        }
        json.get("result")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::Other("missing tx hash in RPC response".into()))
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let config = self.simulation_config.as_ref().ok_or_else(|| {
            CoreError::Other("EVM simulation not configured — call with_simulation()".into())
        })?;

        let mut risk_flags = Vec::new();
        let mut risk_score: u8 = 0;

        // Parse value
        let value: u64 = params.value.parse().unwrap_or(0);

        // High-value check
        if value > config.high_value_threshold {
            risk_flags.push("high_value".into());
            risk_score = risk_score.saturating_add(50);
        }

        // Proxy detection
        let to_lower = params.to.to_lowercase();
        if config
            .known_proxies
            .iter()
            .any(|p| p.to_lowercase() == to_lower)
        {
            risk_flags.push("proxy_detected".into());
            risk_score = risk_score.saturating_add(30);
        }

        // Contract interaction (has calldata)
        if params.data.as_ref().is_some_and(|d| !d.is_empty()) {
            risk_flags.push("contract_interaction".into());
            risk_score = risk_score.saturating_add(10);
        }

        // Invalid address format check
        if params.to.len() != 42 || !params.to.starts_with("0x") {
            risk_flags.push("invalid_address_format".into());
            risk_score = risk_score.saturating_add(40);
        }

        Ok(SimulationResult {
            success: true,
            gas_used: config.default_gas_estimate,
            return_data: Vec::new(),
            risk_flags,
            risk_score,
        })
    }
}
