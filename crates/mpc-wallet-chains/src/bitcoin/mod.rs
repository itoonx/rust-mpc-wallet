pub mod address;
pub mod signer;
pub mod tx;

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};
use crate::utxo::{broadcast_utxo_rest, simulate_utxo, UtxoSimulationConfig};

/// Re-export for backward compatibility — use `UtxoSimulationConfig` directly.
pub type BitcoinSimulationConfig = UtxoSimulationConfig;

pub struct BitcoinProvider {
    pub network: bitcoin::Network,
    pub simulation_config: Option<UtxoSimulationConfig>,
}

impl BitcoinProvider {
    pub fn mainnet() -> Self {
        Self {
            network: bitcoin::Network::Bitcoin,
            simulation_config: None,
        }
    }

    pub fn testnet() -> Self {
        Self {
            network: bitcoin::Network::Testnet,
            simulation_config: None,
        }
    }

    pub fn signet() -> Self {
        Self {
            network: bitcoin::Network::Signet,
            simulation_config: None,
        }
    }

    /// Enable transaction simulation with the given configuration.
    pub fn with_simulation(mut self, config: UtxoSimulationConfig) -> Self {
        self.simulation_config = Some(config);
        self
    }
}

#[async_trait]
impl ChainProvider for BitcoinProvider {
    fn chain(&self) -> Chain {
        match self.network {
            bitcoin::Network::Bitcoin => Chain::BitcoinMainnet,
            _ => Chain::BitcoinTestnet,
        }
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_taproot_address(group_pubkey, self.network)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        tx::build_taproot_transaction(self.chain(), self.network, params).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_taproot_transaction(unsigned, sig)
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        broadcast_utxo_rest(signed, rpc_url).await
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let config = self
            .simulation_config
            .as_ref()
            .ok_or_else(|| CoreError::Other("Bitcoin simulation not configured".into()))?;
        Ok(simulate_utxo(params, config))
    }
}
