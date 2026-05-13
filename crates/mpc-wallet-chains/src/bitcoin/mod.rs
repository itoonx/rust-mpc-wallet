pub mod address;
pub mod rpc_client;
pub mod segwit_tx;
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

    fn metadata(&self) -> &'static crate::metadata::ChainMetadata {
        crate::metadata::metadata_for(self.chain()).unwrap_or_else(|| {
            panic!(
                "CHAIN_METADATA has no entry for {:?} — only BitcoinTestnet is wired in Step 3",
                self.chain()
            )
        })
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        // Default to P2WPKH (native SegWit). Taproot requires BIP-341 key
        // tweaking that the current FROST-Secp256k1-TR protocol doesn't
        // implement, so signatures wouldn't verify against a Taproot output
        // until that's added. Callers wanting Taproot can call
        // `address::derive_taproot_address` directly.
        address::derive_p2wpkh_address(group_pubkey, self.network)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        // Route by `addr_type` in extra; default p2wpkh.
        let addr_type = params
            .extra
            .as_ref()
            .and_then(|e| e.get("addr_type"))
            .and_then(|v| v.as_str())
            .unwrap_or("p2wpkh");
        match addr_type {
            "p2wpkh" => {
                segwit_tx::build_p2wpkh_transaction(self.chain(), self.network, params).await
            }
            "taproot" => tx::build_taproot_transaction(self.chain(), self.network, params).await,
            other => Err(CoreError::InvalidInput(format!(
                "unknown bitcoin addr_type '{other}' (expected p2wpkh or taproot)"
            ))),
        }
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        // Route by signature type: ECDSA → P2WPKH, Schnorr → Taproot.
        match sig {
            MpcSignature::Ecdsa { .. } => segwit_tx::finalize_p2wpkh_transaction(unsigned, sig),
            MpcSignature::Schnorr { .. } => tx::finalize_taproot_transaction(unsigned, sig),
            _ => Err(CoreError::InvalidInput(
                "Bitcoin requires ECDSA (P2WPKH) or Schnorr (Taproot) signature".into(),
            )),
        }
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
