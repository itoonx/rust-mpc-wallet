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

/// Configuration for Bitcoin transaction simulation.
#[derive(Debug, Clone)]
pub struct BitcoinSimulationConfig {
    /// Maximum fee rate in sat/vB before flagging as high-fee.
    pub max_fee_rate_sat_vb: u64,
    /// Maximum total fee in satoshis.
    pub max_total_fee_sat: u64,
    /// Minimum output value in satoshis (dust threshold).
    pub dust_threshold_sat: u64,
}

impl Default for BitcoinSimulationConfig {
    fn default() -> Self {
        Self {
            max_fee_rate_sat_vb: 500,     // 500 sat/vB
            max_total_fee_sat: 1_000_000, // 0.01 BTC
            dust_threshold_sat: 546,      // Bitcoin Core default dust limit
        }
    }
}

pub struct BitcoinProvider {
    pub network: bitcoin::Network,
    pub simulation_config: Option<BitcoinSimulationConfig>,
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
    pub fn with_simulation(mut self, config: BitcoinSimulationConfig) -> Self {
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
        let raw_hex = hex::encode(&signed.raw_tx);
        let url = format!("{rpc_url}/tx");
        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .header("Content-Type", "text/plain")
            .body(raw_hex)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast request failed: {e}")))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast response read failed: {e}")))?;
        if !status.is_success() {
            return Err(CoreError::Other(format!(
                "broadcast failed ({status}): {body}"
            )));
        }
        // Blockstream/Mempool return the txid as plain text
        Ok(body.trim().to_string())
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let config = self
            .simulation_config
            .as_ref()
            .ok_or_else(|| CoreError::Other("Bitcoin simulation not configured".into()))?;

        let mut risk_flags = Vec::new();
        let mut risk_score: u8 = 0;

        // Parse value (output amount in satoshis)
        let value: u64 = params.value.parse().unwrap_or(0);

        // Dust check
        if value > 0 && value < config.dust_threshold_sat {
            risk_flags.push("dust_output".into());
            risk_score = risk_score.saturating_add(40);
        }

        // Parse fee-related fields from extra params
        if let Some(extra) = &params.extra {
            // Fee rate check
            if let Some(fee_rate) = extra.get("fee_rate_sat_vb").and_then(|v| v.as_u64()) {
                if fee_rate > config.max_fee_rate_sat_vb {
                    risk_flags.push("high_fee_rate".into());
                    risk_score = risk_score.saturating_add(50);
                }
            }

            // Total fee check
            if let Some(total_fee) = extra.get("fee_sat").and_then(|v| v.as_u64()) {
                if total_fee > config.max_total_fee_sat {
                    risk_flags.push("excessive_fee".into());
                    risk_score = risk_score.saturating_add(60);
                }
            }

            // RBF (Replace-By-Fee) flag
            if extra.get("rbf").and_then(|v| v.as_bool()).unwrap_or(false) {
                risk_flags.push("rbf_enabled".into());
                risk_score = risk_score.saturating_add(10);
            }

            // Multi-output check (potential change address confusion)
            if let Some(outputs) = extra.get("output_count").and_then(|v| v.as_u64()) {
                if outputs > 5 {
                    risk_flags.push("many_outputs".into());
                    risk_score = risk_score.saturating_add(20);
                }
            }
        }

        Ok(SimulationResult {
            success: true,
            gas_used: 0, // not applicable for Bitcoin
            return_data: Vec::new(),
            risk_flags,
            risk_score,
        })
    }
}
