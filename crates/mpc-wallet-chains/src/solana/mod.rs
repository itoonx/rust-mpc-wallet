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

/// Configuration for Solana transaction simulation / risk analysis.
#[derive(Debug, Clone)]
pub struct SolanaSimulationConfig {
    /// Allowed program IDs — transactions calling unknown programs get flagged.
    pub program_allowlist: Vec<String>,
    /// Maximum lamports per transaction before flagging as high-value.
    pub max_lamports_per_tx: u64,
}

impl Default for SolanaSimulationConfig {
    fn default() -> Self {
        Self {
            program_allowlist: vec![
                "11111111111111111111111111111111".into(),
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
            ],
            max_lamports_per_tx: 1_000_000_000_000,
        }
    }
}

pub struct SolanaProvider {
    simulation_config: Option<SolanaSimulationConfig>,
}

impl SolanaProvider {
    pub fn new() -> Self {
        Self {
            simulation_config: None,
        }
    }

    /// Attach a simulation configuration for risk analysis.
    pub fn with_simulation(mut self, config: SolanaSimulationConfig) -> Self {
        self.simulation_config = Some(config);
        self
    }
}

impl Default for SolanaProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainProvider for SolanaProvider {
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_solana_address(group_pubkey)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        tx::build_solana_transaction(params).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_solana_transaction(unsigned, sig)
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let config = match &self.simulation_config {
            Some(c) => c,
            None => {
                // No simulation config — return neutral result
                return Ok(SimulationResult {
                    success: true,
                    gas_used: 0,
                    return_data: vec![],
                    risk_flags: vec![],
                    risk_score: 0,
                });
            }
        };

        let mut risk_flags = Vec::new();
        let mut risk_score: u16 = 0;

        // Check value against max_lamports_per_tx
        let lamports: u64 = params
            .value
            .parse()
            .unwrap_or(0);
        if lamports > config.max_lamports_per_tx {
            risk_flags.push("high_value".to_string());
            risk_score += 50;
        }

        // Check program_id from extra against allowlist
        if let Some(extra) = &params.extra {
            if let Some(program_id) = extra.get("program_id").and_then(|v| v.as_str()) {
                if !config.program_allowlist.iter().any(|a| a == program_id) {
                    risk_flags.push("unknown_program".to_string());
                    risk_score += 40;
                }
            }
        }

        Ok(SimulationResult {
            success: true,
            gas_used: 0,
            return_data: vec![],
            risk_flags,
            risk_score: risk_score.min(255) as u8,
        })
    }
}
