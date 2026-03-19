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
    group_pubkey: Option<GroupPublicKey>,
    simulation_config: Option<SolanaSimulationConfig>,
}

impl SolanaProvider {
    pub fn new() -> Self {
        Self {
            group_pubkey: None,
            simulation_config: None,
        }
    }

    /// Create a provider pre-loaded with the group's Ed25519 public key.
    ///
    /// When a public key is set, `build_transaction` validates that the `from`
    /// address in `extra` matches the signing public key (SEC-017).
    pub fn with_pubkey(group_pubkey: GroupPublicKey) -> Self {
        Self {
            group_pubkey: Some(group_pubkey),
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
        // SEC-017: If a group pubkey is set, validate that the `from` address
        // (fee payer) matches the signing public key.
        if let Some(ref gpk) = self.group_pubkey {
            if let Some(from_str) = params
                .extra
                .as_ref()
                .and_then(|e| e.get("from"))
                .and_then(|v| v.as_str())
            {
                let expected_address = address::derive_solana_address(gpk)?;
                if from_str != expected_address {
                    return Err(CoreError::InvalidInput(format!(
                        "from address '{}' does not match signing public key (expected '{}')",
                        from_str, expected_address
                    )));
                }
            }
        }
        tx::build_solana_transaction(params).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_solana_transaction(unsigned, sig)
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        let encoded = bs58::encode(&signed.raw_tx).into_string();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendTransaction",
            "params": [encoded, {"encoding": "base58"}]
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
            return Err(CoreError::Other(format!("sendTransaction: {msg}")));
        }
        json.get("result")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::Other("missing tx signature in RPC response".into()))
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
        let lamports: u64 = params.value.parse().unwrap_or(0);
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
