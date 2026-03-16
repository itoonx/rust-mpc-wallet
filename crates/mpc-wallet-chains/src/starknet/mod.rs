//! Starknet chain provider.
//!
//! Starknet uses the STARK curve for signing (not secp256k1 or Ed25519).
//! Threshold MPC STARK signing is not yet implemented — this provider
//! supports address derivation and transaction building with a placeholder
//! signing flow that will be connected to a future STARK MPC protocol.

pub mod address;
pub mod tx;

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// Starknet chain provider.
///
/// Signing uses STARK curve — threshold MPC for this curve is planned.
/// Currently supports address derivation and tx building structure.
pub struct StarknetProvider;

impl StarknetProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StarknetProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainProvider for StarknetProvider {
    fn chain(&self) -> Chain {
        Chain::Starknet
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_starknet_address(group_pubkey)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        tx::build_starknet_transaction(params).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_starknet_transaction(unsigned, sig)
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        // Starknet JSON-RPC: starknet_addInvokeTransaction
        let raw_hex = hex::encode(&signed.raw_tx);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "starknet_addInvokeTransaction",
            "params": [{"raw_tx": raw_hex}]
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
            return Err(CoreError::Other(format!(
                "Starknet broadcast failed: {msg}"
            )));
        }
        json.get("result")
            .and_then(|r| r.get("transaction_hash"))
            .and_then(|h| h.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::Other("missing tx hash in Starknet response".into()))
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let mut risk_flags = Vec::new();
        let mut risk_score: u8 = 0;

        let amount: u64 = params.value.parse().unwrap_or(0);
        if amount > 1_000_000_000_000_000_000 {
            risk_flags.push("high_value".into());
            risk_score = risk_score.saturating_add(50);
        }

        Ok(SimulationResult {
            success: true,
            gas_used: 0,
            return_data: Vec::new(),
            risk_flags,
            risk_score,
        })
    }
}
