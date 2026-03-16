//! TON (The Open Network) chain provider.
//!
//! TON uses Ed25519 signing (FROST Ed25519) with Cell/BOC encoding.
//! Addresses are derived from SHA-256 of the wallet state init.

pub mod address;
pub mod cell;
pub mod tx;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// TON chain provider.
pub struct TonProvider;

impl TonProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TonProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainProvider for TonProvider {
    fn chain(&self) -> Chain {
        Chain::Ton
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_ton_address(group_pubkey)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        tx::build_ton_transaction(params).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_ton_transaction(unsigned, sig)
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        let boc_b64 = BASE64.encode(&signed.raw_tx);
        let url = format!("{rpc_url}/api/v2/sendBoc");
        let body = serde_json::json!({
            "boc": boc_b64,
        });
        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast request failed: {e}")))?;
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast response parse failed: {e}")))?;
        if json.get("ok").and_then(|o| o.as_bool()) != Some(true) {
            let err = json
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error");
            return Err(CoreError::Other(format!("TON broadcast failed: {err}")));
        }
        // Return tx hash from sign payload
        Ok(signed.tx_hash.clone())
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let mut risk_flags = Vec::new();
        let mut risk_score: u8 = 0;

        // TON uses nanotons (1 TON = 10^9 nanoton)
        let nanoton: u64 = params.value.parse().unwrap_or(0);
        if nanoton > 10_000_000_000_000 {
            // > 10,000 TON
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
