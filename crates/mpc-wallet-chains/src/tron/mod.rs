//! TRON chain provider.
//!
//! TRON uses ECDSA secp256k1 signing (GG20) with Base58Check addresses.
//! Transaction format is Protobuf-based.

pub mod address;

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// TRON chain provider.
pub struct TronProvider;

impl TronProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TronProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainProvider for TronProvider {
    fn chain(&self) -> Chain {
        Chain::Tron
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_tron_address(group_pubkey)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        let value: u64 = params
            .value
            .parse()
            .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

        // Build simplified tx payload
        let mut payload = Vec::new();
        payload.extend_from_slice(params.to.as_bytes());
        payload.extend_from_slice(&value.to_le_bytes());
        if let Some(extra) = &params.extra {
            payload.extend_from_slice(extra.to_string().as_bytes());
        }

        // TRON uses SHA-256 for tx hash
        use sha2::{Digest, Sha256};
        let sign_payload = Sha256::digest(&payload).to_vec();

        Ok(UnsignedTransaction {
            chain: Chain::Tron,
            sign_payload,
            tx_data: payload,
        })
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        let (r, s, recovery_id) = match sig {
            MpcSignature::Ecdsa { r, s, recovery_id } => (r.clone(), s.clone(), *recovery_id),
            _ => {
                return Err(CoreError::InvalidInput(
                    "TRON requires ECDSA signature".into(),
                ))
            }
        };

        // TRON signature: r(32) || s(32) || v(1)
        let mut raw_tx = unsigned.tx_data.clone();
        raw_tx.extend_from_slice(&r);
        raw_tx.extend_from_slice(&s);
        raw_tx.push(recovery_id);

        let tx_hash = hex::encode(&unsigned.sign_payload);

        Ok(SignedTransaction {
            chain: Chain::Tron,
            raw_tx,
            tx_hash,
        })
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        let raw_hex = hex::encode(&signed.raw_tx);
        let url = format!("{rpc_url}/wallet/broadcasttransaction");
        let body = serde_json::json!({
            "raw_data_hex": raw_hex,
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
        if json.get("result").and_then(|r| r.as_bool()) != Some(true) {
            let msg = json
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return Err(CoreError::Other(format!("TRON broadcast failed: {msg}")));
        }
        json.get("txid")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::Other("missing txid in TRON response".into()))
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let mut risk_flags = Vec::new();
        let mut risk_score: u8 = 0;

        // TRON uses SUN (1 TRX = 1,000,000 SUN)
        let sun: u64 = params.value.parse().unwrap_or(0);
        if sun > 100_000_000_000 {
            // > 100,000 TRX
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
