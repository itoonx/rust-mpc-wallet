//! TRON HTTP RPC client (TronGrid-compatible).
//!
//! Mainnet: `https://api.trongrid.io`. Shasta testnet: `https://api.shasta.trongrid.io`.
//! All endpoints accept a JSON body and return a JSON body. The TronGrid API
//! key, if any, is passed via the `TRON-PRO-API-KEY` header — not required for
//! Shasta during ordinary use.

use mpc_wallet_core::error::CoreError;
use serde_json::Value;

/// Reference block info — the (block_bytes, block_hash) pair the validator
/// uses to anchor a transaction to a recent block (replay protection).
pub struct BlockRef {
    pub ref_block_bytes: [u8; 2],
    pub ref_block_hash: [u8; 8],
}

pub struct TronRpcClient {
    url: String,
    client: reqwest::Client,
}

impl TronRpcClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, CoreError> {
        let url = format!("{}{}", self.url.trim_end_matches('/'), path);
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("TRON {path} request failed: {e}")))?;
        resp.json::<Value>()
            .await
            .map_err(|e| CoreError::Other(format!("TRON {path} response parse failed: {e}")))
    }

    /// `POST /wallet/getnowblock` → derive `ref_block_bytes` (last 2 bytes of
    /// `block.number` BE) and `ref_block_hash` (bytes 8..16 of the blockID hex).
    pub async fn get_now_block(&self) -> Result<BlockRef, CoreError> {
        let resp = self
            .post("/wallet/getnowblock", serde_json::json!({}))
            .await?;

        let number = resp
            .get("block_header")
            .and_then(|h| h.get("raw_data"))
            .and_then(|r| r.get("number"))
            .and_then(|n| n.as_i64())
            .ok_or_else(|| CoreError::Other("TRON getnowblock missing block.number".into()))?;

        let block_id_hex = resp
            .get("blockID")
            .and_then(|b| b.as_str())
            .ok_or_else(|| CoreError::Other("TRON getnowblock missing blockID".into()))?;
        let block_id = hex::decode(block_id_hex)
            .map_err(|e| CoreError::Other(format!("TRON blockID hex: {e}")))?;
        if block_id.len() < 16 {
            return Err(CoreError::Other(format!(
                "TRON blockID too short: {} bytes",
                block_id.len()
            )));
        }

        let n_bytes = (number as u64).to_be_bytes();
        let mut ref_block_bytes = [0u8; 2];
        ref_block_bytes.copy_from_slice(&n_bytes[6..8]);

        let mut ref_block_hash = [0u8; 8];
        ref_block_hash.copy_from_slice(&block_id[8..16]);

        Ok(BlockRef {
            ref_block_bytes,
            ref_block_hash,
        })
    }

    /// `POST /wallet/getaccount` → balance in sun. Treats "Account not found"
    /// (empty `{}` response) as 0 — TRON returns no balance field for
    /// unfunded addresses, which is the common case before the first deposit.
    pub async fn get_balance(&self, addr_base58: &str) -> Result<i64, CoreError> {
        let resp = self
            .post(
                "/wallet/getaccount",
                serde_json::json!({ "address": addr_base58, "visible": true }),
            )
            .await?;
        Ok(resp.get("balance").and_then(|b| b.as_i64()).unwrap_or(0))
    }

    /// `POST /wallet/broadcasttransaction` with the JSON-shaped signed tx.
    /// `raw_tx` MUST be the protobuf raw_data bytes (NO trailing signature).
    /// Returns the canonical tx_id (hex of SHA-256(raw_data)).
    pub async fn broadcast(&self, raw_data: &[u8], sig: &[u8]) -> Result<String, CoreError> {
        if sig.len() != 65 {
            return Err(CoreError::InvalidInput(format!(
                "TRON sig must be 65 bytes, got {}",
                sig.len()
            )));
        }
        use sha2::{Digest, Sha256};
        let tx_id = hex::encode(Sha256::digest(raw_data));

        let body = serde_json::json!({
            "txID": tx_id,
            "raw_data_hex": hex::encode(raw_data),
            "signature": [hex::encode(sig)],
        });
        let resp = self.post("/wallet/broadcasttransaction", body).await?;

        if resp.get("result").and_then(|r| r.as_bool()) != Some(true) {
            let code = resp
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("UNKNOWN");
            // `message` comes back hex-encoded ASCII per TronGrid convention.
            let raw_msg = resp.get("message").and_then(|m| m.as_str()).unwrap_or("");
            let decoded = hex::decode(raw_msg)
                .ok()
                .and_then(|v| String::from_utf8(v).ok())
                .unwrap_or_else(|| raw_msg.to_string());
            return Err(CoreError::Other(format!(
                "TRON broadcast rejected: {code}: {decoded}"
            )));
        }
        Ok(tx_id)
    }
}
