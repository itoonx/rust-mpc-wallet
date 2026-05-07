//! Minimal Solana JSON-RPC helper for fetching pre-sign data
//! (recent blockhash). Used by CLI/gateway to populate
//! `TransactionParams::extra` before MPC signing.

use mpc_wallet_core::error::CoreError;
use serde_json::json;

pub struct SolanaRpcClient {
    url: String,
    client: reqwest::Client,
}

impl SolanaRpcClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }

    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, CoreError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("rpc {method} request failed: {e}")))?;
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CoreError::Other(format!("rpc {method} parse failed: {e}")))?;
        if let Some(err) = json.get("error") {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(CoreError::Other(format!("rpc {method}: {msg}")));
        }
        json.get("result")
            .cloned()
            .ok_or_else(|| CoreError::Other(format!("rpc {method}: missing result")))
    }

    /// `getBalance(pubkey)` → lamports.
    pub async fn get_balance(&self, pubkey: &str) -> Result<u64, CoreError> {
        let res = self.call("getBalance", json!([pubkey])).await?;
        res.get("value")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| CoreError::Other("getBalance: missing value".into()))
    }

    /// `getLatestBlockhash` → base58-encoded blockhash.
    pub async fn get_latest_blockhash(&self) -> Result<String, CoreError> {
        let res = self
            .call("getLatestBlockhash", json!([{ "commitment": "finalized" }]))
            .await?;
        res.get("value")
            .and_then(|v| v.get("blockhash"))
            .and_then(|b| b.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::Other("getLatestBlockhash: missing blockhash".into()))
    }
}
