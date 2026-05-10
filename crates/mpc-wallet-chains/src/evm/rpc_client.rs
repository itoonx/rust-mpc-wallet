//! Minimal EVM JSON-RPC helper for fetching pre-sign data
//! (nonce, gas price, fee history). Used by CLI/gateway to populate
//! `TransactionParams::extra` before MPC signing.
//!
//! Intentionally tiny: no caching, no retries, no batching. Production
//! deployments should use `RpcRegistry` health/failover for endpoint selection
//! and pass the resolved URL here.

use mpc_wallet_core::error::CoreError;
use serde_json::json;

/// JSON-RPC client for a single EVM endpoint.
pub struct EvmRpcClient {
    url: String,
    client: reqwest::Client,
}

impl EvmRpcClient {
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
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
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

    /// `eth_estimateGas({from, to, data, value})` → estimated gas as u64.
    /// `data` and `value` must already be 0x-prefixed hex (or empty string for none).
    /// Used to size `gas_limit` for contract calls (ERC-20 etc.); add a safety
    /// margin (typically 20%) to the returned value.
    pub async fn estimate_gas(
        &self,
        from: &str,
        to: &str,
        data: &str,
        value_wei_hex: &str,
    ) -> Result<u64, CoreError> {
        let mut tx = serde_json::Map::new();
        tx.insert("from".into(), json!(from));
        tx.insert("to".into(), json!(to));
        if !data.is_empty() {
            tx.insert("data".into(), json!(data));
        }
        if !value_wei_hex.is_empty() {
            tx.insert("value".into(), json!(value_wei_hex));
        }
        let res = self
            .call("eth_estimateGas", json!([serde_json::Value::Object(tx)]))
            .await?;
        parse_hex_u64(&res, "estimatedGas")
    }

    /// `eth_call({to, data}, "latest")` → returns the raw hex result string.
    /// Used for read-only calls into smart contracts (e.g. ERC-20 `balanceOf`,
    /// `decimals`, `symbol`). The data must already be 0x-prefixed hex.
    pub async fn eth_call(&self, to: &str, data: &str) -> Result<String, CoreError> {
        let res = self
            .call("eth_call", json!([{"to": to, "data": data}, "latest"]))
            .await?;
        res.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::Other("eth_call: result not a string".into()))
    }

    /// `eth_getBalance(address, "latest")` → balance in wei.
    pub async fn get_balance(&self, address: &str) -> Result<u128, CoreError> {
        let res = self
            .call("eth_getBalance", json!([address, "latest"]))
            .await?;
        parse_hex_u128(&res, "balance")
    }

    /// `eth_getTransactionCount(address, "pending")` → next usable nonce.
    pub async fn get_nonce(&self, address: &str) -> Result<u64, CoreError> {
        let res = self
            .call("eth_getTransactionCount", json!([address, "pending"]))
            .await?;
        parse_hex_u64(&res, "nonce")
    }

    /// `eth_chainId` → chain id.
    pub async fn get_chain_id(&self) -> Result<u64, CoreError> {
        let res = self.call("eth_chainId", json!([])).await?;
        parse_hex_u64(&res, "chainId")
    }

    /// `eth_gasPrice` — legacy fallback when EIP-1559 fields are not available.
    pub async fn get_gas_price(&self) -> Result<u128, CoreError> {
        let res = self.call("eth_gasPrice", json!([])).await?;
        parse_hex_u128(&res, "gasPrice")
    }

    /// `eth_maxPriorityFeePerGas` — current priority tip suggestion.
    /// Falls back to a sensible default (1 gwei) if the node doesn't expose it.
    pub async fn get_max_priority_fee(&self) -> Result<u128, CoreError> {
        match self.call("eth_maxPriorityFeePerGas", json!([])).await {
            Ok(v) => parse_hex_u128(&v, "maxPriorityFee"),
            Err(_) => Ok(1_000_000_000), // 1 gwei
        }
    }

    /// Suggest EIP-1559 fees: `(max_fee_per_gas, max_priority_fee_per_gas)`.
    /// `max_fee = base_fee * 2 + tip` (a simple, safe overshoot).
    pub async fn suggest_eip1559_fees(&self) -> Result<(u128, u128), CoreError> {
        let tip = self.get_max_priority_fee().await?;
        let base = self.get_gas_price().await.unwrap_or(tip);
        let max_fee = base.saturating_mul(2).saturating_add(tip);
        Ok((max_fee, tip))
    }
}

fn parse_hex_u64(v: &serde_json::Value, field: &str) -> Result<u64, CoreError> {
    let s = v
        .as_str()
        .ok_or_else(|| CoreError::Other(format!("{field} not a string")))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| CoreError::Other(format!("{field} parse: {e}")))
}

fn parse_hex_u128(v: &serde_json::Value, field: &str) -> Result<u128, CoreError> {
    let s = v
        .as_str()
        .ok_or_else(|| CoreError::Other(format!("{field} not a string")))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    u128::from_str_radix(s, 16).map_err(|e| CoreError::Other(format!("{field} parse: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_u64() {
        assert_eq!(parse_hex_u64(&json!("0x10"), "x").unwrap(), 16);
        assert_eq!(parse_hex_u64(&json!("0x0"), "x").unwrap(), 0);
        assert!(parse_hex_u64(&json!(42), "x").is_err());
    }

    #[test]
    fn test_parse_hex_u128() {
        assert_eq!(parse_hex_u128(&json!("0xff"), "x").unwrap(), 255);
    }
}
