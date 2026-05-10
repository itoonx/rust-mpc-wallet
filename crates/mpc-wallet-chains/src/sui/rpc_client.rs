//! Minimal Sui JSON-RPC helper for fetching pre-sign data
//! (gas payment object, reference gas price, account balance).
//!
//! Mirrors the `EvmRpcClient` / `SolanaRpcClient` / `BitcoinRpcClient`
//! pattern: thin `reqwest` wrapper, no caching, no retries.

use mpc_wallet_core::error::CoreError;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Clone, Deserialize)]
pub struct CoinObject {
    /// Coin object ID, `0x`-prefixed 64-hex (32 bytes).
    #[serde(rename = "coinObjectId")]
    pub object_id: String,
    /// Object version (Sui RPC encodes u64 as a JSON string).
    pub version: StringU64,
    /// Object digest, base58-encoded (32 bytes when decoded).
    pub digest: String,
    /// SUI balance in MIST.
    pub balance: StringU64,
}

/// Sui RPC encodes u64 as JSON strings to avoid losing precision in JS clients.
#[derive(Debug, Clone, Copy)]
pub struct StringU64(pub u64);

impl<'de> Deserialize<'de> for StringU64 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<u64>()
            .map(StringU64)
            .map_err(serde::de::Error::custom)
    }
}

pub struct SuiRpcClient {
    url: String,
    client: reqwest::Client,
}

impl SuiRpcClient {
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

    /// `suix_getBalance(owner, coinType="0x2::sui::SUI")` → total MIST owned.
    pub async fn get_balance(&self, owner: &str) -> Result<u64, CoreError> {
        let res = self
            .call("suix_getBalance", json!([owner, "0x2::sui::SUI"]))
            .await?;
        let total = res
            .get("totalBalance")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CoreError::Other("suix_getBalance: missing totalBalance".into()))?;
        total
            .parse::<u64>()
            .map_err(|e| CoreError::Other(format!("suix_getBalance parse: {e}")))
    }

    /// `suix_getCoins(owner, coinType=…)` — first page of owned coin objects
    /// of the given type (~50 results). For native SUI, pass
    /// `"0x2::sui::SUI"`. For tokens, pass the canonical type tag like
    /// `"0xa1ec…::usdc::USDC"`.
    pub async fn get_owned_coins(
        &self,
        owner: &str,
        coin_type: &str,
    ) -> Result<Vec<CoinObject>, CoreError> {
        let res = self
            .call("suix_getCoins", json!([owner, coin_type, null, null]))
            .await?;
        let data = res
            .get("data")
            .ok_or_else(|| CoreError::Other("suix_getCoins: missing data".into()))?;
        serde_json::from_value::<Vec<CoinObject>>(data.clone())
            .map_err(|e| CoreError::Other(format!("suix_getCoins decode: {e}")))
    }

    /// `suix_getReferenceGasPrice` → current reference gas price in MIST.
    pub async fn get_reference_gas_price(&self) -> Result<u64, CoreError> {
        let res = self.call("suix_getReferenceGasPrice", json!([])).await?;
        match &res {
            serde_json::Value::String(s) => s
                .parse::<u64>()
                .map_err(|e| CoreError::Other(format!("ref gas price parse: {e}"))),
            serde_json::Value::Number(n) => n
                .as_u64()
                .ok_or_else(|| CoreError::Other("ref gas price not u64".into())),
            other => Err(CoreError::Other(format!(
                "ref gas price unexpected shape: {other}"
            ))),
        }
    }
}
