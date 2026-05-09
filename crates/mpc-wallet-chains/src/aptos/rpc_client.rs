//! Minimal Aptos REST helper for fetching pre-sign data
//! (sequence number, gas price, balance) and broadcasting signed
//! transactions. Mirrors the EVM/Solana/Bitcoin/Sui RPC client pattern:
//! thin `reqwest` wrapper, no caching.

use mpc_wallet_core::error::CoreError;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    pub sequence_number: StringU64,
    #[allow(dead_code)]
    pub authentication_key: String,
}

/// Aptos REST encodes u64 as JSON strings.
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

pub struct AptosRpcClient {
    base_url: String,
    client: reqwest::Client,
}

impl AptosRpcClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// `GET /v1/accounts/{addr}` — returns sequence_number + authentication_key.
    pub async fn get_account(&self, addr: &str) -> Result<Account, CoreError> {
        let url = format!("{}/v1/accounts/{}", self.base_url, addr);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("get_account request: {e}")))?;
        if !resp.status().is_success() {
            return Err(CoreError::Other(format!(
                "get_account status {}",
                resp.status()
            )));
        }
        resp.json::<Account>()
            .await
            .map_err(|e| CoreError::Other(format!("get_account parse: {e}")))
    }

    /// `GET /v1/accounts/{addr}/balance/0x1::aptos_coin::AptosCoin` → octas.
    /// Treats 404 as 0 (account doesn't exist yet — common before first faucet).
    pub async fn get_balance(&self, addr: &str) -> Result<u64, CoreError> {
        let url = format!(
            "{}/v1/accounts/{}/balance/0x1::aptos_coin::AptosCoin",
            self.base_url, addr
        );
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("get_balance request: {e}")))?;
        if !resp.status().is_success() {
            if resp.status().as_u16() == 404 {
                return Ok(0);
            }
            return Err(CoreError::Other(format!(
                "get_balance status {}",
                resp.status()
            )));
        }
        let body = resp
            .text()
            .await
            .map_err(|e| CoreError::Other(format!("get_balance body: {e}")))?;
        body.trim()
            .trim_matches('"')
            .parse::<u64>()
            .map_err(|e| CoreError::Other(format!("get_balance parse: {e} (body={body})")))
    }

    /// `GET /v1/estimate_gas_price` → gas_estimate (octas per gas unit).
    pub async fn estimate_gas_price(&self) -> Result<u64, CoreError> {
        let url = format!("{}/v1/estimate_gas_price", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("estimate_gas_price request: {e}")))?;
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CoreError::Other(format!("estimate_gas_price parse: {e}")))?;
        json.get("gas_estimate")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| CoreError::Other("estimate_gas_price: missing gas_estimate".into()))
    }

    /// `GET /v1` → ledger info; returns the chain_id (u8).
    pub async fn get_chain_id(&self) -> Result<u8, CoreError> {
        let url = format!("{}/v1", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("get_chain_id request: {e}")))?;
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CoreError::Other(format!("get_chain_id parse: {e}")))?;
        json.get("chain_id")
            .and_then(|v| v.as_u64())
            .map(|x| x as u8)
            .ok_or_else(|| CoreError::Other("get_chain_id: missing chain_id".into()))
    }

    /// `POST /v1/transactions` with `Content-Type: application/x.aptos.signed_transaction+bcs`.
    /// Body is the BCS-encoded signed transaction. Returns the tx hash.
    pub async fn submit(&self, raw_tx_bcs: &[u8]) -> Result<String, CoreError> {
        let url = format!("{}/v1/transactions", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x.aptos.signed_transaction+bcs",
            )
            .body(raw_tx_bcs.to_vec())
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("submit request: {e}")))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| CoreError::Other(format!("submit body: {e}")))?;
        if !status.is_success() {
            return Err(CoreError::Other(format!(
                "submit {} → {}",
                status,
                body.trim()
            )));
        }
        let json: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| CoreError::Other(format!("submit parse: {e} body={body}")))?;
        json.get("hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::Other(format!("submit: missing hash, body={body}")))
    }
}
