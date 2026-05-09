//! Minimal Bitcoin REST helper for fetching pre-sign data
//! (UTXO list, balance) and broadcasting raw transactions.
//!
//! Uses the Blockstream/Mempool Esplora REST API:
//!   GET  /address/{addr}/utxo  → [{txid, vout, value, status}]
//!   GET  /address/{addr}       → balance summary
//!   POST /tx                   → broadcast raw hex; returns txid
//!
//! `base_url` examples:
//!   https://blockstream.info/testnet/api    (Bitcoin testnet3)
//!   https://blockstream.info/api            (Bitcoin mainnet)
//!   https://mempool.space/testnet/api       (mempool.space testnet)

use mpc_wallet_core::error::CoreError;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BitcoinUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
}

pub struct BitcoinRpcClient {
    base_url: String,
    client: reqwest::Client,
}

impl BitcoinRpcClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// `GET /address/{addr}/utxo` — list of confirmed/pending UTXOs.
    /// Esplora returns objects with extra fields (status), but only `txid`,
    /// `vout`, `value` are required for spending. We discard the rest.
    pub async fn get_utxos(&self, address: &str) -> Result<Vec<BitcoinUtxo>, CoreError> {
        let url = format!("{}/address/{}/utxo", self.base_url, address);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("get_utxos request failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(CoreError::Other(format!(
                "get_utxos status {}",
                resp.status()
            )));
        }
        resp.json::<Vec<BitcoinUtxo>>()
            .await
            .map_err(|e| CoreError::Other(format!("get_utxos parse: {e}")))
    }

    /// Sum of confirmed + mempool UTXO values.
    pub async fn get_balance(&self, address: &str) -> Result<u64, CoreError> {
        let utxos = self.get_utxos(address).await?;
        Ok(utxos.iter().map(|u| u.value).sum())
    }

    /// `POST /tx` with the hex-encoded raw tx body — Esplora returns the txid
    /// in plain text (no JSON wrapping).
    pub async fn broadcast(&self, raw_tx_hex: &str) -> Result<String, CoreError> {
        let url = format!("{}/tx", self.base_url);
        let resp = self
            .client
            .post(&url)
            .body(raw_tx_hex.to_string())
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast request: {e}")))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast body: {e}")))?;
        if !status.is_success() {
            return Err(CoreError::Other(format!(
                "broadcast {} → {}",
                status,
                body.trim()
            )));
        }
        Ok(body.trim().to_string())
    }
}
