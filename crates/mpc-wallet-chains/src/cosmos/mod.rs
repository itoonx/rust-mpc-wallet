//! Cosmos / IBC chain providers.
//!
//! Cosmos chains use secp256k1 ECDSA (GG20) or Ed25519 signing with
//! bech32 addresses and Amino/Protobuf transaction encoding.
//! Each chain has its own bech32 HRP (human-readable prefix).

pub mod address;
pub mod tx;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// Cosmos chain configuration.
#[derive(Debug, Clone)]
pub struct CosmosChainConfig {
    pub chain: Chain,
    /// Bech32 human-readable prefix (e.g. "cosmos", "osmo", "celestia").
    pub bech32_hrp: &'static str,
    /// Native denomination (e.g. "uatom", "uosmo", "utia").
    pub denom: &'static str,
    /// Chain ID string (e.g. "cosmoshub-4", "osmosis-1").
    pub chain_id: &'static str,
    /// Display name.
    pub name: &'static str,
}

pub const COSMOS_HUB_CONFIG: CosmosChainConfig = CosmosChainConfig {
    chain: Chain::CosmosHub,
    bech32_hrp: "cosmos",
    denom: "uatom",
    chain_id: "cosmoshub-4",
    name: "Cosmos Hub",
};

pub const OSMOSIS_CONFIG: CosmosChainConfig = CosmosChainConfig {
    chain: Chain::Osmosis,
    bech32_hrp: "osmo",
    denom: "uosmo",
    chain_id: "osmosis-1",
    name: "Osmosis",
};

pub const CELESTIA_CONFIG: CosmosChainConfig = CosmosChainConfig {
    chain: Chain::Celestia,
    bech32_hrp: "celestia",
    denom: "utia",
    chain_id: "celestia",
    name: "Celestia",
};

pub const INJECTIVE_CONFIG: CosmosChainConfig = CosmosChainConfig {
    chain: Chain::Injective,
    bech32_hrp: "inj",
    denom: "inj",
    chain_id: "injective-1",
    name: "Injective",
};

pub const SEI_CONFIG: CosmosChainConfig = CosmosChainConfig {
    chain: Chain::Sei,
    bech32_hrp: "sei",
    denom: "usei",
    chain_id: "pacific-1",
    name: "Sei",
};

/// Cosmos chain provider — supports all Cosmos SDK / IBC chains.
pub struct CosmosProvider {
    pub config: CosmosChainConfig,
}

impl CosmosProvider {
    pub fn cosmos_hub() -> Self {
        Self {
            config: COSMOS_HUB_CONFIG,
        }
    }

    pub fn osmosis() -> Self {
        Self {
            config: OSMOSIS_CONFIG,
        }
    }

    pub fn celestia() -> Self {
        Self {
            config: CELESTIA_CONFIG,
        }
    }

    pub fn injective() -> Self {
        Self {
            config: INJECTIVE_CONFIG,
        }
    }

    pub fn sei() -> Self {
        Self { config: SEI_CONFIG }
    }
}

#[async_trait]
impl ChainProvider for CosmosProvider {
    fn chain(&self) -> Chain {
        self.config.chain
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_cosmos_address(group_pubkey, self.config.bech32_hrp)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        tx::build_cosmos_transaction(
            self.config.chain,
            self.config.chain_id,
            self.config.denom,
            params,
        )
        .await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_cosmos_transaction(unsigned, sig, self.config.name)
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        // Cosmos LCD/REST: POST /cosmos/tx/v1beta1/txs
        let raw_b64 = BASE64.encode(&signed.raw_tx);
        let url = format!("{rpc_url}/cosmos/tx/v1beta1/txs");
        let body = serde_json::json!({
            "tx_bytes": raw_b64,
            "mode": "BROADCAST_MODE_SYNC",
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
        if let Some(code) = json
            .get("tx_response")
            .and_then(|r| r.get("code"))
            .and_then(|c| c.as_u64())
        {
            if code != 0 {
                let log = json
                    .get("tx_response")
                    .and_then(|r| r.get("raw_log"))
                    .and_then(|l| l.as_str())
                    .unwrap_or("unknown error");
                return Err(CoreError::Other(format!(
                    "{} broadcast failed (code {code}): {log}",
                    self.config.name
                )));
            }
        }
        json.get("tx_response")
            .and_then(|r| r.get("txhash"))
            .and_then(|h| h.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                CoreError::Other(format!("missing txhash in {} response", self.config.name))
            })
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let mut risk_flags = Vec::new();
        let mut risk_score: u8 = 0;

        let amount: u64 = params.value.parse().unwrap_or(0);
        // Flag high value (> 1M base units)
        if amount > 1_000_000_000_000 {
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
