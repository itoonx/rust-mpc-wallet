//! Substrate / Polkadot ecosystem chain providers.
//!
//! Substrate chains use SS58 addresses and SCALE-encoded extrinsics.
//! Signing: Ed25519 (via FROST Ed25519) — Sr25519 MPC threshold signing
//! is not yet available and will be added as a future protocol.

pub mod address;

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// Substrate chain configuration.
#[derive(Debug, Clone)]
pub struct SubstrateChainConfig {
    pub chain: Chain,
    /// SS58 address prefix.
    pub ss58_prefix: u16,
    /// Display name.
    pub name: &'static str,
    /// Native token symbol.
    pub token: &'static str,
    /// Decimals for native token.
    pub decimals: u8,
}

pub const POLKADOT_CONFIG: SubstrateChainConfig = SubstrateChainConfig {
    chain: Chain::Polkadot,
    ss58_prefix: 0,
    name: "Polkadot",
    token: "DOT",
    decimals: 10,
};

pub const KUSAMA_CONFIG: SubstrateChainConfig = SubstrateChainConfig {
    chain: Chain::Kusama,
    ss58_prefix: 2,
    name: "Kusama",
    token: "KSM",
    decimals: 12,
};

pub const ASTAR_CONFIG: SubstrateChainConfig = SubstrateChainConfig {
    chain: Chain::Astar,
    ss58_prefix: 5,
    name: "Astar",
    token: "ASTR",
    decimals: 18,
};

pub const ACALA_CONFIG: SubstrateChainConfig = SubstrateChainConfig {
    chain: Chain::Acala,
    ss58_prefix: 10,
    name: "Acala",
    token: "ACA",
    decimals: 12,
};

pub const PHALA_CONFIG: SubstrateChainConfig = SubstrateChainConfig {
    chain: Chain::Phala,
    ss58_prefix: 30,
    name: "Phala",
    token: "PHA",
    decimals: 12,
};

pub const INTERLAY_CONFIG: SubstrateChainConfig = SubstrateChainConfig {
    chain: Chain::Interlay,
    ss58_prefix: 2032,
    name: "Interlay",
    token: "INTR",
    decimals: 10,
};

/// Substrate chain provider — supports Polkadot, Kusama, and parachains.
///
/// Uses Ed25519 signing (FROST Ed25519). Sr25519 threshold MPC is planned
/// as a future protocol addition.
pub struct SubstrateProvider {
    pub config: SubstrateChainConfig,
}

impl SubstrateProvider {
    pub fn polkadot() -> Self {
        Self {
            config: POLKADOT_CONFIG,
        }
    }

    pub fn kusama() -> Self {
        Self {
            config: KUSAMA_CONFIG,
        }
    }

    pub fn astar() -> Self {
        Self {
            config: ASTAR_CONFIG,
        }
    }

    pub fn acala() -> Self {
        Self {
            config: ACALA_CONFIG,
        }
    }

    pub fn phala() -> Self {
        Self {
            config: PHALA_CONFIG,
        }
    }

    pub fn interlay() -> Self {
        Self {
            config: INTERLAY_CONFIG,
        }
    }
}

#[async_trait]
impl ChainProvider for SubstrateProvider {
    fn chain(&self) -> Chain {
        self.config.chain
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_substrate_address(group_pubkey, self.config.ss58_prefix)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        let value: u64 = params
            .value
            .parse()
            .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

        // Simplified SCALE-like payload
        let mut payload = Vec::new();
        // Module + call index placeholder
        payload.extend_from_slice(&[0x04, 0x00]); // balances.transfer
        payload.extend_from_slice(params.to.as_bytes());
        payload.extend_from_slice(&value.to_le_bytes());
        if let Some(extra) = &params.extra {
            payload.extend_from_slice(extra.to_string().as_bytes());
        }

        // Sign payload = Blake2b-256(payload)
        use blake2::{digest::consts::U32, Blake2b, Digest};
        type Blake2b256 = Blake2b<U32>;
        let sign_payload = Blake2b256::digest(&payload).to_vec();

        Ok(UnsignedTransaction {
            chain: self.config.chain,
            sign_payload,
            tx_data: payload,
        })
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        let sig_bytes = match sig {
            MpcSignature::EdDsa { signature } => signature.to_vec(),
            _ => {
                return Err(CoreError::InvalidInput(format!(
                    "{} requires EdDsa signature (Ed25519)",
                    self.config.name
                )))
            }
        };

        // Extrinsic: [length | signed_flag | account | sig_type(0x00=Ed25519) | sig | era | nonce | tip | call_data]
        let mut raw_tx = Vec::new();
        raw_tx.push(0x00); // Ed25519 signature type
        raw_tx.extend_from_slice(&sig_bytes);
        raw_tx.extend_from_slice(&unsigned.tx_data);

        let tx_hash = hex::encode(&unsigned.sign_payload);

        Ok(SignedTransaction {
            chain: self.config.chain,
            raw_tx,
            tx_hash,
        })
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        // Substrate RPC: author_submitExtrinsic
        let raw_hex = format!("0x{}", hex::encode(&signed.raw_tx));
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "author_submitExtrinsic",
            "params": [raw_hex]
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
                "{} broadcast failed: {msg}",
                self.config.name
            )));
        }
        json.get("result")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                CoreError::Other(format!("missing tx hash in {} response", self.config.name))
            })
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let mut risk_flags = Vec::new();
        let mut risk_score: u8 = 0;

        let amount: u64 = params.value.parse().unwrap_or(0);
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
