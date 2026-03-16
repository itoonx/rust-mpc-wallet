//! UTXO chain infrastructure — shared by Bitcoin, Litecoin, Dogecoin, Zcash.
//!
//! This module provides:
//! - `UtxoChainConfig` — per-chain address version bytes and network params
//! - `UtxoSimulationConfig` + `simulate_utxo()` — shared dust/fee/RBF risk checks
//! - `broadcast_utxo_rest()` — shared REST POST /tx broadcast (Blockstream/Mempool pattern)
//! - `UtxoProvider` — generic provider for LTC/DOGE/ZEC (Bitcoin has its own Taproot provider)
//!
//! Bitcoin stays in `crate::bitcoin` for Taproot-specific code but uses these shared utilities.

pub mod address;
pub mod broadcast;
pub mod simulation;

pub use broadcast::broadcast_utxo_rest;
pub use simulation::{simulate_utxo, UtxoSimulationConfig};

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// UTXO chain configuration.
#[derive(Debug, Clone, Copy)]
pub struct UtxoChainConfig {
    pub chain: Chain,
    /// P2PKH address version byte.
    pub p2pkh_version: u8,
    /// P2SH address version byte.
    pub p2sh_version: u8,
    /// Human-readable part for bech32 addresses (if supported).
    pub bech32_hrp: Option<&'static str>,
    /// Coin name for display.
    pub coin_name: &'static str,
}

// ── Bitcoin configs (for reference — Bitcoin uses its own Taproot provider) ──

/// Bitcoin mainnet configuration.
pub const BITCOIN_MAINNET_CONFIG: UtxoChainConfig = UtxoChainConfig {
    chain: Chain::BitcoinMainnet,
    p2pkh_version: 0x00, // '1' prefix
    p2sh_version: 0x05,  // '3' prefix
    bech32_hrp: Some("bc"),
    coin_name: "Bitcoin",
};

/// Bitcoin testnet configuration.
pub const BITCOIN_TESTNET_CONFIG: UtxoChainConfig = UtxoChainConfig {
    chain: Chain::BitcoinTestnet,
    p2pkh_version: 0x6F, // 'm' or 'n' prefix
    p2sh_version: 0xC4,  // '2' prefix
    bech32_hrp: Some("tb"),
    coin_name: "Bitcoin Testnet",
};

// ── Other UTXO chain configs ────────────────────────────────────────────────

/// Litecoin configuration.
pub const LITECOIN_CONFIG: UtxoChainConfig = UtxoChainConfig {
    chain: Chain::Litecoin,
    p2pkh_version: 0x30, // 'L' prefix
    p2sh_version: 0x32,  // 'M' prefix
    bech32_hrp: Some("ltc"),
    coin_name: "Litecoin",
};

/// Dogecoin configuration.
pub const DOGECOIN_CONFIG: UtxoChainConfig = UtxoChainConfig {
    chain: Chain::Dogecoin,
    p2pkh_version: 0x1E, // 'D' prefix
    p2sh_version: 0x16,  // '9' or 'A' prefix
    bech32_hrp: None,    // Dogecoin doesn't widely use bech32
    coin_name: "Dogecoin",
};

/// Zcash transparent configuration.
pub const ZCASH_CONFIG: UtxoChainConfig = UtxoChainConfig {
    chain: Chain::Zcash,
    p2pkh_version: 0x1C, // t1 prefix (two-byte: 0x1CB8)
    p2sh_version: 0x1C,  // t3 prefix (two-byte: 0x1CBD)
    bech32_hrp: None,    // Zcash uses t-addresses, not bech32
    coin_name: "Zcash",
};

/// Generic UTXO chain provider for Litecoin, Dogecoin, Zcash.
///
/// Uses secp256k1 ECDSA signing (GG20) — same as Bitcoin legacy.
/// Bitcoin has its own `BitcoinProvider` with Taproot/Schnorr support,
/// but shares broadcast and simulation utilities from this module.
pub struct UtxoProvider {
    pub config: UtxoChainConfig,
    pub simulation_config: Option<UtxoSimulationConfig>,
}

impl UtxoProvider {
    pub fn litecoin() -> Self {
        Self {
            config: LITECOIN_CONFIG,
            simulation_config: None,
        }
    }

    pub fn dogecoin() -> Self {
        Self {
            config: DOGECOIN_CONFIG,
            simulation_config: None,
        }
    }

    pub fn zcash() -> Self {
        Self {
            config: ZCASH_CONFIG,
            simulation_config: None,
        }
    }

    /// Enable transaction simulation with the given configuration.
    pub fn with_simulation(mut self, config: UtxoSimulationConfig) -> Self {
        self.simulation_config = Some(config);
        self
    }
}

#[async_trait]
impl ChainProvider for UtxoProvider {
    fn chain(&self) -> Chain {
        self.config.chain
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_utxo_p2pkh_address(group_pubkey, &self.config)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        let chain = self.config.chain;
        let value: u64 = params
            .value
            .parse()
            .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

        let mut payload_data = Vec::new();
        payload_data.extend_from_slice(params.to.as_bytes());
        payload_data.extend_from_slice(&value.to_le_bytes());
        if let Some(extra) = &params.extra {
            payload_data.extend_from_slice(extra.to_string().as_bytes());
        }

        // Double SHA-256 hash (standard for UTXO chains)
        use sha2::{Digest, Sha256};
        let first = Sha256::digest(&payload_data);
        let sign_payload = Sha256::digest(first).to_vec();

        Ok(UnsignedTransaction {
            chain,
            sign_payload,
            tx_data: payload_data,
        })
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        let (r, s) = match sig {
            MpcSignature::Ecdsa { r, s, .. } => (r.clone(), s.clone()),
            _ => {
                return Err(CoreError::InvalidInput(format!(
                    "{} requires ECDSA signature",
                    self.config.coin_name
                )))
            }
        };

        let mut raw_tx = unsigned.tx_data.clone();
        raw_tx.extend_from_slice(&r);
        raw_tx.extend_from_slice(&s);

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
        broadcast_utxo_rest(signed, rpc_url).await
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let config = self.simulation_config.as_ref().ok_or_else(|| {
            CoreError::Other(format!(
                "{} simulation not configured",
                self.config.coin_name
            ))
        })?;
        Ok(simulate_utxo(params, config))
    }
}
