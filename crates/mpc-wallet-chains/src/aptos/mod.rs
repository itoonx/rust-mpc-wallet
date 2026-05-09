pub mod address;
pub mod rpc_client;
pub mod signer;
pub mod tx;
pub mod types;

pub use address::validate_aptos_address;

use async_trait::async_trait;
use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// Configuration for Aptos transaction simulation / risk analysis.
#[derive(Debug, Clone)]
pub struct AptosSimulationConfig {
    /// Maximum Octas (1 APT = 10^8 Octas) per transaction before flagging as high-value.
    pub max_octas_per_tx: u64,
    /// Maximum gas budget before flagging as excessive.
    pub max_gas_amount: u64,
}

impl Default for AptosSimulationConfig {
    fn default() -> Self {
        Self {
            max_octas_per_tx: 1_000_000_000_000, // 10,000 APT
            max_gas_amount: 200_000,
        }
    }
}

/// Move VM chain provider — supports Aptos and Movement.
///
/// Both chains use BCS encoding, SHA3-256 hashing, and Ed25519 signing.
/// Movement is a Move-based L2 on Ethereum with the same VM and tx format.
///
/// Holds an optional Ed25519 `GroupPublicKey` so that `build_transaction` can
/// embed it inside the serialized `tx_data`, and `finalize_transaction` can
/// later recover it to build the correct signature format.
pub struct AptosProvider {
    chain: Chain,
    group_pubkey: Option<GroupPublicKey>,
    simulation_config: Option<AptosSimulationConfig>,
}

impl AptosProvider {
    /// Create an Aptos provider (address derivation only).
    pub fn new() -> Self {
        Self {
            chain: Chain::Aptos,
            group_pubkey: None,
            simulation_config: None,
        }
    }

    /// Create a Movement provider (address derivation only).
    pub fn movement() -> Self {
        Self {
            chain: Chain::Movement,
            group_pubkey: None,
            simulation_config: None,
        }
    }

    /// Create a provider pre-loaded with the group's Ed25519 public key.
    pub fn with_pubkey(group_pubkey: GroupPublicKey) -> Self {
        Self {
            chain: Chain::Aptos,
            group_pubkey: Some(group_pubkey),
            simulation_config: None,
        }
    }

    /// Create a Movement provider pre-loaded with the group's Ed25519 public key.
    pub fn movement_with_pubkey(group_pubkey: GroupPublicKey) -> Self {
        Self {
            chain: Chain::Movement,
            group_pubkey: Some(group_pubkey),
            simulation_config: None,
        }
    }

    /// Attach a simulation configuration for risk analysis.
    pub fn with_simulation(mut self, config: AptosSimulationConfig) -> Self {
        self.simulation_config = Some(config);
        self
    }
}

impl Default for AptosProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainProvider for AptosProvider {
    fn chain(&self) -> Chain {
        self.chain
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_aptos_address(group_pubkey)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        // Pubkey resolution: provider-stored → extras["pubkey_hex"] → error.
        // Mirrors the Sui pattern so registry-built providers work without
        // forcing every caller to use `with_pubkey`.
        let owned;
        let pubkey: &GroupPublicKey = if let Some(pk) = &self.group_pubkey {
            pk
        } else if let Some(hex_str) = params
            .extra
            .as_ref()
            .and_then(|e| e.get("pubkey_hex"))
            .and_then(|v| v.as_str())
        {
            let bytes = hex::decode(hex_str).map_err(|e| {
                CoreError::InvalidInput(format!("Aptos pubkey_hex invalid hex: {e}"))
            })?;
            if bytes.len() != 32 {
                return Err(CoreError::InvalidInput(format!(
                    "Aptos pubkey_hex must decode to 32 bytes, got {}",
                    bytes.len()
                )));
            }
            owned = GroupPublicKey::Ed25519(bytes);
            &owned
        } else {
            return Err(CoreError::InvalidInput(
                "AptosProvider requires a GroupPublicKey — use `with_pubkey` or pass `pubkey_hex` in extras".into(),
            ));
        };
        tx::build_move_transaction(self.chain, params, pubkey).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_aptos_transaction(unsigned, sig)
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        // Aptos accepts a BCS-encoded SignedTransaction at POST /v1/transactions
        // when Content-Type is application/x.aptos.signed_transaction+bcs.
        // `signed.raw_tx` is exactly that body (RawTransaction BCS ‖ Authenticator BCS).
        rpc_client::AptosRpcClient::new(rpc_url)
            .submit(&signed.raw_tx)
            .await
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let config = match &self.simulation_config {
            Some(c) => c,
            None => {
                return Ok(SimulationResult {
                    success: true,
                    gas_used: 0,
                    return_data: vec![],
                    risk_flags: vec![],
                    risk_score: 0,
                });
            }
        };

        let mut risk_flags = Vec::new();
        let mut risk_score: u16 = 0;

        let octas: u64 = params.value.parse().unwrap_or(0);
        if octas > config.max_octas_per_tx {
            risk_flags.push("high_value".to_string());
            risk_score += 50;
        }

        if let Some(extra) = &params.extra {
            if let Some(gas) = extra.get("max_gas_amount").and_then(|v| v.as_u64()) {
                if gas > config.max_gas_amount {
                    risk_flags.push("excessive_gas".to_string());
                    risk_score += 30;
                }
            }
        }

        Ok(SimulationResult {
            success: true,
            gas_used: 0,
            return_data: vec![],
            risk_flags,
            risk_score: risk_score.min(255) as u8,
        })
    }
}
