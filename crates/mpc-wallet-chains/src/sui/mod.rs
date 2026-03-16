pub mod address;
pub mod signer;
pub mod tx;

pub use tx::validate_sui_address;

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// Configuration for Sui transaction simulation / risk analysis.
#[derive(Debug, Clone)]
pub struct SuiSimulationConfig {
    /// Maximum MIST (1 SUI = 10^9 MIST) per transaction before flagging as high-value.
    pub max_mist_per_tx: u64,
    /// Maximum gas budget before flagging as excessive.
    pub max_gas_budget: u64,
}

impl Default for SuiSimulationConfig {
    fn default() -> Self {
        Self {
            max_mist_per_tx: 1_000_000_000_000,
            max_gas_budget: 50_000_000,
        }
    }
}

/// Sui chain provider.
///
/// Holds an optional Ed25519 `GroupPublicKey` so that `build_transaction` can
/// embed it inside the serialized `tx_data`, and `finalize_transaction` can
/// later recover it to build the correct Sui signature format.
///
/// Use `SuiProvider::with_pubkey` when you have the group public key at
/// provider-construction time (the typical production path).  The bare
/// `SuiProvider::new()` constructor exists for contexts where only address
/// derivation is needed.
pub struct SuiProvider {
    group_pubkey: Option<GroupPublicKey>,
    simulation_config: Option<SuiSimulationConfig>,
}

impl SuiProvider {
    /// Create a provider without a pre-loaded public key (address derivation only).
    pub fn new() -> Self {
        Self {
            group_pubkey: None,
            simulation_config: None,
        }
    }

    /// Create a provider pre-loaded with the group's Ed25519 public key.
    /// Use this constructor when you need to call `build_transaction` /
    /// `finalize_transaction`.
    pub fn with_pubkey(group_pubkey: GroupPublicKey) -> Self {
        Self {
            group_pubkey: Some(group_pubkey),
            simulation_config: None,
        }
    }

    /// Attach a simulation configuration for risk analysis.
    pub fn with_simulation(mut self, config: SuiSimulationConfig) -> Self {
        self.simulation_config = Some(config);
        self
    }
}

impl Default for SuiProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SuiProvider {
    /// Build a Sui transaction with an explicit sender address.
    ///
    /// Unlike `build_transaction` (which reads the sender from `params.extra["sender"]`),
    /// this method takes the sender directly and validates it before constructing the tx.
    ///
    /// # Errors
    /// Returns `CoreError::InvalidInput` if `sender` is not a valid Sui address
    /// (`0x` + 64 lowercase hex chars).
    pub async fn build_transaction_with_sender(
        &self,
        params: TransactionParams,
        sender: &str,
    ) -> Result<UnsignedTransaction, CoreError> {
        // Validate sender address — fail fast before touching any transaction state.
        tx::validate_sui_address(sender)?;

        // Inject validated sender into extra params and delegate.
        let mut params = params;
        let extra = params
            .extra
            .get_or_insert(serde_json::Value::Object(Default::default()));
        extra["sender"] = serde_json::Value::String(sender.to_string());
        params.extra = Some(extra.clone());

        // Delegate to existing build logic (requires pubkey stored).
        self.build_transaction(params).await
    }

    /// Broadcast a signed transaction to the Sui network.
    ///
    /// # TODO (production)
    /// Use the Sui JSON-RPC API: `sui_executeTransactionBlock`
    /// - POST to `{rpc_url}` with:
    ///   ```json
    ///   {
    ///     "jsonrpc": "2.0",
    ///     "id": 1,
    ///     "method": "sui_executeTransactionBlock",
    ///     "params": [
    ///       "<base64 tx_bytes>",
    ///       ["<base64 signature>"],
    ///       {"showEffects": true},
    ///       "WaitForLocalExecution"
    ///     ]
    ///   }
    ///   ```
    /// Returns the transaction digest as the tx hash.
    pub async fn broadcast_stub(
        &self,
        _signed: &crate::provider::SignedTransaction,
    ) -> Result<String, mpc_wallet_core::error::CoreError> {
        // TODO(production): implement HTTP call to Sui RPC
        // For now, return a placeholder tx digest
        Err(mpc_wallet_core::error::CoreError::Protocol(
            "broadcast not yet implemented — use sui_executeTransactionBlock RPC".to_string(),
        ))
    }
}

#[async_trait]
impl ChainProvider for SuiProvider {
    fn chain(&self) -> Chain {
        Chain::Sui
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_sui_address(group_pubkey)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        let pubkey = self.group_pubkey.as_ref().ok_or_else(|| {
            CoreError::InvalidInput(
                "SuiProvider requires a GroupPublicKey — use SuiProvider::with_pubkey".into(),
            )
        })?;
        tx::build_sui_transaction(params, pubkey).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_sui_transaction(unsigned, sig)
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

        // Check value against max_mist_per_tx
        let mist: u64 = params.value.parse().unwrap_or(0);
        if mist > config.max_mist_per_tx {
            risk_flags.push("high_value".to_string());
            risk_score += 50;
        }

        // Check gas_budget from extra against max_gas_budget
        if let Some(extra) = &params.extra {
            if let Some(gas_budget) = extra.get("gas_budget").and_then(|v| v.as_u64()) {
                if gas_budget > config.max_gas_budget {
                    risk_flags.push("excessive_gas_budget".to_string());
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
