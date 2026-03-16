use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

/// Supported blockchain networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Chain {
    Ethereum,
    Polygon,
    Bsc,
    BitcoinMainnet,
    BitcoinTestnet,
    Solana,
    Sui,
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Ethereum => write!(f, "ethereum"),
            Chain::Polygon => write!(f, "polygon"),
            Chain::Bsc => write!(f, "bsc"),
            Chain::BitcoinMainnet => write!(f, "bitcoin-mainnet"),
            Chain::BitcoinTestnet => write!(f, "bitcoin-testnet"),
            Chain::Solana => write!(f, "solana"),
            Chain::Sui => write!(f, "sui"),
        }
    }
}

impl std::str::FromStr for Chain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ethereum" | "eth" => Ok(Chain::Ethereum),
            "polygon" => Ok(Chain::Polygon),
            "bsc" => Ok(Chain::Bsc),
            "bitcoin" | "bitcoin-mainnet" | "btc" => Ok(Chain::BitcoinMainnet),
            "bitcoin-testnet" => Ok(Chain::BitcoinTestnet),
            "solana" | "sol" => Ok(Chain::Solana),
            "sui" => Ok(Chain::Sui),
            _ => Err(format!("unknown chain: {s}")),
        }
    }
}

/// Parameters for building an unsigned transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionParams {
    pub to: String,
    pub value: String,
    pub data: Option<Vec<u8>>,
    pub chain_id: Option<u64>,
    /// Extra chain-specific parameters as JSON.
    pub extra: Option<serde_json::Value>,
}

/// An unsigned transaction ready for MPC signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransaction {
    /// The chain this transaction is for.
    pub chain: Chain,
    /// The message/hash that needs to be signed.
    pub sign_payload: Vec<u8>,
    /// Serialized transaction data (chain-specific).
    pub tx_data: Vec<u8>,
}

/// A fully signed transaction ready for broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub chain: Chain,
    /// Serialized signed transaction bytes.
    pub raw_tx: Vec<u8>,
    /// Transaction hash/ID.
    pub tx_hash: String,
}

/// Result of a pre-broadcast transaction simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// Whether the simulated execution succeeded.
    pub success: bool,
    /// Estimated gas consumed.
    pub gas_used: u64,
    /// Raw return data from the simulated call (empty for simple transfers).
    pub return_data: Vec<u8>,
    /// Risk flags identified during simulation (e.g. "high_value", "proxy_detected").
    pub risk_flags: Vec<String>,
    /// Aggregate risk score (0 = safe, higher = riskier).
    pub risk_score: u8,
}

/// Trait for chain-specific transaction building and signing.
#[async_trait]
pub trait ChainProvider: Send + Sync {
    /// Returns the chain this provider handles.
    fn chain(&self) -> Chain;

    /// Derive a chain-specific address from a group public key.
    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError>;

    /// Build an unsigned transaction.
    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError>;

    /// Finalize a transaction by attaching the MPC signature.
    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError>;

    /// Simulate a transaction before broadcast, returning risk analysis.
    /// Default implementation returns an error; chain providers may override.
    async fn simulate_transaction(
        &self,
        _params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        Err(CoreError::Other(
            "simulate_transaction not implemented for this chain".into(),
        ))
    }
}
