use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

/// Supported blockchain networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Result of a transaction simulation / risk analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: Vec<u8>,
    pub risk_flags: Vec<String>,
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

    /// Simulate a transaction and return a risk assessment.
    ///
    /// The default implementation returns a neutral result (no risk flags, score 0).
    /// Chain providers can override this to perform chain-specific analysis.
    async fn simulate_transaction(
        &self,
        _params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        Ok(SimulationResult {
            success: true,
            gas_used: 0,
            return_data: vec![],
            risk_flags: vec![],
            risk_score: 0,
        })
    }
}
