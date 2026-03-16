use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

/// Supported blockchain networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Chain {
    // EVM L1s
    Ethereum,
    Polygon,
    Bsc,
    // EVM L2s — P0
    Arbitrum,
    Optimism,
    Base,
    // EVM L2s — P1
    Avalanche,
    Linea,
    ZkSync,
    Scroll,
    // EVM L2s — P2
    Mantle,
    Blast,
    Zora,
    Fantom,
    Gnosis,
    // EVM L2s — P3
    Cronos,
    Celo,
    Moonbeam,
    Ronin,
    OpBnb,
    Immutable,
    MantaPacific,
    // EVM L2s — Phase 5 (Emerging)
    Hyperliquid,
    Berachain,
    MegaEth,
    Monad,
    // Move chains
    Aptos,
    Movement,
    // UTXO chains
    BitcoinMainnet,
    BitcoinTestnet,
    Litecoin,
    Dogecoin,
    Zcash,
    // CryptoNote
    Monero,
    // Alt L1s
    Ton,
    Tron,
    // Cosmos / IBC
    CosmosHub,
    Osmosis,
    Celestia,
    Injective,
    Sei,
    // Other
    Solana,
    Sui,
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Ethereum => write!(f, "ethereum"),
            Chain::Polygon => write!(f, "polygon"),
            Chain::Bsc => write!(f, "bsc"),
            Chain::Arbitrum => write!(f, "arbitrum"),
            Chain::Optimism => write!(f, "optimism"),
            Chain::Base => write!(f, "base"),
            Chain::Avalanche => write!(f, "avalanche"),
            Chain::Linea => write!(f, "linea"),
            Chain::ZkSync => write!(f, "zksync"),
            Chain::Scroll => write!(f, "scroll"),
            Chain::Mantle => write!(f, "mantle"),
            Chain::Blast => write!(f, "blast"),
            Chain::Zora => write!(f, "zora"),
            Chain::Fantom => write!(f, "fantom"),
            Chain::Gnosis => write!(f, "gnosis"),
            Chain::Cronos => write!(f, "cronos"),
            Chain::Celo => write!(f, "celo"),
            Chain::Moonbeam => write!(f, "moonbeam"),
            Chain::Ronin => write!(f, "ronin"),
            Chain::OpBnb => write!(f, "opbnb"),
            Chain::Immutable => write!(f, "immutable"),
            Chain::MantaPacific => write!(f, "manta-pacific"),
            Chain::Hyperliquid => write!(f, "hyperliquid"),
            Chain::Berachain => write!(f, "berachain"),
            Chain::MegaEth => write!(f, "megaeth"),
            Chain::Monad => write!(f, "monad"),
            Chain::Aptos => write!(f, "aptos"),
            Chain::Movement => write!(f, "movement"),
            Chain::BitcoinMainnet => write!(f, "bitcoin-mainnet"),
            Chain::BitcoinTestnet => write!(f, "bitcoin-testnet"),
            Chain::Litecoin => write!(f, "litecoin"),
            Chain::Dogecoin => write!(f, "dogecoin"),
            Chain::Zcash => write!(f, "zcash"),
            Chain::Monero => write!(f, "monero"),
            Chain::Ton => write!(f, "ton"),
            Chain::Tron => write!(f, "tron"),
            Chain::CosmosHub => write!(f, "cosmos"),
            Chain::Osmosis => write!(f, "osmosis"),
            Chain::Celestia => write!(f, "celestia"),
            Chain::Injective => write!(f, "injective"),
            Chain::Sei => write!(f, "sei"),
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
            "polygon" | "matic" => Ok(Chain::Polygon),
            "bsc" | "bnb" => Ok(Chain::Bsc),
            "arbitrum" | "arb" => Ok(Chain::Arbitrum),
            "optimism" | "op" => Ok(Chain::Optimism),
            "base" => Ok(Chain::Base),
            "avalanche" | "avax" => Ok(Chain::Avalanche),
            "linea" => Ok(Chain::Linea),
            "zksync" | "zksync-era" => Ok(Chain::ZkSync),
            "scroll" => Ok(Chain::Scroll),
            "mantle" => Ok(Chain::Mantle),
            "blast" => Ok(Chain::Blast),
            "zora" => Ok(Chain::Zora),
            "fantom" | "ftm" => Ok(Chain::Fantom),
            "gnosis" | "xdai" => Ok(Chain::Gnosis),
            "cronos" | "cro" => Ok(Chain::Cronos),
            "celo" => Ok(Chain::Celo),
            "moonbeam" | "glmr" => Ok(Chain::Moonbeam),
            "ronin" | "ron" => Ok(Chain::Ronin),
            "opbnb" => Ok(Chain::OpBnb),
            "immutable" | "imx" => Ok(Chain::Immutable),
            "manta-pacific" | "manta" => Ok(Chain::MantaPacific),
            "hyperliquid" | "hyper" => Ok(Chain::Hyperliquid),
            "berachain" | "bera" => Ok(Chain::Berachain),
            "megaeth" => Ok(Chain::MegaEth),
            "monad" => Ok(Chain::Monad),
            "aptos" | "apt" => Ok(Chain::Aptos),
            "movement" | "move" => Ok(Chain::Movement),
            "bitcoin" | "bitcoin-mainnet" | "btc" => Ok(Chain::BitcoinMainnet),
            "bitcoin-testnet" => Ok(Chain::BitcoinTestnet),
            "litecoin" | "ltc" => Ok(Chain::Litecoin),
            "dogecoin" | "doge" => Ok(Chain::Dogecoin),
            "zcash" | "zec" => Ok(Chain::Zcash),
            "monero" | "xmr" => Ok(Chain::Monero),
            "ton" => Ok(Chain::Ton),
            "tron" | "trx" => Ok(Chain::Tron),
            "cosmos" | "atom" | "cosmos-hub" => Ok(Chain::CosmosHub),
            "osmosis" | "osmo" => Ok(Chain::Osmosis),
            "celestia" | "tia" => Ok(Chain::Celestia),
            "injective" | "inj" => Ok(Chain::Injective),
            "sei" => Ok(Chain::Sei),
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

    /// Broadcast a signed transaction to the network via the given RPC endpoint.
    /// Returns the on-chain transaction hash/ID on success.
    /// Default implementation returns an error; chain providers should override.
    async fn broadcast(
        &self,
        _signed: &SignedTransaction,
        _rpc_url: &str,
    ) -> Result<String, CoreError> {
        Err(CoreError::Other(
            "broadcast not implemented for this chain".into(),
        ))
    }
}
