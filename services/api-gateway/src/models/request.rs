//! API request types.

use serde::Deserialize;

/// Request body for `POST /v1/wallets` — create a new MPC wallet.
#[derive(Debug, Deserialize)]
pub struct CreateWalletRequest {
    /// Human-readable label for the wallet.
    pub label: String,
    /// Cryptographic scheme: "gg20-ecdsa", "frost-ed25519", etc.
    pub scheme: String,
    /// Signing threshold (t).
    pub threshold: u16,
    /// Total number of parties (n).
    pub total_parties: u16,
}

/// Request body for `POST /v1/wallets/:id/sign` — sign a message.
#[derive(Debug, Deserialize)]
pub struct SignRequest {
    /// Hex-encoded message to sign.
    pub message: String,
}

/// Request body for `POST /v1/wallets/:id/transactions` — build + sign + broadcast.
#[derive(Debug, Deserialize)]
pub struct TransactionRequest {
    /// Target chain: "ethereum", "bitcoin", "solana", etc.
    pub chain: String,
    /// Recipient address.
    pub to: String,
    /// Value as string (chain-native denomination, e.g. wei for EVM).
    pub value: String,
    /// Optional calldata (hex-encoded, for smart contract calls).
    pub data: Option<String>,
    /// Extra chain-specific parameters.
    pub extra: Option<serde_json::Value>,
}

/// Request body for `POST /v1/wallets/:id/simulate`.
#[derive(Debug, Deserialize)]
pub struct SimulateRequest {
    /// Target chain.
    pub chain: String,
    /// Recipient address.
    pub to: String,
    /// Value as string.
    pub value: String,
    /// Optional calldata (hex-encoded).
    pub data: Option<String>,
    /// Extra chain-specific parameters.
    pub extra: Option<serde_json::Value>,
}
