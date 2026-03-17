//! API response types.

use serde::Serialize;

/// Generic API response wrapper.
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

/// Response for wallet creation.
#[derive(Debug, Serialize)]
pub struct WalletResponse {
    pub id: String,
    pub label: String,
    pub scheme: String,
    pub threshold: u16,
    pub total_parties: u16,
    pub created_at: u64,
}

/// Response for wallet list.
#[derive(Debug, Serialize)]
pub struct WalletListResponse {
    pub wallets: Vec<WalletResponse>,
}

/// Response for wallet details with addresses.
#[derive(Debug, Serialize)]
pub struct WalletDetailResponse {
    pub id: String,
    pub label: String,
    pub scheme: String,
    pub threshold: u16,
    pub total_parties: u16,
    pub created_at: u64,
    pub addresses: Vec<AddressEntry>,
}

/// A chain-specific address derived from the wallet's group public key.
#[derive(Debug, Serialize)]
pub struct AddressEntry {
    pub chain: String,
    pub address: String,
}

/// Response for signing.
#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub signature: serde_json::Value,
    pub scheme: String,
}

/// Response for transaction broadcast.
#[derive(Debug, Serialize)]
pub struct TransactionResponse {
    pub tx_hash: String,
    pub chain: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
}

/// Response for simulation.
#[derive(Debug, Serialize)]
pub struct SimulationResponse {
    pub success: bool,
    pub gas_used: u64,
    pub risk_score: u8,
    pub risk_flags: Vec<String>,
}

/// Single chain info in the chains list.
#[derive(Debug, Serialize)]
pub struct ChainInfo {
    pub name: String,
    pub display_name: String,
    pub category: String,
}

/// Response for chains list.
#[derive(Debug, Serialize)]
pub struct ChainsListResponse {
    pub chains: Vec<ChainInfo>,
    pub total: usize,
}

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub chains_supported: usize,
}
