//! Transaction and simulation endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use mpc_wallet_chains::provider::{Chain, TransactionParams};

use crate::models::request::{SimulateRequest, TransactionRequest};
use crate::models::response::{ApiResponse, SimulationResponse, TransactionResponse};
use crate::state::AppState;

/// Explorer URL for a transaction hash.
#[allow(dead_code)]
fn explorer_url(chain: Chain, tx_hash: &str) -> Option<String> {
    match chain {
        Chain::Ethereum => Some(format!("https://etherscan.io/tx/{tx_hash}")),
        Chain::Polygon => Some(format!("https://polygonscan.com/tx/{tx_hash}")),
        Chain::Bsc => Some(format!("https://bscscan.com/tx/{tx_hash}")),
        Chain::Arbitrum => Some(format!("https://arbiscan.io/tx/{tx_hash}")),
        Chain::Optimism => Some(format!("https://optimistic.etherscan.io/tx/{tx_hash}")),
        Chain::Base => Some(format!("https://basescan.org/tx/{tx_hash}")),
        Chain::Avalanche => Some(format!("https://snowtrace.io/tx/{tx_hash}")),
        Chain::Solana => Some(format!("https://explorer.solana.com/tx/{tx_hash}")),
        Chain::BitcoinMainnet => Some(format!("https://mempool.space/tx/{tx_hash}")),
        Chain::BitcoinTestnet => Some(format!("https://mempool.space/testnet/tx/{tx_hash}")),
        Chain::Sui => Some(format!("https://suiscan.xyz/mainnet/tx/{tx_hash}")),
        _ => None,
    }
}

/// `POST /v1/wallets/:id/transactions` — build + sign + broadcast.
pub async fn create_transaction(
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
    Json(req): Json<TransactionRequest>,
) -> Result<Json<ApiResponse<TransactionResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let chain: Chain = req
        .chain
        .parse()
        .map_err(|e: String| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;

    // Verify chain provider exists.
    let _provider = state.chain_registry.provider(chain).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(e.to_string())),
        )
    })?;

    // Parse optional calldata.
    let data = req
        .data
        .as_deref()
        .map(|d| {
            hex::decode(d.strip_prefix("0x").unwrap_or(d)).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::err(format!("invalid hex data: {e}"))),
                )
            })
        })
        .transpose()?;

    let _params = TransactionParams {
        to: req.to,
        value: req.value,
        data,
        chain_id: None,
        extra: req.extra,
    };

    state.metrics.sign_total.inc();

    // In production:
    // 1. Load key share from key store by wallet_id
    // 2. Build unsigned tx: provider.build_transaction(params)
    // 3. MPC sign: protocol.sign(key_share, signers, sign_payload, transport)
    // 4. Finalize: provider.finalize_transaction(unsigned, signature)
    // 5. Broadcast: chain_registry.broadcast(signed)

    Err((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::err(format!(
            "wallet {wallet_id} not found — full tx pipeline requires key store + MPC transport"
        ))),
    ))
}

/// `POST /v1/wallets/:id/simulate` — simulate transaction risk.
pub async fn simulate_transaction(
    State(state): State<AppState>,
    Path(_wallet_id): Path<String>,
    Json(req): Json<SimulateRequest>,
) -> Result<Json<ApiResponse<SimulationResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let chain: Chain = req
        .chain
        .parse()
        .map_err(|e: String| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;

    let provider = state.chain_registry.provider(chain).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(e.to_string())),
        )
    })?;

    let data = req
        .data
        .as_deref()
        .map(|d| {
            hex::decode(d.strip_prefix("0x").unwrap_or(d)).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::err(format!("invalid hex data: {e}"))),
                )
            })
        })
        .transpose()?;

    let params = TransactionParams {
        to: req.to,
        value: req.value,
        data,
        chain_id: None,
        extra: req.extra,
    };

    match provider.simulate_transaction(&params).await {
        Ok(result) => Ok(Json(ApiResponse::ok(SimulationResponse {
            success: result.success,
            gas_used: result.gas_used,
            risk_score: result.risk_score,
            risk_flags: result.risk_flags,
        }))),
        Err(e) => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ApiResponse::err(format!("simulation failed: {e}"))),
        )),
    }
}

// Re-export explorer_url for use in tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explorer_urls() {
        let url = explorer_url(Chain::Ethereum, "0xabc").unwrap();
        assert!(url.contains("etherscan.io"));
        assert!(url.contains("0xabc"));

        let url = explorer_url(Chain::BitcoinMainnet, "abc123").unwrap();
        assert!(url.contains("mempool.space"));

        let url = explorer_url(Chain::Solana, "sig123").unwrap();
        assert!(url.contains("explorer.solana.com"));

        // Unknown chain returns None
        assert!(explorer_url(Chain::Monero, "x").is_none());
    }
}
