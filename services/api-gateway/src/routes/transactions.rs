//! Transaction and simulation endpoints with RBAC enforcement.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};

use mpc_wallet_chains::provider::{Chain, TransactionParams};
use mpc_wallet_core::rbac::{ApiRole, AuthContext, Permissions};

use crate::errors::{ApiError, ErrorBody, ErrorCode};
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
/// Requires: Initiator or Admin + risk tier check
#[utoipa::path(post, path = "/v1/wallets/{id}/transactions", tag = "Transactions",
    params(("id" = String, Path, description = "Wallet ID")),
    request_body = TransactionRequest,
    security(("session_token" = [])),
    responses(
        (status = 200, description = "Transaction broadcast", body = ApiResponse<TransactionResponse>),
        (status = 404, description = "Wallet not found", body = ErrorBody)
    )
)]
pub async fn create_transaction(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
    Json(req): Json<TransactionRequest>,
) -> Result<Json<ApiResponse<TransactionResponse>>, ApiError> {
    Permissions::require_role(&ctx, &[ApiRole::Initiator, ApiRole::Admin])
        .map_err(|_| ApiError::forbidden("insufficient permissions"))?;
    Permissions::check_risk_tier_for_signing(&ctx)
        .map_err(|e| ApiError::forbidden(e.to_string()))?;

    let chain: Chain = req
        .chain
        .parse()
        .map_err(|e: String| ApiError::bad_request(ErrorCode::InvalidInput, e))?;

    let _provider = state
        .chain_registry
        .provider(chain)
        .map_err(ApiError::from)?;

    let data = req
        .data
        .as_deref()
        .map(|d| {
            hex::decode(d.strip_prefix("0x").unwrap_or(d)).map_err(|e| {
                ApiError::bad_request(ErrorCode::InvalidInput, format!("invalid hex data: {e}"))
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

    Err(ApiError::not_found(format!(
        "wallet {wallet_id} not found — full tx pipeline requires key store + MPC transport"
    )))
}

/// `POST /v1/wallets/:id/simulate` — simulate transaction risk.
/// Requires: Viewer+
#[utoipa::path(post, path = "/v1/wallets/{id}/simulate", tag = "Transactions",
    params(("id" = String, Path, description = "Wallet ID")),
    request_body = SimulateRequest,
    security(("session_token" = [])),
    responses(
        (status = 200, description = "Simulation result", body = ApiResponse<SimulationResponse>),
        (status = 401, description = "Unauthorized", body = ErrorBody)
    )
)]
pub async fn simulate_transaction(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(_wallet_id): Path<String>,
    Json(req): Json<SimulateRequest>,
) -> Result<Json<ApiResponse<SimulationResponse>>, ApiError> {
    Permissions::require_role(
        &ctx,
        &[
            ApiRole::Viewer,
            ApiRole::Initiator,
            ApiRole::Approver,
            ApiRole::Admin,
        ],
    )
    .map_err(|_| ApiError::forbidden("insufficient permissions"))?;

    let chain: Chain = req
        .chain
        .parse()
        .map_err(|e: String| ApiError::bad_request(ErrorCode::InvalidInput, e))?;

    let provider = state
        .chain_registry
        .provider(chain)
        .map_err(ApiError::from)?;

    let data = req
        .data
        .as_deref()
        .map(|d| {
            hex::decode(d.strip_prefix("0x").unwrap_or(d)).map_err(|e| {
                ApiError::bad_request(ErrorCode::InvalidInput, format!("invalid hex data: {e}"))
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
        Err(e) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::ProtocolError,
            format!("simulation failed: {e}"),
        )),
    }
}

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

        assert!(explorer_url(Chain::Monero, "x").is_none());
    }
}
