//! Transaction and simulation endpoints with RBAC enforcement.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use sha2::{Digest, Sha256};

use mpc_wallet_chains::evm::rpc_client::EvmRpcClient;
use mpc_wallet_chains::provider::{Chain, TransactionParams};
use mpc_wallet_chains::registry::NetworkEnv;
use mpc_wallet_chains::rpc::providers::infura::InfuraProvider;
use mpc_wallet_chains::rpc::RpcProvider;
use mpc_wallet_core::protocol::sign_authorization::{AuthorizationPayload, SignAuthorization};
use mpc_wallet_core::rbac::{ApiRole, AuthContext, Permissions};

use crate::errors::{ApiError, ErrorBody, ErrorCode};
use crate::models::request::{SimulateRequest, TransactionRequest};
use crate::models::response::{ApiResponse, SimulationResponse, TransactionResponse};
use crate::state::AppState;

/// Explorer URL for a transaction hash, network-aware.
fn explorer_url(chain: Chain, network: &NetworkEnv, tx_hash: &str) -> Option<String> {
    let base = match (chain, network) {
        (Chain::Ethereum, NetworkEnv::Mainnet) => "https://etherscan.io/tx/",
        (Chain::Ethereum, _) => "https://sepolia.etherscan.io/tx/",
        (Chain::Polygon, NetworkEnv::Mainnet) => "https://polygonscan.com/tx/",
        (Chain::Polygon, _) => "https://amoy.polygonscan.com/tx/",
        (Chain::Bsc, _) => "https://bscscan.com/tx/",
        (Chain::Arbitrum, NetworkEnv::Mainnet) => "https://arbiscan.io/tx/",
        (Chain::Arbitrum, _) => "https://sepolia.arbiscan.io/tx/",
        (Chain::Optimism, NetworkEnv::Mainnet) => "https://optimistic.etherscan.io/tx/",
        (Chain::Optimism, _) => "https://sepolia-optimism.etherscan.io/tx/",
        (Chain::Base, NetworkEnv::Mainnet) => "https://basescan.org/tx/",
        (Chain::Base, _) => "https://sepolia.basescan.org/tx/",
        (Chain::Avalanche, _) => "https://snowtrace.io/tx/",
        (Chain::Solana, _) => "https://explorer.solana.com/tx/",
        (Chain::BitcoinMainnet, _) => "https://mempool.space/tx/",
        (Chain::BitcoinTestnet, _) => "https://mempool.space/testnet/tx/",
        (Chain::Sui, _) => "https://suiscan.xyz/mainnet/tx/",
        _ => return None,
    };
    Some(format!("{base}{tx_hash}"))
}

fn parse_network(s: &str) -> NetworkEnv {
    match s {
        "mainnet" => NetworkEnv::Mainnet,
        "devnet" => NetworkEnv::Devnet,
        _ => NetworkEnv::Testnet,
    }
}

/// Resolve an EVM RPC URL for the given chain via Infura. Errors if
/// `INFURA_API_KEY` is not configured or the chain is unsupported.
fn resolve_evm_rpc(state: &AppState, chain: Chain) -> Result<String, ApiError> {
    let key = state.infura_api_key.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::InternalError,
            "INFURA_API_KEY not configured — cannot broadcast EVM tx",
        )
    })?;
    let provider = InfuraProvider::new(key);
    provider
        .https_endpoint(chain, &parse_network(&state.network))
        .ok_or_else(|| {
            ApiError::bad_request(
                ErrorCode::InvalidInput,
                format!(
                    "Infura does not support chain {chain} on network {}",
                    state.network
                ),
            )
        })
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

    // Today only EVM chains have a wired build → MPC sign → broadcast path here.
    let is_evm = matches!(
        chain,
        Chain::Ethereum
            | Chain::Polygon
            | Chain::Bsc
            | Chain::Arbitrum
            | Chain::Optimism
            | Chain::Base
            | Chain::Avalanche
            | Chain::Linea
    );
    if !is_evm {
        return Err(ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            ErrorCode::InternalError,
            format!("chain {chain} broadcast not yet wired through gateway"),
        ));
    }

    let metadata = state
        .orchestrator
        .get(&wallet_id)
        .await
        .ok_or_else(|| ApiError::not_found(format!("wallet {wallet_id} not found")))?;

    let provider = state
        .chain_registry
        .provider(chain)
        .map_err(ApiError::from)?;

    let sender = provider
        .derive_address(&metadata.group_public_key)
        .map_err(ApiError::from)?;

    let calldata = req
        .data
        .as_deref()
        .map(|d| {
            hex::decode(d.strip_prefix("0x").unwrap_or(d)).map_err(|e| {
                ApiError::bad_request(ErrorCode::InvalidInput, format!("invalid hex data: {e}"))
            })
        })
        .transpose()?;

    // Pull live nonce + fees from RPC; fall back to caller-supplied `extra` if present.
    let rpc_url = resolve_evm_rpc(&state, chain)?;
    let rpc = EvmRpcClient::new(&rpc_url);
    let chain_id = rpc.get_chain_id().await.map_err(ApiError::from)?;
    let nonce = rpc.get_nonce(&sender).await.map_err(ApiError::from)?;
    let (max_fee, max_priority) = rpc.suggest_eip1559_fees().await.map_err(ApiError::from)?;

    // Merge auto-fetched values with caller-provided overrides (caller wins).
    let mut extra = serde_json::json!({
        "nonce": nonce,
        "gas_limit": 21_000u64,
        "max_fee_per_gas": max_fee as u64,
        "max_priority_fee_per_gas": max_priority as u64,
    });
    if let (Some(serde_json::Value::Object(ref mut base)), Some(serde_json::Value::Object(over))) =
        (Some(&mut extra), req.extra.as_ref())
    {
        for (k, v) in over {
            base.insert(k.clone(), v.clone());
        }
    }

    let params = TransactionParams {
        to: req.to.clone(),
        value: req.value.clone(),
        data: calldata,
        chain_id: Some(chain_id),
        extra: Some(extra),
    };
    let unsigned = mpc_wallet_chains::evm::tx::build_evm_transaction(chain, chain_id, params)
        .await
        .map_err(ApiError::from)?;

    state.metrics.sign_total.inc();

    // Build SignAuthorization (DEC-012) — same pattern as wallets::sign_message.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let payload = AuthorizationPayload {
        authorization_id: uuid::Uuid::new_v4().to_string(),
        requester_id: ctx.user_id.clone(),
        wallet_id: wallet_id.clone(),
        message_hash: hex::encode(Sha256::digest(&unsigned.sign_payload)),
        policy_hash: hex::encode(Sha256::digest(b"")),
        policy_passed: true,
        approval_count: 0,
        approval_required: 0,
        approvers: vec![],
        timestamp: now,
        session_id: uuid::Uuid::new_v4().to_string(),
        encrypted_context: None,
    };
    let sign_auth = SignAuthorization::create(payload, &state.server_signing_key);
    let sign_auth_json = serde_json::to_string(&sign_auth)
        .map_err(|e| ApiError::internal(format!("serialize sign_auth: {e}")))?;

    let sig = state
        .orchestrator
        .sign(&wallet_id, &unsigned.sign_payload, &sign_auth_json)
        .await
        .map_err(ApiError::from)?;

    let signed = provider
        .finalize_transaction(&unsigned, &sig)
        .map_err(ApiError::from)?;

    let tx_hash = provider
        .broadcast(&signed, &rpc_url)
        .await
        .map_err(ApiError::from)?;

    let net = parse_network(&state.network);
    tracing::info!(
        wallet_id = %wallet_id,
        chain = %chain,
        tx_hash = %tx_hash,
        sender = %sender,
        user = %ctx.user_id,
        "EVM transaction broadcast"
    );

    Ok(Json(ApiResponse::ok(TransactionResponse {
        tx_hash: tx_hash.clone(),
        chain: chain.to_string(),
        status: "broadcast".into(),
        explorer_url: explorer_url(chain, &net, &tx_hash),
    })))
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
        let url = explorer_url(Chain::Ethereum, &NetworkEnv::Mainnet, "0xabc").unwrap();
        assert!(url.contains("etherscan.io"));
        assert!(!url.contains("sepolia"));

        let url = explorer_url(Chain::Ethereum, &NetworkEnv::Testnet, "0xabc").unwrap();
        assert!(url.contains("sepolia.etherscan.io"));

        let url = explorer_url(Chain::BitcoinMainnet, &NetworkEnv::Mainnet, "abc").unwrap();
        assert!(url.contains("mempool.space"));

        assert!(explorer_url(Chain::Monero, &NetworkEnv::Mainnet, "x").is_none());
    }
}
