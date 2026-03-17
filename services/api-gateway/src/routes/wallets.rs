//! Wallet management endpoints: create, list, get, freeze, unfreeze, refresh.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use crate::models::request::{CreateWalletRequest, SignRequest};
use crate::models::response::{
    ApiResponse, SignResponse, WalletDetailResponse, WalletListResponse, WalletResponse,
};
use crate::state::AppState;

/// `POST /v1/wallets` — create a new MPC wallet (keygen).
///
/// In production this triggers a distributed keygen ceremony across MPC nodes.
/// This stub validates the request and returns a wallet ID.
pub async fn create_wallet(
    State(state): State<AppState>,
    Json(req): Json<CreateWalletRequest>,
) -> Result<(StatusCode, Json<ApiResponse<WalletResponse>>), (StatusCode, Json<ApiResponse<()>>)> {
    // Validate scheme.
    let _scheme: mpc_wallet_core::types::CryptoScheme = req
        .scheme
        .parse()
        .map_err(|e: String| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;

    // Validate threshold config.
    mpc_wallet_core::types::ThresholdConfig::new(req.threshold, req.total_parties).map_err(
        |e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::err(e.to_string())),
            )
        },
    )?;

    state.metrics.keygen_total.inc();

    let group_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // In production: initiate MPC keygen ceremony via transport layer,
    // store resulting key shares, and return the group ID.
    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::ok(WalletResponse {
            id: group_id,
            label: req.label,
            scheme: req.scheme,
            threshold: req.threshold,
            total_parties: req.total_parties,
            created_at: now,
        })),
    ))
}

/// `GET /v1/wallets` — list all wallets.
///
/// In production this reads from the key store.
pub async fn list_wallets(State(_state): State<AppState>) -> Json<ApiResponse<WalletListResponse>> {
    // In production: call key_store.list() and map to WalletResponse.
    Json(ApiResponse::ok(WalletListResponse { wallets: vec![] }))
}

/// `GET /v1/wallets/:id` — get wallet details.
pub async fn get_wallet(
    State(_state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<WalletDetailResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    // In production: load from key store, derive addresses for compatible chains.
    Err((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::err(format!("wallet {wallet_id} not found"))),
    ))
}

/// `POST /v1/wallets/:id/sign` — sign a message.
pub async fn sign_message(
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
    Json(req): Json<SignRequest>,
) -> Result<Json<ApiResponse<SignResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    // Validate hex-encoded message.
    let _message_bytes = hex::decode(&req.message).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(format!("invalid hex message: {e}"))),
        )
    })?;

    state.metrics.sign_total.inc();

    // In production: load key share, initiate MPC signing ceremony.
    Err((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::err(format!(
            "wallet {wallet_id} not found — MPC signing requires key store integration"
        ))),
    ))
}

/// `POST /v1/wallets/:id/refresh` — proactive key refresh.
pub async fn refresh_wallet(
    State(_state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    // In production: load key share, initiate refresh ceremony.
    Err((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::err(format!(
            "wallet {wallet_id} not found — key refresh requires key store integration"
        ))),
    ))
}

/// `POST /v1/wallets/:id/freeze` — freeze wallet.
pub async fn freeze_wallet(
    State(_state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    // In production: call key_store.freeze(group_id).
    Err((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::err(format!(
            "wallet {wallet_id} not found — freeze requires key store integration"
        ))),
    ))
}

/// `POST /v1/wallets/:id/unfreeze` — unfreeze wallet.
pub async fn unfreeze_wallet(
    State(_state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    // In production: call key_store.unfreeze(group_id).
    Err((
        StatusCode::NOT_FOUND,
        Json(ApiResponse::err(format!(
            "wallet {wallet_id} not found — unfreeze requires key store integration"
        ))),
    ))
}
