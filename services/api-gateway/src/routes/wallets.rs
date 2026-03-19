//! Wallet management endpoints: create, list, get, sign, freeze, unfreeze, refresh.
//!
//! Production architecture (DEC-015): Gateway delegates to distributed MPC nodes via NATS.
//! Gateway holds ZERO key shares. Each MPC node holds exactly 1 share.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};

use mpc_wallet_core::protocol::sign_authorization::{AuthorizationPayload, SignAuthorization};
use mpc_wallet_core::protocol::MpcSignature;
use mpc_wallet_core::rbac::{ApiRole, AuthContext, Permissions};
use sha2::{Digest, Sha256};

use crate::errors::{ApiError, ErrorCode};
use crate::models::request::{CreateWalletRequest, SignRequest};
use crate::models::response::{
    AddressEntry, ApiResponse, SignResponse, WalletDetailResponse, WalletListResponse,
    WalletResponse,
};
use crate::state::AppState;

fn require_roles(ctx: &AuthContext, roles: &[ApiRole]) -> Result<(), ApiError> {
    Permissions::require_role(ctx, roles).map_err(|e| {
        tracing::warn!(user_id = %ctx.user_id, required = ?roles, actual = ?ctx.roles, "RBAC denied: {e}");
        ApiError::forbidden("insufficient permissions")
    })
}

fn require_admin_mfa(ctx: &AuthContext) -> Result<(), ApiError> {
    Permissions::can_freeze_key_mfa(ctx).map_err(|e| {
        tracing::warn!(user_id = %ctx.user_id, mfa = ctx.mfa_verified, "RBAC denied (admin+MFA): {e}");
        ApiError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::MfaRequired,
            "insufficient permissions",
        )
    })
}

/// `POST /v1/wallets` — create a new MPC wallet (distributed keygen).
pub async fn create_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<CreateWalletRequest>,
) -> Result<(StatusCode, Json<ApiResponse<WalletResponse>>), ApiError> {
    require_admin_mfa(&ctx)?;

    let scheme: mpc_wallet_core::types::CryptoScheme = req
        .scheme
        .parse()
        .map_err(|e: String| ApiError::bad_request(ErrorCode::InvalidInput, e))?;

    mpc_wallet_core::types::ThresholdConfig::new(req.threshold, req.total_parties)
        .map_err(|e| ApiError::bad_request(ErrorCode::InvalidConfig, e.to_string()))?;

    state.metrics.keygen_total.inc();
    let group_id = uuid::Uuid::new_v4().to_string();

    let metadata = state
        .orchestrator
        .keygen(
            group_id,
            req.label,
            scheme,
            req.threshold,
            req.total_parties,
        )
        .await
        .map_err(ApiError::from)?;

    tracing::info!(
        group_id = %metadata.group_id,
        scheme = %metadata.scheme,
        "wallet created via distributed MPC keygen (no shares in gateway)"
    );

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::ok(WalletResponse {
            id: metadata.group_id,
            label: metadata.label,
            scheme: metadata.scheme.to_string(),
            threshold: metadata.config.threshold,
            total_parties: metadata.config.total_parties,
            created_at: metadata.created_at,
        })),
    ))
}

/// `GET /v1/wallets` — list all wallets.
pub async fn list_wallets(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<ApiResponse<WalletListResponse>>, ApiError> {
    require_roles(
        &ctx,
        &[
            ApiRole::Viewer,
            ApiRole::Initiator,
            ApiRole::Approver,
            ApiRole::Admin,
        ],
    )?;

    let wallets = state
        .orchestrator
        .list()
        .await
        .into_iter()
        .map(|m| WalletResponse {
            id: m.group_id,
            label: m.label,
            scheme: m.scheme.to_string(),
            threshold: m.config.threshold,
            total_parties: m.config.total_parties,
            created_at: m.created_at,
        })
        .collect();

    Ok(Json(ApiResponse::ok(WalletListResponse { wallets })))
}

/// `GET /v1/wallets/:id` — get wallet details with derived addresses.
pub async fn get_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<WalletDetailResponse>>, ApiError> {
    require_roles(
        &ctx,
        &[
            ApiRole::Viewer,
            ApiRole::Initiator,
            ApiRole::Approver,
            ApiRole::Admin,
        ],
    )?;

    let m = state
        .orchestrator
        .get(&wallet_id)
        .await
        .ok_or_else(|| ApiError::not_found(format!("wallet {wallet_id} not found")))?;

    // Derive addresses for common chains matching the wallet's signing scheme.
    use mpc_wallet_chains::provider::Chain;
    let chains_to_derive: Vec<Chain> = match m.scheme {
        mpc_wallet_core::types::CryptoScheme::Gg20Ecdsa => {
            vec![Chain::Ethereum, Chain::Polygon, Chain::Bsc, Chain::Arbitrum]
        }
        mpc_wallet_core::types::CryptoScheme::FrostEd25519 => {
            vec![Chain::Solana, Chain::Sui, Chain::Aptos]
        }
        mpc_wallet_core::types::CryptoScheme::FrostSecp256k1Tr => {
            vec![Chain::BitcoinTestnet, Chain::BitcoinMainnet]
        }
        _ => vec![],
    };

    let mut addresses = Vec::new();
    for chain in chains_to_derive {
        if let Ok(provider) = state.chain_registry.provider(chain) {
            if let Ok(addr) = provider.derive_address(&m.group_public_key) {
                addresses.push(AddressEntry {
                    chain: chain.to_string(),
                    address: addr,
                });
            }
        }
    }

    Ok(Json(ApiResponse::ok(WalletDetailResponse {
        id: m.group_id,
        label: m.label,
        scheme: m.scheme.to_string(),
        threshold: m.config.threshold,
        total_parties: m.config.total_parties,
        created_at: m.created_at,
        addresses,
    })))
}

/// `POST /v1/wallets/:id/sign` — distributed MPC sign.
pub async fn sign_message(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
    Json(req): Json<SignRequest>,
) -> Result<Json<ApiResponse<SignResponse>>, ApiError> {
    require_roles(&ctx, &[ApiRole::Initiator, ApiRole::Admin])?;
    Permissions::check_risk_tier_for_signing(&ctx)
        .map_err(|e| ApiError::forbidden(e.to_string()))?;

    let message_bytes = hex::decode(&req.message).map_err(|e| {
        ApiError::bad_request(ErrorCode::InvalidInput, format!("invalid hex message: {e}"))
    })?;

    state.metrics.sign_total.inc();

    // Build SignAuthorization proof for MPC nodes to independently verify (DEC-012).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let message_hash = hex::encode(Sha256::digest(&message_bytes));
    let policy_hash = hex::encode(Sha256::digest(b""));

    let payload = AuthorizationPayload {
        authorization_id: uuid::Uuid::new_v4().to_string(),
        requester_id: ctx.user_id.clone(),
        wallet_id: wallet_id.clone(),
        message_hash,
        policy_hash,
        policy_passed: true, // TODO: wire real policy engine check
        approval_count: 0,   // TODO: wire approval workflow
        approval_required: 0,
        approvers: vec![],
        timestamp: now,
        session_id: uuid::Uuid::new_v4().to_string(),
        encrypted_context: None,
    };

    let sign_auth = SignAuthorization::create(payload, &state.server_signing_key);
    let sign_auth_json = serde_json::to_string(&sign_auth)
        .map_err(|e| ApiError::internal(format!("failed to serialize sign authorization: {e}")))?;

    let sig = state
        .orchestrator
        .sign(&wallet_id, &message_bytes, &sign_auth_json)
        .await
        .map_err(ApiError::from)?;

    let (sig_json, scheme_name) = match &sig {
        MpcSignature::Ecdsa { r, s, recovery_id } => (
            serde_json::json!({"r": hex::encode(r), "s": hex::encode(s), "recovery_id": recovery_id}),
            "gg20-ecdsa",
        ),
        MpcSignature::EdDsa { signature } => (
            serde_json::json!({"signature": hex::encode(signature)}),
            "frost-ed25519",
        ),
        MpcSignature::Schnorr { signature } => (
            serde_json::json!({"signature": hex::encode(signature)}),
            "frost-secp256k1-tr",
        ),
        _ => (serde_json::json!({"raw": "unsupported"}), "unknown"),
    };

    tracing::info!(wallet_id = %wallet_id, scheme = scheme_name, user = %ctx.user_id, "message signed via distributed MPC");

    Ok(Json(ApiResponse::ok(SignResponse {
        signature: sig_json,
        scheme: scheme_name.to_string(),
    })))
}

/// `POST /v1/wallets/:id/refresh` — proactive key refresh (distributed).
pub async fn refresh_wallet(
    State(_state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    Err(ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        ErrorCode::InternalError,
        format!("wallet {wallet_id}: key refresh via NATS not yet implemented"),
    ))
}

/// `POST /v1/wallets/:id/freeze` — freeze wallet (gateway + all nodes).
pub async fn freeze_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    state
        .orchestrator
        .freeze(&wallet_id, true)
        .await
        .map_err(ApiError::from)?;

    tracing::info!(wallet_id = %wallet_id, user = %ctx.user_id, "wallet frozen");
    Ok(Json(ApiResponse::ok(
        serde_json::json!({"wallet_id": wallet_id, "status": "frozen"}),
    )))
}

/// `POST /v1/wallets/:id/unfreeze` — unfreeze wallet (gateway + all nodes).
pub async fn unfreeze_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    state
        .orchestrator
        .freeze(&wallet_id, false)
        .await
        .map_err(ApiError::from)?;

    tracing::info!(wallet_id = %wallet_id, user = %ctx.user_id, "wallet unfrozen");
    Ok(Json(ApiResponse::ok(
        serde_json::json!({"wallet_id": wallet_id, "status": "active"}),
    )))
}
