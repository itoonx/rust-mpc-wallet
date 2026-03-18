//! Wallet management endpoints: create, list, get, sign, freeze, unfreeze, refresh.
//!
//! Two modes:
//! - **Production (DEC-015):** Uses `MpcOrchestrator` — delegates to distributed nodes via NATS.
//!   Gateway holds ZERO key shares. Each node holds exactly 1 share.
//! - **Demo mode:** Falls back to `WalletStore` — all shares in gateway memory.
//!   WARNING: This violates MPC security guarantees. Only for development/testing.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};

use mpc_wallet_core::protocol::MpcSignature;
use mpc_wallet_core::rbac::{ApiRole, AuthContext, Permissions};

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
        ApiError::new(StatusCode::FORBIDDEN, ErrorCode::MfaRequired, "insufficient permissions")
    })
}

/// Check if orchestrator (distributed mode) is available.
fn is_distributed(state: &AppState) -> bool {
    state.orchestrator.is_some()
}

/// `POST /v1/wallets` — create a new MPC wallet (keygen).
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

    if let Some(ref orchestrator) = state.orchestrator {
        // Production: distributed keygen via NATS (NO shares in gateway)
        let metadata = orchestrator
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
            mode = "distributed",
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
    } else {
        // Demo mode: local keygen (all shares in gateway — NOT for production)
        tracing::warn!("using demo mode — all key shares held in gateway memory (NOT MPC-safe)");
        let record = state
            .wallet_store
            .create(
                group_id,
                req.label,
                scheme,
                req.threshold,
                req.total_parties,
            )
            .await
            .map_err(ApiError::from)?;

        Ok((
            StatusCode::CREATED,
            Json(ApiResponse::ok(WalletResponse {
                id: record.group_id,
                label: record.label,
                scheme: record.scheme.to_string(),
                threshold: record.config.threshold,
                total_parties: record.config.total_parties,
                created_at: record.created_at,
            })),
        ))
    }
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

    let wallets = if let Some(ref orch) = state.orchestrator {
        orch.list()
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
            .collect()
    } else {
        state
            .wallet_store
            .list()
            .await
            .into_iter()
            .map(|r| WalletResponse {
                id: r.group_id,
                label: r.label,
                scheme: r.scheme.to_string(),
                threshold: r.config.threshold,
                total_parties: r.config.total_parties,
                created_at: r.created_at,
            })
            .collect()
    };

    Ok(Json(ApiResponse::ok(WalletListResponse { wallets })))
}

/// `GET /v1/wallets/:id` — get wallet details.
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

    use mpc_wallet_chains::provider::Chain;

    // Get metadata from orchestrator or demo store
    let (group_id, label, scheme, threshold, total_parties, created_at, gpk) =
        if let Some(ref orch) = state.orchestrator {
            let m = orch
                .get(&wallet_id)
                .await
                .ok_or_else(|| ApiError::not_found(format!("wallet {wallet_id} not found")))?;
            (
                m.group_id,
                m.label,
                m.scheme,
                m.config.threshold,
                m.config.total_parties,
                m.created_at,
                m.group_public_key,
            )
        } else {
            let r = state
                .wallet_store
                .get(&wallet_id)
                .await
                .ok_or_else(|| ApiError::not_found(format!("wallet {wallet_id} not found")))?;
            (
                r.group_id,
                r.label,
                r.scheme,
                r.config.threshold,
                r.config.total_parties,
                r.created_at,
                r.group_public_key,
            )
        };

    // Derive addresses
    let chains_to_derive: Vec<Chain> = match scheme {
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
            if let Ok(addr) = provider.derive_address(&gpk) {
                addresses.push(AddressEntry {
                    chain: chain.to_string(),
                    address: addr,
                });
            }
        }
    }

    Ok(Json(ApiResponse::ok(WalletDetailResponse {
        id: group_id,
        label,
        scheme: scheme.to_string(),
        threshold,
        total_parties,
        created_at,
        addresses,
    })))
}

/// `POST /v1/wallets/:id/sign` — sign a message.
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

    let sig = if let Some(ref orch) = state.orchestrator {
        // Production: create SignAuthorization + delegate to distributed nodes
        // TODO: Generate proper SignAuthorization with policy + approvals
        let sign_auth_json = "{}"; // Placeholder — nodes will skip verification if GATEWAY_PUBKEY not set
        orch.sign(&wallet_id, &message_bytes, sign_auth_json)
            .await
            .map_err(ApiError::from)?
    } else {
        // Demo mode
        state
            .wallet_store
            .sign(&wallet_id, &message_bytes)
            .await
            .map_err(ApiError::from)?
    };

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

    tracing::info!(
        wallet_id = %wallet_id,
        scheme = scheme_name,
        user = %ctx.user_id,
        mode = if is_distributed(&state) { "distributed" } else { "demo" },
        "message signed"
    );

    Ok(Json(ApiResponse::ok(SignResponse {
        signature: sig_json,
        scheme: scheme_name.to_string(),
    })))
}

/// `POST /v1/wallets/:id/refresh` — proactive key refresh.
pub async fn refresh_wallet(
    State(_state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    Err(ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        ErrorCode::InternalError,
        format!("wallet {wallet_id}: key refresh requires distributed MPC transport"),
    ))
}

/// `POST /v1/wallets/:id/freeze` — freeze wallet.
pub async fn freeze_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;

    if let Some(ref orch) = state.orchestrator {
        orch.freeze(&wallet_id, true)
            .await
            .map_err(ApiError::from)?;
    } else {
        state
            .wallet_store
            .freeze(&wallet_id)
            .await
            .map_err(ApiError::from)?;
    }

    tracing::info!(wallet_id = %wallet_id, user = %ctx.user_id, "wallet frozen");
    Ok(Json(ApiResponse::ok(
        serde_json::json!({"wallet_id": wallet_id, "status": "frozen"}),
    )))
}

/// `POST /v1/wallets/:id/unfreeze` — unfreeze wallet.
pub async fn unfreeze_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;

    if let Some(ref orch) = state.orchestrator {
        orch.freeze(&wallet_id, false)
            .await
            .map_err(ApiError::from)?;
    } else {
        state
            .wallet_store
            .unfreeze(&wallet_id)
            .await
            .map_err(ApiError::from)?;
    }

    tracing::info!(wallet_id = %wallet_id, user = %ctx.user_id, "wallet unfrozen");
    Ok(Json(ApiResponse::ok(
        serde_json::json!({"wallet_id": wallet_id, "status": "active"}),
    )))
}
