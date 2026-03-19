//! MPC Node — holds exactly one party's key share.
//!
//! Each node:
//! 1. Connects to NATS with Ed25519 signed envelopes
//! 2. Listens for keygen/sign/freeze requests on control channels
//! 3. Participates in MPC protocol rounds via NATS
//! 4. Stores its own share in EncryptedFileStore (AES-256-GCM + Argon2id)
//! 5. Verifies SignAuthorization before signing (DEC-012)
//!
//! # Configuration (env vars)
//! - `PARTY_ID` — this node's party ID (1-indexed)
//! - `NATS_URL` — NATS server URL
//! - `KEY_STORE_DIR` — directory for encrypted key shares
//! - `KEY_STORE_PASSWORD` — password for key store encryption
//! - `NODE_SIGNING_KEY` — hex Ed25519 signing key for envelope auth
//! - `GATEWAY_PUBKEY` — hex Ed25519 verifying key of the gateway (for SignAuth verification)

mod rpc;

use std::path::PathBuf;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use mpc_wallet_core::key_store::encrypted::EncryptedFileStore;
use mpc_wallet_core::key_store::types::{KeyGroupId, KeyMetadata};
use mpc_wallet_core::key_store::KeyStore;
use mpc_wallet_core::protocol::MpcProtocol;
use mpc_wallet_core::transport::nats::NatsTransport;
use mpc_wallet_core::types::{CryptoScheme, PartyId, ThresholdConfig};

use rpc::*;

/// Node configuration loaded from environment.
struct NodeConfig {
    party_id: PartyId,
    nats_url: String,
    key_store_dir: PathBuf,
    key_store_password: String,
    signing_key: SigningKey,
    gateway_pubkey: Option<ed25519_dalek::VerifyingKey>,
}

impl NodeConfig {
    fn from_env() -> Self {
        let party_id = std::env::var("PARTY_ID")
            .expect("PARTY_ID must be set")
            .parse::<u16>()
            .expect("PARTY_ID must be a number");

        let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".into());

        let key_store_dir = std::env::var("KEY_STORE_DIR").unwrap_or_else(|_| "/data/keys".into());

        let key_store_password =
            std::env::var("KEY_STORE_PASSWORD").expect("KEY_STORE_PASSWORD must be set");

        let signing_key_hex =
            std::env::var("NODE_SIGNING_KEY").expect("NODE_SIGNING_KEY must be set");
        let key_bytes = hex::decode(&signing_key_hex).expect("NODE_SIGNING_KEY must be valid hex");
        assert_eq!(key_bytes.len(), 32, "NODE_SIGNING_KEY must be 32 bytes");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        let signing_key = SigningKey::from_bytes(&arr);

        let gateway_pubkey = std::env::var("GATEWAY_PUBKEY").ok().map(|hex| {
            let bytes = hex::decode(&hex).expect("GATEWAY_PUBKEY must be valid hex");
            assert_eq!(bytes.len(), 32);
            ed25519_dalek::VerifyingKey::from_bytes(&bytes.try_into().unwrap()).unwrap()
        });

        Self {
            party_id: PartyId(party_id),
            nats_url,
            key_store_dir: PathBuf::from(key_store_dir),
            key_store_password,
            signing_key,
            gateway_pubkey,
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mpc_wallet_node=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = NodeConfig::from_env();

    tracing::info!(
        party_id = config.party_id.0,
        nats_url = %config.nats_url,
        key_store_dir = %config.key_store_dir.display(),
        "MPC Node starting"
    );

    // Initialize key store
    let key_store = Arc::new(EncryptedFileStore::new(
        config.key_store_dir.clone(),
        &config.key_store_password,
    ));

    // Connect to NATS
    let nats_client = async_nats::connect(&config.nats_url)
        .await
        .expect("failed to connect to NATS");

    tracing::info!("connected to NATS");

    // Subscribe to control channels
    let keygen_sub = nats_client
        .subscribe("mpc.control.keygen.*")
        .await
        .expect("failed to subscribe to keygen channel");

    let sign_sub = nats_client
        .subscribe("mpc.control.sign.*")
        .await
        .expect("failed to subscribe to sign channel");

    let freeze_sub = nats_client
        .subscribe("mpc.control.freeze.*")
        .await
        .expect("failed to subscribe to freeze channel");

    tracing::info!(
        party_id = config.party_id.0,
        "listening for keygen/sign/freeze requests"
    );

    // Process requests
    let config = Arc::new(config);
    let nats = Arc::new(nats_client);

    tokio::select! {
        _ = handle_keygen_requests(keygen_sub, config.clone(), key_store.clone(), nats.clone()) => {}
        _ = handle_sign_requests(sign_sub, config.clone(), key_store.clone(), nats.clone()) => {}
        _ = handle_freeze_requests(freeze_sub, config.clone(), key_store.clone(), nats.clone()) => {}
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
        }
    }
}

async fn handle_keygen_requests(
    mut sub: async_nats::Subscriber,
    config: Arc<NodeConfig>,
    key_store: Arc<EncryptedFileStore>,
    nats: Arc<async_nats::Client>,
) {
    use futures::StreamExt;

    while let Some(msg) = sub.next().await {
        let req: KeygenRequest = match serde_json::from_slice(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("invalid keygen request: {e}");
                continue;
            }
        };

        tracing::info!(
            group_id = %req.group_id,
            scheme = %req.scheme,
            threshold = req.threshold,
            total = req.total_parties,
            "keygen request received"
        );

        let config = config.clone();
        let key_store = key_store.clone();
        let nats = nats.clone();
        let reply_to = msg.reply.clone();

        tokio::spawn(async move {
            let response = execute_keygen(&req, &config, &key_store).await;
            let payload = serde_json::to_vec(&response).unwrap();

            // Use NATS request-reply: respond to the inbox from the request message.
            // Falls back to legacy reply subject for backward compatibility.
            let reply_subject = reply_to
                .unwrap_or_else(|| format!("mpc.control.keygen.{}.reply", req.group_id).into());
            if let Err(e) = nats.publish(reply_subject, payload.into()).await {
                tracing::error!("failed to publish keygen response: {e}");
            }
        });
    }
}

async fn execute_keygen(
    req: &KeygenRequest,
    config: &NodeConfig,
    key_store: &EncryptedFileStore,
) -> KeygenResponse {
    let scheme: CryptoScheme = match req.scheme.parse() {
        Ok(s) => s,
        Err(e) => {
            return KeygenResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                group_pubkey_hex: String::new(),
                success: false,
                error: Some(format!("invalid scheme: {e}")),
            };
        }
    };

    let protocol = match create_protocol(scheme) {
        Ok(p) => p,
        Err(e) => {
            return KeygenResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                group_pubkey_hex: String::new(),
                success: false,
                error: Some(e),
            };
        }
    };

    let threshold_config = match ThresholdConfig::new(req.threshold, req.total_parties) {
        Ok(c) => c,
        Err(e) => {
            return KeygenResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                group_pubkey_hex: String::new(),
                success: false,
                error: Some(e.to_string()),
            };
        }
    };

    // Connect to NATS with signed envelope for this session
    // Use nats_url from control message if provided, otherwise fall back to config
    let transport_url = req.nats_url.as_deref().unwrap_or(&config.nats_url);
    let mut transport = match NatsTransport::connect_signed(
        transport_url,
        config.party_id,
        req.session_id.clone(),
        config.signing_key.clone(),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            return KeygenResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                group_pubkey_hex: String::new(),
                success: false,
                error: Some(format!("NATS connect failed: {e}")),
            };
        }
    };

    // Register peer keys
    for peer in &req.peer_keys {
        if peer.party_id != config.party_id.0 {
            if let Ok(bytes) = hex::decode(&peer.verifying_key_hex) {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                        transport.register_peer_key(PartyId(peer.party_id), vk);
                    }
                }
            }
        }
    }

    // Run keygen
    match protocol
        .keygen(threshold_config, config.party_id, &transport)
        .await
    {
        Ok(share) => {
            let gpk_hex = hex::encode(share.group_public_key.as_bytes());

            // Persist share to encrypted file store
            let group_id = KeyGroupId::from_string(req.group_id.clone());
            let metadata = KeyMetadata {
                group_id: group_id.clone(),
                label: req.label.clone(),
                scheme,
                config: threshold_config,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            };

            if let Err(e) = key_store
                .save(&group_id, &metadata, config.party_id, &share)
                .await
            {
                return KeygenResponse {
                    party_id: config.party_id.0,
                    group_id: req.group_id.clone(),
                    group_pubkey_hex: gpk_hex,
                    success: false,
                    error: Some(format!("key store save failed: {e}")),
                };
            }

            tracing::info!(
                group_id = %req.group_id,
                party_id = config.party_id.0,
                gpk = %gpk_hex[..16],
                "keygen complete — share saved"
            );

            KeygenResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                group_pubkey_hex: gpk_hex,
                success: true,
                error: None,
            }
        }
        Err(e) => KeygenResponse {
            party_id: config.party_id.0,
            group_id: req.group_id.clone(),
            group_pubkey_hex: String::new(),
            success: false,
            error: Some(format!("keygen failed: {e}")),
        },
    }
}

async fn handle_sign_requests(
    mut sub: async_nats::Subscriber,
    config: Arc<NodeConfig>,
    key_store: Arc<EncryptedFileStore>,
    nats: Arc<async_nats::Client>,
) {
    use futures::StreamExt;

    while let Some(msg) = sub.next().await {
        let req: SignRequest = match serde_json::from_slice(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("invalid sign request: {e}");
                continue;
            }
        };

        // Only participate if this node is in the signer set
        if !req.signer_ids.contains(&config.party_id.0) {
            continue;
        }

        tracing::info!(
            group_id = %req.group_id,
            signers = ?req.signer_ids,
            "sign request received"
        );

        let config = config.clone();
        let key_store = key_store.clone();
        let nats = nats.clone();
        let reply_to = msg.reply.clone();

        tokio::spawn(async move {
            let response = execute_sign(&req, &config, &key_store).await;
            let payload = serde_json::to_vec(&response).unwrap();

            // Use NATS request-reply: respond to the inbox from the request message.
            // Falls back to legacy reply subject for backward compatibility.
            let reply_subject = reply_to
                .unwrap_or_else(|| format!("mpc.control.sign.{}.reply", req.group_id).into());
            if let Err(e) = nats.publish(reply_subject, payload.into()).await {
                tracing::error!("failed to publish sign response: {e}");
            }
        });
    }
}

async fn execute_sign(
    req: &SignRequest,
    config: &NodeConfig,
    key_store: &EncryptedFileStore,
) -> SignResponse {
    // Load this party's share from key store
    let group_id = KeyGroupId::from_string(req.group_id.clone());
    let share = match key_store.load(&group_id, config.party_id).await {
        Ok(s) => s,
        Err(e) => {
            return SignResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                signature_json: None,
                success: false,
                error: Some(format!("load share failed: {e}")),
            };
        }
    };

    // Verify SignAuthorization (DEC-012)
    if let Some(ref gateway_pubkey) = config.gateway_pubkey {
        let message_bytes = match hex::decode(&req.message_hex) {
            Ok(b) => b,
            Err(e) => {
                return SignResponse {
                    party_id: config.party_id.0,
                    group_id: req.group_id.clone(),
                    signature_json: None,
                    success: false,
                    error: Some(format!("invalid message hex: {e}")),
                };
            }
        };

        match serde_json::from_str::<mpc_wallet_core::protocol::sign_authorization::SignAuthorization>(
            &req.sign_authorization,
        ) {
            Ok(auth) => {
                if let Err(e) = auth.verify(gateway_pubkey, &message_bytes) {
                    tracing::warn!(
                        group_id = %req.group_id,
                        "SignAuthorization verification FAILED: {e}"
                    );
                    return SignResponse {
                        party_id: config.party_id.0,
                        group_id: req.group_id.clone(),
                        signature_json: None,
                        success: false,
                        error: Some(format!("SignAuthorization verification failed: {e}")),
                    };
                }
                tracing::debug!("SignAuthorization verified");
            }
            Err(e) => {
                return SignResponse {
                    party_id: config.party_id.0,
                    group_id: req.group_id.clone(),
                    signature_json: None,
                    success: false,
                    error: Some(format!("invalid SignAuthorization: {e}")),
                };
            }
        }
    }

    let protocol = match create_protocol(share.scheme) {
        Ok(p) => p,
        Err(e) => {
            return SignResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                signature_json: None,
                success: false,
                error: Some(e),
            };
        }
    };

    // Connect to NATS for this signing session
    // Use nats_url from control message if provided, otherwise fall back to config
    let transport_url = req.nats_url.as_deref().unwrap_or(&config.nats_url);
    let mut transport = match NatsTransport::connect_signed(
        transport_url,
        config.party_id,
        req.session_id.clone(),
        config.signing_key.clone(),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            return SignResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                signature_json: None,
                success: false,
                error: Some(format!("NATS connect failed: {e}")),
            };
        }
    };

    // Register only signing peers
    for peer in &req.peer_keys {
        if peer.party_id != config.party_id.0 && req.signer_ids.contains(&peer.party_id) {
            if let Ok(bytes) = hex::decode(&peer.verifying_key_hex) {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                        transport.register_peer_key(PartyId(peer.party_id), vk);
                    }
                }
            }
        }
    }

    let message = match hex::decode(&req.message_hex) {
        Ok(m) => m,
        Err(e) => {
            return SignResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                signature_json: None,
                success: false,
                error: Some(format!("invalid message hex: {e}")),
            };
        }
    };

    let signers: Vec<PartyId> = req.signer_ids.iter().map(|&id| PartyId(id)).collect();

    match protocol.sign(&share, &signers, &message, &transport).await {
        Ok(sig) => {
            let sig_json = serde_json::to_string(&sig).unwrap_or_default();
            tracing::info!(
                group_id = %req.group_id,
                party_id = config.party_id.0,
                "sign complete"
            );
            SignResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                signature_json: Some(sig_json),
                success: true,
                error: None,
            }
        }
        Err(e) => SignResponse {
            party_id: config.party_id.0,
            group_id: req.group_id.clone(),
            signature_json: None,
            success: false,
            error: Some(format!("sign failed: {e}")),
        },
    }
}

async fn handle_freeze_requests(
    mut sub: async_nats::Subscriber,
    config: Arc<NodeConfig>,
    key_store: Arc<EncryptedFileStore>,
    nats: Arc<async_nats::Client>,
) {
    use futures::StreamExt;

    while let Some(msg) = sub.next().await {
        let req: FreezeRequest = match serde_json::from_slice(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("invalid freeze request: {e}");
                continue;
            }
        };

        let group_id = KeyGroupId::from_string(req.group_id.clone());
        let result = if req.freeze {
            key_store.freeze(&group_id).await
        } else {
            key_store.unfreeze(&group_id).await
        };

        let (success, error) = match &result {
            Ok(()) => {
                tracing::info!(
                    group_id = %req.group_id,
                    frozen = req.freeze,
                    "freeze/unfreeze complete"
                );
                (true, None)
            }
            Err(e) => {
                tracing::error!(
                    group_id = %req.group_id,
                    "freeze/unfreeze failed: {e}"
                );
                (false, Some(e.to_string()))
            }
        };

        // Send acknowledgment via NATS request-reply if reply inbox is present
        if let Some(reply) = msg.reply {
            let response = FreezeResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                success,
                error,
            };
            let payload = serde_json::to_vec(&response).unwrap();
            if let Err(e) = nats.publish(reply, payload.into()).await {
                tracing::error!("failed to publish freeze response: {e}");
            }
        }
    }
}

/// Create MPC protocol instance for a given scheme.
fn create_protocol(scheme: CryptoScheme) -> Result<Box<dyn MpcProtocol>, String> {
    use mpc_wallet_core::protocol::*;
    match scheme {
        CryptoScheme::Gg20Ecdsa => Ok(Box::new(gg20::Gg20Protocol::new())),
        CryptoScheme::FrostEd25519 => Ok(Box::new(frost_ed25519::FrostEd25519Protocol::new())),
        CryptoScheme::FrostSecp256k1Tr => {
            Ok(Box::new(frost_secp256k1::FrostSecp256k1TrProtocol::new()))
        }
        _ => Err(format!("unsupported scheme: {scheme:?}")),
    }
}
